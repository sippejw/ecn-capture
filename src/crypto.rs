// Taken from CloudFlare's Rust implementation of QUIC (Quiche)

// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::iter::repeat;

use crypto::aes::KeySize;
use ring::aead;
use ring::hkdf;

use crypto::aead::AeadDecryptor;
use crypto::aes_gcm::AesGcm;
use crate::quic;
use crate::quic::QuicParseError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    #[allow(non_camel_case_types)]
    AES128_GCM,

    #[allow(non_camel_case_types)]
    AES256_GCM,

    #[allow(non_camel_case_types)]
    ChaCha20_Poly1305,
}

impl Algorithm {
    fn get_ring_hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Algorithm::AES128_GCM => &aead::quic::AES_128,
            Algorithm::AES256_GCM => &aead::quic::AES_256,
            Algorithm::ChaCha20_Poly1305 => &aead::quic::CHACHA20,
        }
    }

    fn get_ring_digest(self) -> hkdf::Algorithm {
        match self {
            Algorithm::AES128_GCM => hkdf::HKDF_SHA256,
            Algorithm::AES256_GCM => hkdf::HKDF_SHA384,
            Algorithm::ChaCha20_Poly1305 => hkdf::HKDF_SHA256,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 32,
            Algorithm::ChaCha20_Poly1305 => 32,
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 16,
            Algorithm::ChaCha20_Poly1305 => 16,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 12,
            Algorithm::AES256_GCM => 12,
            Algorithm::ChaCha20_Poly1305 => 12,
        }
    }

    pub fn get_key_len(self) -> Option<KeySize> {
        match self {
            Algorithm::AES128_GCM => Some(KeySize::KeySize128),
            Algorithm::AES256_GCM => Some(KeySize::KeySize256),
            Algorithm::ChaCha20_Poly1305 => None,
        }
    }
}

pub struct Open {
    alg: Algorithm,

    key_len: Option<KeySize>,

    initial_key: Vec<u8>,

    pub hp_key: aead::quic::HeaderProtectionKey,

    nonce: Vec<u8>,
}

impl Open {
    pub fn new(
        alg: Algorithm, key: &[u8], iv: &[u8], hp_key: &[u8],
    ) -> Result<Open, QuicParseError> {
        Ok(Open {
            alg,

            initial_key: key.to_vec(),

            key_len: alg.get_key_len(),

            hp_key: aead::quic::HeaderProtectionKey::new(
                alg.get_ring_hp(),
                hp_key,
            )
            .map_err(|_| QuicParseError::CryptoFail)?,

            nonce: Vec::from(iv),
        })
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], tag: &[u8],
    ) -> Result<Vec<u8>, QuicParseError> {

        let tag_len = self.alg().tag_len();

        let nonce = make_nonce(&self.nonce, counter);
        let mut cipher = match self.alg {
            Algorithm::AES128_GCM => AesGcm::new(self.key_len.unwrap(), &self.initial_key, &nonce, &ad),
            Algorithm::AES256_GCM => AesGcm::new(self.key_len.unwrap(), &self.initial_key, &nonce, &ad),
            Algorithm::ChaCha20_Poly1305 => todo!(),
        };

        let mut out: Vec<u8> = repeat(0).take(buf.len()).collect();

        let rc = cipher.decrypt(buf, &mut out, tag);

        if !rc {
            return Err(QuicParseError::CryptoFail);
        }

        Ok(out)
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicParseError> {
        let mask = self
            .hp_key
            .new_mask(sample)
            .map_err(|_| QuicParseError::CryptoFail)?;

        Ok(mask)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }
}
impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Point")
         .field("alg", &self.alg)
         .field("nonce", &self.nonce)
         .finish()
    }
}

pub fn derive_initial_key_material(
    cid: &[u8], version: u32, is_server: bool,
) -> Result<Open, QuicParseError> {
    let mut secret = [0; 32];

    let aead = Algorithm::AES128_GCM;

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    let initial_secret = derive_initial_secret(cid, version);

    // Client.
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_hp_key = vec![0; key_len];

    derive_client_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut client_key)?;
    derive_pkt_iv(aead, &secret, &mut client_iv)?;
    derive_hdr_key(aead, &secret, &mut client_hp_key)?;

    // Server.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_hp_key = vec![0; key_len];

    derive_server_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut server_key)?;
    derive_pkt_iv(aead, &secret, &mut server_iv)?;
    derive_hdr_key(aead, &secret, &mut server_hp_key)?;

    let open = if is_server {
            Open::new(aead, &client_key, &client_iv, &client_hp_key)?
    } else {
            Open::new(aead, &server_key, &server_iv, &server_hp_key)?
    };

    Ok(open)
}

fn derive_initial_secret(secret: &[u8], version: u32) -> hkdf::Prk {
    const INITIAL_SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
        0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    const INITIAL_SALT_DRAFT29: [u8; 20] = [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1,
        0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
    ];

    const INITIAL_SALT_DRAFT27: [u8; 20] = [
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43,
        0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
    ];

    let salt = match version {
        quic::PROTOCOL_VERSION_DRAFT27 | quic::PROTOCOL_VERSION_DRAFT28 =>
            &INITIAL_SALT_DRAFT27,

        quic::PROTOCOL_VERSION_DRAFT29 => &INITIAL_SALT_DRAFT29,

        _ => &INITIAL_SALT,
    };

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    salt.extract(secret)
}

fn derive_client_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<(), QuicParseError> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(prk, LABEL, out)
}

fn derive_server_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<(), QuicParseError> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(prk, LABEL, out)
}

pub fn derive_hdr_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<(), QuicParseError> {
    const LABEL: &[u8] = b"quic hp";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(QuicParseError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<(), QuicParseError> {
    const LABEL: &[u8] = b"quic key";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(QuicParseError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<(), QuicParseError> {
    const LABEL: &[u8] = b"quic iv";

    let nonce_len = aead.nonce_len();

    if nonce_len > out.len() {
        return Err(QuicParseError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(
    prk: &hkdf::Prk, label: &[u8], out: &mut [u8],
) -> Result<(), QuicParseError> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;

    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];

    prk.expand(&info, ArbitraryOutputLen(out.len()))
        .map_err(|_| QuicParseError::CryptoFail)?
        .fill(out)
        .map_err(|_| QuicParseError::CryptoFail)?;

    Ok(())
}

fn make_nonce(iv: &[u8], counter: u64) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0; aead::NONCE_LEN];
    nonce.copy_from_slice(iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

// The ring HKDF expand() API does not accept an arbitrary output length, so we
// need to hide the `usize` length as part of a type that implements the trait
// `ring::hkdf::KeyType` in order to trick ring into accepting it.
struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}