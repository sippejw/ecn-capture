extern crate num;
extern crate hex_slice;
extern crate crypto;
extern crate byteorder;

use std::fmt::{self, Debug};
use crate::common;

use self::num::FromPrimitive;
use self::hex_slice::AsHex;
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use self::byteorder::{ByteOrder, BigEndian};
use enum_primitive::{self, enum_from_primitive};
use enum_primitive::enum_from_primitive_impl;
use enum_primitive::enum_from_primitive_impl_ty;

use common::{u8_to_u16_be, u8_to_u32_be, vec_u8_to_vec_u16_be, vec_u16_to_vec_u8_be, hash_u32};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HelloParseError {
    ShortBuffer,
    NotAHandshake,
    UnknownRecordTLSVersion,
    ShortOuterRecord,
    NotAClientHello,
    InnerOuterRecordLenContradict,
    UnknownChTLSVersion,
    SessionIDLenExceedBuf,
    CiphersuiteLenMisparse,
    CompressionLenExceedBuf,
    ExtensionsLenExceedBuf,
    ShortExtensionHeader,
    ExtensionLenExceedBuf,

    NotAServerHello,

    KeyShareExtShort,
    KeyShareExtLong,
    KeyShareExtLenMisparse,
    PskKeyExchangeModesExtShort,
    PskKeyExchangeModesExtLenMisparse,
    SupportedVersionsExtShort,
    SupportedVersionsExtLenMisparse,

    UnknownQuicTransportParameter,
}

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsRecordType {
	ChangeCipherSpec = 20,
	Alert            = 21,
	Handshake        = 22,
	ApplicationData  = 23,
	Hearbeat         = 24,
}
}

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsHandshakeType {
    HelloRequest       = 0,
	ClientHello        = 1,
	ServerHello        = 2,
	NewSessionTicket   = 4,
	Certificate        = 11,
	ServerKeyExchange  = 12,
	CertificateRequest = 13,
	ServerHelloDone    = 14,
	CertificateVerify  = 15,
	ClientKeyExchange  = 16,
	Finished           = 20,
	CertificateStatus  = 22,
	NextProtocol       = 67, // Not IANA assigned
}
}


enum_from_primitive! {
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum TlsExtension {
	ServerName                       = 0,
	StatusRequest                    = 5,
	SupportedCurves                  = 10,
	SupportedPoints                  = 11,
	SignatureAlgorithms              = 13,
	ALPN                             = 16,
	SCT                              = 18, // https://tools.ietf.org/html/rfc6962#section-6
	Padding                          = 21,
	ExtendedMasterSecret             = 23, // https://tools.ietf.org/html/rfc7627
	SessionTicket                    = 35,
	NextProtoNeg                     = 13172, // not IANA assigned
	RenegotiationInfo                = 0xff01,
	ChannelID                        = 30032, // not IANA assigned

    KeyShare                         = 0x0033,
    PskKeyExchangeModes              = 0x002D,
    SupportedVersions                = 0x002B,
    CertificateCompressionAlgorithms = 0x001B,
    TokenBinding                     = 0x0018,
    EarlyData                        = 0x002A,
    PreSharedKey                     = 0x0029,
    RecordSizeLimit                  = 0x001C,
    QuicTransportParameters          = 0x0039,
}
}

enum_from_primitive! {
#[repr(i16)]
#[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum TlsVersion {
    // TODO
	SSL30 = 0x0300,
	TLS10 = 0x0301,
	TLS11 = 0x0302,
	TLS12 = 0x0303,
}
}

enum_from_primitive! {
#[repr(u16)]
#[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum QuicTransportParams {
    OriginalDestinationConnectionID = 0x0000,
    IdleTimeout                     = 0x0001,
    StatelessResetToken             = 0x0002,
    MaxUdpPayloadSize               = 0x0003,
    InitialMaxData                  = 0x0004,
    InitialMaxStreamDataBidiLocal   = 0x0005,
    InitialMaxStreamDataBidiRemote  = 0x0006,
    InitialMaxStreamDataUni         = 0x0007,
    InitialMaxStreamsBidi           = 0x0008,
    InitialMaxStreamsUni            = 0x0009,
    AckDelayExponent                = 0x000A,
    MaxAckDelay                     = 0x000B,
    DisableMigration                = 0x000C,
    ActiveConnectionIDLimit         = 0x000E,
    InitialSourceConnectionID       = 0x000F,
    RetrySourceConnectionID         = 0x0010,
    VersionInformation              = 0x0011,
    MaxDatagramFrameSize            = 0x0020,
    InitialRtt                      = 0x3127,
    GoogleConnectionOptions         = 0x3128,
    GoogleVersion                   = 0x4752,
    DatagramFlightSize              = 0x0012,
    NegotiatedVersion               = 0x0013,
}
}

#[derive(Debug, PartialEq)]
pub struct QuicTransportFingerprint {
    pub idle_timeout: Vec<u8>, 
    pub max_udp_payload_size: Vec<u8>, 
    pub initial_max_data: Vec<u8>,
    pub initial_max_stream_data_bidi_local: Vec<u8>,
    pub initial_max_stream_data_bidi_remote: Vec<u8>,
    pub initial_max_stream_data_uni: Vec<u8>,
    pub initial_max_streams_bidi: Vec<u8>,
    pub initial_max_streams_uni: Vec<u8>,
    pub ack_delay_exponent: Vec<u8>,
    pub max_ack_delay: Vec<u8>,
    pub active_connection_id_limit: Vec<u8>,
    pub ids: Vec<u32>,
}

impl QuicTransportFingerprint {
    pub fn get_fingerprint(&self) -> u64 {
        let mut hasher = Sha1::new();
        hash_u32(&mut hasher, self.idle_timeout.len() as u32);
        hasher.input(&self.idle_timeout);

        hash_u32(&mut hasher, self.max_udp_payload_size.len() as u32);
        hasher.input(&self.max_udp_payload_size);

        hash_u32(&mut hasher, self.initial_max_data.len() as u32);
        hasher.input(&self.initial_max_data);

        hash_u32(&mut hasher, self.initial_max_stream_data_bidi_local.len() as u32);
        hasher.input(&self.initial_max_stream_data_bidi_local);

        hash_u32(&mut hasher, self.initial_max_stream_data_bidi_remote.len() as u32);
        hasher.input(&self.initial_max_stream_data_bidi_remote);

        hash_u32(&mut hasher, self.initial_max_stream_data_uni.len() as u32);
        hasher.input(&self.initial_max_stream_data_uni);

        hash_u32(&mut hasher, self.initial_max_streams_bidi.len() as u32);
        hasher.input(&self.initial_max_streams_bidi);

        hash_u32(&mut hasher, self.initial_max_streams_uni.len() as u32);
        hasher.input(&self.initial_max_streams_uni);

        hash_u32(&mut hasher, self.ack_delay_exponent.len() as u32);
        hasher.input(&self.ack_delay_exponent);

        hash_u32(&mut hasher, self.max_ack_delay.len() as u32);
        hasher.input(&self.max_ack_delay);

        hash_u32(&mut hasher, self.active_connection_id_limit.len() as u32);
        hasher.input(&self.active_connection_id_limit);

        hash_u32(&mut hasher, self.ids.len() as u32);
        for id in &self.ids {
            hash_u32(&mut hasher, *id);
        }
        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

#[derive(Debug, PartialEq)]
pub struct ClientHelloFingerprint {
    pub ch_tls_version: TlsVersion,
    pub cipher_suites: Vec<u8>,
    pub compression_methods: Vec<u8>,

    pub extensions: Vec<u8>,
    pub extensions_norm: Vec<u8>,
    pub named_groups: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub sig_algs: Vec<u8>,
    pub alpn: Vec<u8>,

    // fields below are not part of final fingerprint
    pub sni: Vec<u8>,
    pub ticket_size: Option<i16>,

    pub key_share: Vec<u8>, // format [[u16, u16], [u16, u16], ...], where each element is [group, length]
    pub psk_key_exchange_modes: Vec<u8>,
    pub supported_versions: Vec<u8>,
    pub cert_compression_algs: Vec<u8>,
    pub record_size_limit : Vec<u8>,
    pub quic_transport_fp: Option<QuicTransportFingerprint>,
    pub quic_transport_fp_id: u64,
}

pub type ClientHelloParseResult = Result<ClientHelloFingerprint, HelloParseError>;

impl ClientHelloFingerprint {
    pub fn from_try(a: &[u8]) -> ClientHelloParseResult {
        let mut offset = 0;
        if a.len() < 42 {
            return Err(HelloParseError::ShortBuffer);
        }

        if TlsHandshakeType::from_u8(a[offset]) != Some(TlsHandshakeType::ClientHello) {
            return Err(HelloParseError::NotAClientHello);
        }
        offset += 1;

        let ch_length = u8_to_u32_be(0, a[offset], a[offset+1], a[offset+2]);
        offset += 3;

        let ch_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[offset], a[offset+1])) {
            Some(tls_version) => tls_version,
            None => return Err(HelloParseError::UnknownChTLSVersion),
        };
        offset += 2;

        // 32 bytes of client random
        offset += 32;

        let session_id_len = a[offset] as usize;
        offset += session_id_len + 1;
        if offset + 2 > a.len() {
            return Err(HelloParseError::SessionIDLenExceedBuf);
        }

        let cipher_suites_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + cipher_suites_len + 1 > a.len() || cipher_suites_len % 2 == 1 {
            return Err(HelloParseError::CiphersuiteLenMisparse);
        }

        let cipher_suites = ungrease_u8(&a[offset..offset + cipher_suites_len]);
        offset += cipher_suites_len;

        let compression_len = a[offset] as usize;
        offset += 1;
        if offset + compression_len + 2 > a.len() {
            return Err(HelloParseError::CompressionLenExceedBuf);
        }

        let compression_methods = a[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + extensions_len > a.len() {
            return Err(HelloParseError::ExtensionsLenExceedBuf);
        }

        let mut ch = ClientHelloFingerprint {
            ch_tls_version: ch_tls_version,
            cipher_suites: cipher_suites,
            compression_methods: compression_methods,
            extensions: Vec::new(),
            extensions_norm: Vec::new(),
            named_groups: Vec::new(),
            ec_point_fmt: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
            quic_transport_fp: None,
            quic_transport_fp_id: 0,
        };

        let ch_end = offset + extensions_len;
        while offset < ch_end {
            if offset > ch_end - 4 {
                return Err(HelloParseError::ShortExtensionHeader);
            }
            let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
            if offset + ext_len > ch_end {
                return Err(HelloParseError::ExtensionLenExceedBuf);
            }
            ch.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len])?;
            offset = match (offset + 4).checked_add(ext_len) {
                Some(i) => i,
                None => return Err(HelloParseError::ExtensionLenExceedBuf),
            };
        }
        ch.sort_extensions();
        Ok(ch)
    }

    fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) -> Result<(), HelloParseError> {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.named_groups = ungrease_u8(ext_data);
            }
            Some(TlsExtension::SupportedPoints) => {
                self.ec_point_fmt = ext_data.to_vec();
            }
            Some(TlsExtension::SignatureAlgorithms) => {
                self.sig_algs = ext_data.to_vec();
            }
            Some(TlsExtension::ServerName) => {
                self.sni = ext_data.to_vec();
            }
            Some(TlsExtension::SessionTicket) => {
                if ext_data.len() <= i16::max_value() as usize {
                    self.ticket_size = Some(ext_data.len() as i16)
                }
            }
            Some(TlsExtension::ALPN) => {
                /* TODO Could be greasy
   ALPN identifiers beginning with
   the prefix "ignore/".  This corresponds to the seven-octet prefix:
   0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x2f.
                */
                self.alpn = ext_data.to_vec();
            }
            Some(TlsExtension::KeyShare) => {
                // key share goes [[group, size, key_itself], [group, size, key_itself], ...]
                // we want [[group, size], [group, size], ...]
                let key_share_data = ext_data.to_vec();
                if key_share_data.len() < 2 {
                    return Err(HelloParseError::KeyShareExtShort);
                }
                let key_share_inner_len = u8_to_u16_be(key_share_data[0], key_share_data[1]) as usize;
                let key_share_inner_data = match key_share_data.get(2 .. key_share_data.len()) {
                    Some(data) => data,
                    None => return Err(HelloParseError::KeyShareExtShort),
                };
                if key_share_inner_len != key_share_inner_data.len() {
                    return Err(HelloParseError::KeyShareExtLenMisparse);
                }
                self.key_share = parse_key_share(key_share_inner_data)?;
            }
            Some(TlsExtension::PskKeyExchangeModes) => {
                if ext_data.len() < 1 {
                    return Err(HelloParseError::PskKeyExchangeModesExtShort);
                }
                let psk_modes_inner_len = ext_data[0] as usize;
                if psk_modes_inner_len != ext_data.len() - 1 {
                    return Err(HelloParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.psk_key_exchange_modes = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::SupportedVersions) => {
                if ext_data.len() < 1 {
                    return Err(HelloParseError::SupportedVersionsExtLenMisparse);
                }
                let versions_inner_len = ext_data[0] as usize;
                if versions_inner_len != ext_data.len() - 1 {
                    return Err(HelloParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.supported_versions = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::CertificateCompressionAlgorithms) => {
                self.cert_compression_algs = ext_data.to_vec();
            }
            Some(TlsExtension::RecordSizeLimit) => {
                self.record_size_limit = ext_data.to_vec();
            },
            Some(TlsExtension::QuicTransportParameters) => {
                // self.quic_transport_fp = Some(self.handle_quic_transport_parameters(ext_data)?);
                // self.quic_transport_fp_id = self.quic_transport_fp.as_ref().unwrap().get_fingerprint();
            }
            _ => {}
        };

        self.extensions.append(&mut ungrease_u8(ext_id_u8));
        Ok(())
    }

    pub fn handle_quic_transport_parameters(&mut self, ext_data: &[u8]) -> Result<QuicTransportFingerprint, HelloParseError> {
        let mut offset = 0;
        let mut transport_params = QuicTransportFingerprint{
            idle_timeout: Vec::with_capacity(0), 
            max_udp_payload_size: Vec::with_capacity(0), 
            initial_max_data: Vec::with_capacity(0),
            initial_max_stream_data_bidi_local: Vec::with_capacity(0),
            initial_max_stream_data_bidi_remote: Vec::with_capacity(0),
            initial_max_stream_data_uni: Vec::with_capacity(0),
            initial_max_streams_bidi: Vec::with_capacity(0),
            initial_max_streams_uni: Vec::with_capacity(0),
            ack_delay_exponent: Vec::with_capacity(0),
            max_ack_delay: Vec::with_capacity(0),
            active_connection_id_limit: Vec::with_capacity(0),
            ids: Vec::with_capacity(0),
        };
        while offset < ext_data.len() {
            let ext_type_len = ((ext_data[offset] >> 6) + 1) as usize;
            let mut ext_type: Vec<u8> = Vec::new();
            for i in 0..4-ext_type_len {
                ext_type.push(0);
            }
            for i in 0..ext_type_len {
                ext_type.push(ext_data[offset+i]);
            }
            ext_type[4-ext_type_len] &= 0b00111111;
            let ext_type_int = u8_to_u32_be(ext_type[0], ext_type[1], ext_type[2], ext_type[3]);
            offset += ext_type_len;

            let ext_len_len = ((ext_data[offset] >> 6) + 1) as usize;
            let mut ext_len: Vec<u8> = Vec::new();
            for i in 0..4-ext_len_len {
                ext_len.push(0);
            }
            for i in 0..ext_len_len {
                ext_len.push(ext_data[offset+i]);
            }
            ext_len[4-ext_len_len] &= 0b00111111;
            let ext_len_int = u8_to_u32_be(ext_len[0], ext_len[1], ext_len[2], ext_len[3]) as usize;
            offset += ext_len_len;
            let ext_contents = ext_data[offset..offset+ext_len_int].to_vec();
            offset += ext_len_int;
            transport_params.ids.push(ext_type_int);
            match QuicTransportParams::from_u32(ext_type_int) {
                Some(t_type) => {
                    match t_type {
                        QuicTransportParams::IdleTimeout => transport_params.idle_timeout = ext_contents,
                        QuicTransportParams::MaxUdpPayloadSize => transport_params.max_udp_payload_size = ext_contents,
                        QuicTransportParams::InitialMaxData => transport_params.initial_max_data = ext_contents,
                        QuicTransportParams::InitialMaxStreamDataBidiLocal => transport_params.initial_max_stream_data_bidi_local = ext_contents,
                        QuicTransportParams::InitialMaxStreamDataBidiRemote => transport_params.initial_max_stream_data_bidi_remote = ext_contents,
                        QuicTransportParams::InitialMaxStreamDataUni => transport_params.initial_max_stream_data_uni = ext_contents,
                        QuicTransportParams::InitialMaxStreamsBidi => transport_params.initial_max_streams_bidi = ext_contents,
                        QuicTransportParams::InitialMaxStreamsUni => transport_params.initial_max_streams_uni = ext_contents,
                        QuicTransportParams::AckDelayExponent => transport_params.ack_delay_exponent = ext_contents,
                        QuicTransportParams::MaxAckDelay => transport_params.max_ack_delay = ext_contents,
                        QuicTransportParams::ActiveConnectionIDLimit => transport_params.active_connection_id_limit = ext_contents,
                        _ => {},
                        // QuicTransportParams::VersionInformation => todo!(),
                        // QuicTransportParams::MaxDatagramFrameSize => todo!(),
                        // QuicTransportParams::InitialRtt => todo!(),
                        // QuicTransportParams::GoogleConnectionOptions => todo!(),
                        // QuicTransportParams::GoogleVersion => todo!(),
                        // QuicTransportParams::DatagramFlightSize => todo!(),
                        // QuicTransportParams::NegotiatedVersion => todo!(),
                    }
                },
                None => {},
            };
        }
        transport_params.ids.sort();
        Ok(transport_params)
    }

    pub fn sort_extensions(&mut self) {
        let mut extensions = vec_u8_to_vec_u16_be(&self.extensions);
        extensions.sort();
        self.extensions_norm = vec_u16_to_vec_u8_be(&extensions);
    }

    pub fn get_fingerprint(&self, normalized_ext: bool) -> u64 {
        //let mut s = DefaultHasher::new(); // This is SipHasher13, nobody uses this...
        //let mut s = SipHasher24::new_with_keys(0, 0);
        // Fuck Rust's deprecated "holier than thou" bullshit attitude
        // We'll use SHA1 instead...

        let mut hasher = Sha1::new();
        let version = (self.ch_tls_version as u32);
        hash_u32(&mut hasher, version);


        hash_u32(&mut hasher, self.cipher_suites.len() as u32);
        hasher.input(&self.cipher_suites);

        hash_u32(&mut hasher, self.compression_methods.len() as u32);
        hasher.input(&self.compression_methods);

        if normalized_ext {
            hash_u32(&mut hasher, self.extensions_norm.len() as u32);
            hasher.input(&self.extensions_norm);
        } else {
            hash_u32(&mut hasher, self.extensions.len() as u32);
            hasher.input(&self.extensions);
        }

        hash_u32(&mut hasher, self.named_groups.len() as u32);
        hasher.input(&self.named_groups);

        hash_u32(&mut hasher, self.ec_point_fmt.len() as u32);
        hasher.input(&self.ec_point_fmt);

        hash_u32(&mut hasher, self.sig_algs.len() as u32);
        hasher.input(&self.sig_algs);

        hash_u32(&mut hasher, self.alpn.len() as u32);
        hasher.input(&self.alpn);

        hash_u32(&mut hasher, self.key_share.len() as u32);
        hasher.input(&self.key_share);

        hash_u32(&mut hasher, self.psk_key_exchange_modes.len() as u32);
        hasher.input(&self.psk_key_exchange_modes);

        hash_u32(&mut hasher, self.supported_versions.len() as u32);
        hasher.input(&self.supported_versions);

        hash_u32(&mut hasher, self.cert_compression_algs.len() as u32);
        hasher.input(&self.cert_compression_algs);

        hash_u32(&mut hasher, self.record_size_limit.len() as u32);
        hasher.input(&self.record_size_limit);

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

impl fmt::Display for ClientHelloFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ch: {:?} ciphers: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} sig_algs: {:X} alpn: {:X} sni: {}",
               self.ch_tls_version,
               vec_u8_to_vec_u16_be(&self.cipher_suites).as_slice().as_hex(),
               &self.compression_methods.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.named_groups).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.sig_algs).as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
               String::from_utf8_lossy(self.sni.clone().as_slice()),
        )
    }
}

// Coverts array of [u8] into Vec<u8>, and performs ungrease.
// Ungrease stores all greasy extensions/ciphers/etc under single id to produce single fingerprint
// https://tools.ietf.org/html/draft-davidben-tls-grease-01
fn ungrease_u8(arr: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = arr.iter().cloned().collect();
    for i in 0..(arr.len() / 2) {
        if res[2 * i] == res[2 * i + 1] && (res[2 * i] & 0x0f == 0x0a) {
            res[2 * i] = 0x0a;
            res[2 * i + 1] = 0x0a;
        }
    }
    res
}

// parses groups and lengths of key_share (but not keys themselves) and ungreases the groups
// passed vector must already be stripped from overall size
fn parse_key_share(arr: &[u8]) -> Result<Vec<u8>, HelloParseError> {
    if arr.len() > std::u16::MAX as usize {
        return Err(HelloParseError::KeyShareExtLong);
    }
    let mut i: usize = 0;
    let mut res = Vec::new();
    while i < arr.len() {
        if i  > arr.len() - 4 {
            return Err(HelloParseError::KeyShareExtShort);
        }
        let mut group_size = ungrease_u8(&arr[i .. i+2]);
        let size = u8_to_u16_be(arr[i+2], arr[i+3]) as usize;
        group_size.push(arr[i+2]);
        group_size.push(arr[i+3]);
        res.append(&mut group_size);

        i = match i.checked_add(4 + size) {
            Some(i) => i,
            None => return Err(HelloParseError::KeyShareExtShort),
        };
    }
    Ok(res)
}