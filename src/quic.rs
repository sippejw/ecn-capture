use std::fmt;

use crate::common::{u8_to_u32_be, hash_u32};
use crate::{crypto, tls_parser};
use byteorder::{BigEndian, ByteOrder};
use ::crypto::digest::Digest;
use ::crypto::sha1::Sha1;
use enum_primitive::{self, enum_from_primitive};
use num::FromPrimitive;
use enum_primitive::enum_from_primitive_impl;
use enum_primitive::enum_from_primitive_impl_ty;
use tls_parser::{ClientHelloFingerprint};

const SHORT_HEADER: u8 = 0b01;
const LONG_HEADER: u8 = 0b11;

const INIT_PACKET: u8 = 0b00;
const ZERO_RTT_PACKET: u8 = 0b01;
const HANDSHAKE_PACKET: u8 = 0b10;
const RETRY_PACKET: u8 = 0b11;

// From CloudFlare's Quiche
/// Supported QUIC versions.
///
/// Note that the older ones might not be fully supported.
pub const PROTOCOL_VERSION_V1: u32 = 0x0000_0001;
pub const PROTOCOL_VERSION_DRAFT27: u32 = 0xff00_001b;
pub const PROTOCOL_VERSION_DRAFT28: u32 = 0xff00_001c;
pub const PROTOCOL_VERSION_DRAFT29: u32 = 0xff00_001d;

const VERSION_NEGOTIATION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
enum_from_primitive! {
    #[repr(u8)]
    #[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum FrameType {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    STREAM = 0x08,
    STREAM_FIN = 0x09,
    STREAM_LEN = 0x0a,
    STREAM_LEN_FIN = 0x0b,
    STREAM_OFF = 0x0c,
    STREAM_OFF_FIN = 0x0d,
    STREAM_OFF_LEN = 0x0e,
    STREAM_OFF_LEN_FIN = 0x0f,
}
}

#[derive(Debug, Clone)]
pub enum QuicParseResult {
    ParsedVersionNegotiation,
    ParsedHandshake,
    ParsedInit,
    ParsedZeroRTT,
    ParsedRetry,
    ParsedShortHeader,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QuicParseError {
    UnknownHeaderType,
    UnknownPacketType,
    ShortVersionNegotiationPacket,
    ShortRetryPacket,
    ShortInitPacket,
    ShortLongHeader,
    ShortShortHeader,
    ShortZeroRttPacket,
    ShortHandshakePacket,
    ClientAttemptedVersionNegotiation,
    InvalidVersionLength,
    CryptoFail,
    UnknownFrameType,
    UnhandledFrameType,
    FailedTLSFingerprinting,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoFrame {
    pub offset: usize,
    pub length: usize,
    pub contents: Vec<u8>,
}

#[derive(Debug)]
pub struct QuicConn {
    pub start_time: i64,
    pub last_updated: i64,
    pub is_ipv4: u8,
    pub server_port: u16,
    pub quic_version: Vec<u8>,
    pub server_cid: Vec<u8>,
    pub client_cid: Vec<u8>,
    pub initial_packet_number: Vec<u8>,
    pub frames: Vec<u8>,
    pub token_length: u8,
    pub client_decrypt: Option<crypto::Open>,
    pub server_decrypt: Option<crypto::Open>,
    pub tls_fp: i64,
    pub tls_ch: Option<ClientHelloFingerprint>,
}

impl QuicConn {
    pub fn new_conn(is_ipv4: u8, server_port: u16) -> Result<QuicConn, QuicParseError> {
        let curr_time = time::now().to_timespec().sec;
        Ok(QuicConn {
            start_time: curr_time,
            last_updated: curr_time,
            server_port: server_port,
            is_ipv4: is_ipv4,
            quic_version: Vec::new(),
            server_cid: Vec::new(),
            client_cid: Vec::new(),
            initial_packet_number: Vec::new(),
            frames: Vec::new(),
            token_length: 0,
            client_decrypt: None,
            server_decrypt: None,
            tls_fp: 0,
            tls_ch: None,
        })
    }

    pub fn get_fp(&mut self) -> u64 {
        let mut hasher = Sha1::new();

        hash_u32(&mut hasher, self.quic_version.len() as u32);
        hasher.input(&self.quic_version);

        hash_u32(&mut hasher, self.server_cid.len() as u32);

        hash_u32(&mut hasher, self.client_cid.len() as u32);

        hash_u32(&mut hasher, self.initial_packet_number.len() as u32);
        hasher.input(&self.initial_packet_number);

        hash_u32(&mut hasher, self.frames.len() as u32);
        hasher.input(&self.frames);

        hash_u32(&mut hasher, self.token_length as u32);

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }

    pub fn parse_header(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        // The highest order bit indicates the packet form.
        // The second highest order bit is a checkbit that should always be 1;
        self.last_updated = time::now().to_timespec().sec;
        let packet_form = record[0] >> 6 & 0b00000011;
        match packet_form {
            LONG_HEADER => return self.parse_long_header(record, is_client),
            _ => return Err(QuicParseError::UnknownHeaderType)
        }
    }

    fn parse_long_header(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        let protected_byte = record[offset];
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortLongHeader);
        }
        let packet_type = record[offset] >> 4 & 0b00000011;
        offset += 1;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortLongHeader);
        }
        let version = &record[offset..offset+4];
        offset += 4;
        if version == &VERSION_NEGOTIATION {
            if is_client {
                return Err(QuicParseError::ClientAttemptedVersionNegotiation)
            }
        }
        self.quic_version = version.to_vec();
        match packet_type {
            INIT_PACKET => return self.parse_init(&record[offset..], protected_byte, version, is_client),
            _ => return Err(QuicParseError::UnknownPacketType)
        }
    } 

    fn parse_init(&mut self, record: &[u8], protected_header: u8, version: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortInitPacket);
        }
        let dest_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let dest_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortInitPacket);
        }
        let src_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + src_cid_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let src_cid = &record[offset..offset+src_cid_len];
        offset += src_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortInitPacket);
        }
        let token_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + token_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let token = &record[offset..offset+token_len];
        self.token_length = token_len as u8;
        offset += token_len;
        if record.len() - 1 < offset + 1 {
            return Err(QuicParseError::ShortInitPacket);
        }
        let packet_len_len = ((record[offset] >> 6) + 1) as usize;
        let mut packet_len = Vec::new();
        for i in 0..4-packet_len_len {
            packet_len.push(0);
        }
        if record.len() - 1 < offset + packet_len_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let mut record_packet_len = record[offset..offset+packet_len_len].to_vec();
        let a_record_packet_len = record[offset..offset+packet_len_len].to_vec();
        record_packet_len[0] = record_packet_len[0] & 0b00111111;
        packet_len.append(& mut record_packet_len);
        let packet_len_int = BigEndian::read_i32(&packet_len) as usize;
        offset += packet_len_len;
        
        if is_client && self.client_decrypt.is_none() && self.server_decrypt.is_none() {
            self.decrypt_init(dest_cid)?;
        }
        if self.client_decrypt.is_none() || self.server_decrypt.is_none() {
            return Err(QuicParseError::CryptoFail);
        }
        let sample_len = self.client_decrypt.as_ref().unwrap().hp_key.algorithm().sample_len();
        if record.len() - 1 < offset + 4 + sample_len {
            return Err(QuicParseError::ShortInitPacket);
        }

        let unprotected_header: u8;
        let mask: [u8; 5];
        let hp_sample: &[u8];
        if is_client{
            hp_sample = &record[offset+4..offset+sample_len+4];
            mask = self.server_decrypt.as_ref().unwrap().new_mask(hp_sample)?;
            unprotected_header = protected_header ^ (mask[0] & 0b00001111);
        } else {
            hp_sample = &record[offset+4..offset+sample_len+4];
            mask = self.server_decrypt.as_ref().unwrap().new_mask(hp_sample)?;
            unprotected_header = protected_header ^ (mask[0] & 0b00001111);
        }
        if (unprotected_header >> 2) & 0b00000011 != 0 {
            return Err(QuicParseError::CryptoFail);
        }
        let packet_num_len = ((unprotected_header & 0b00000011) + 1) as usize;
        if record.len() - 1 < offset + packet_num_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let protected_packet_number = record[offset..offset+packet_num_len].to_vec();
        let mut packet_number: Vec<u8> = Vec::new();
        for i in 0..4-protected_packet_number.len() {
            packet_number.push(0);
        }
        for i in 0..protected_packet_number.len() {
            packet_number.push(protected_packet_number[i] ^ mask[i+1]);
        }
        let packet_number_int = BigEndian::read_i32(&packet_number);
        self.initial_packet_number = packet_number;
        offset += packet_num_len;

        let tag_len = self.client_decrypt.as_ref().unwrap().alg().tag_len();
        let cipher_text_len = packet_len_int - tag_len - 1;
        if record.len() - 1 < offset + cipher_text_len + tag_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let mut buf = record[offset..offset+cipher_text_len].to_vec();
        offset += cipher_text_len;
        let tag_len = self.client_decrypt.as_ref().unwrap().alg().tag_len();
        let tag = &record[offset..offset+tag_len];
        let mut ad = Vec::new();
        ad.append(&mut [unprotected_header].to_vec());
        ad.append(&mut version.to_vec());
        ad.append(&mut [dest_cid_len as u8].to_vec());
        ad.append(&mut dest_cid.to_vec());
        ad.append(&mut [src_cid_len as u8].to_vec());
        ad.append(&mut src_cid.to_vec());
        ad.append(&mut [token_len as u8].to_vec());
        ad.append(&mut token.to_vec());
        ad.append(&mut a_record_packet_len.to_vec());
        ad.append(&mut &mut self.initial_packet_number[4-packet_num_len..].to_vec());

        let decrypted_packet: Vec<u8>;
        if is_client {
            decrypted_packet = self.server_decrypt.as_ref().unwrap().open_with_u64_counter(packet_number_int as u64, &ad, &mut buf, tag)?;
        } else {
            decrypted_packet = self.client_decrypt.as_ref().unwrap().open_with_u64_counter(packet_number_int as u64, &ad, &mut buf, tag)?;
        }
        self.handle_frames(&decrypted_packet);
        Ok(QuicParseResult::ParsedInit)
    }

    fn handle_frames(&mut self, decrypted_record: &[u8]) -> Result<(), QuicParseError> {
        let mut offset = 0;
        let mut frame_list: Vec<u8> = Vec::new();
        let mut crypto_frames = Vec::new();
        while offset < decrypted_record.len() {
            let record_type = match FrameType::from_u8(decrypted_record[offset]) {
                Some(r_type) => r_type,
                None => return Err(QuicParseError::UnknownFrameType),
            };
            offset += 1;
            match record_type {
                FrameType::PADDING => {
                    match frame_list.last() {
                        Some(last_frame) => {
                            if last_frame.clone() != FrameType::PADDING as u8 {
                                frame_list.push(FrameType::PADDING as u8);
                            }
                        },
                        None => frame_list.push(FrameType::PADDING as u8),
                    }
                },
                FrameType::CRYPTO => {
                    frame_list.push(FrameType::CRYPTO as u8);
                    let crypto_offset_len = ((decrypted_record[offset] >> 6) + 1) as usize;
                    let mut crypto_offset = Vec::new();
                    for i in 0..4-crypto_offset_len {
                        crypto_offset.push(0);
                    }
                    let mut crypto_offset_record = decrypted_record[offset..offset+crypto_offset_len].to_vec();
                    crypto_offset_record[0] = crypto_offset_record[0] & 0b00111111;
                    crypto_offset.append(&mut crypto_offset_record);
                    offset += crypto_offset_len;
                    let crypto_offset_int = BigEndian::read_i32(&crypto_offset) as usize;
                    let length_len = ((decrypted_record[offset] >> 6) + 1) as usize;
                    let mut length = Vec::new();
                    for i in 0..4-length_len {
                        length.push(0);
                    }
                    let mut length_record = decrypted_record[offset..offset+length_len].to_vec();
                    length_record[0] = length_record[0] & 0b00111111;
                    length.append(&mut length_record);
                    let length_int = BigEndian::read_i32(&length) as usize;
                    offset += length_len;
                    let crypto_contents = decrypted_record[offset..offset+length_int].to_vec();
                    offset += length_int;
                    crypto_frames.push(CryptoFrame{offset: crypto_offset_int, length: length_int, contents: crypto_contents});
                },
                _ => return Err(QuicParseError::UnhandledFrameType),
            }
        }
        crypto_frames.sort_by(|a, b| b.offset.cmp(&a.offset));
        crypto_frames.reverse();
        let mut combined_crypto_frame: Vec<u8> = Vec::new();
        for mut frame in crypto_frames {
            combined_crypto_frame.append(&mut frame.contents);
        }
        self.frames = frame_list;
        match ClientHelloFingerprint::from_try(&combined_crypto_frame) {
            Ok(fp) => {
                let fp_id = fp.get_fingerprint(true);
                self.tls_fp = fp_id as i64;
                self.tls_ch = Some(fp);
            },
            Err(_) => return Err(QuicParseError::FailedTLSFingerprinting),
        }
        Ok(())
    }

    fn decrypt_init(&mut self, dest_cid: &[u8]) -> Result<(), QuicParseError> {
        self.client_decrypt = Some(crypto::derive_initial_key_material(dest_cid, u8_to_u32_be(self.quic_version[0], self.quic_version[1], self.quic_version[2], self.quic_version[3]), false)?);
        self.server_decrypt = Some(crypto::derive_initial_key_material(dest_cid, u8_to_u32_be(self.quic_version[0], self.quic_version[1], self.quic_version[2], self.quic_version[3]), true)?);
        Ok(())
    }

}

impl fmt::Display for QuicConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "start: {:?} last: {:?} port: {:?} ipv4: {:?} \
        version: {:X?} cid: {:X?} sid: {:X?} packet_num: {:X?} frames: {:X?} token_length: {:X?}",
               self.start_time, self.last_updated,
               self.server_port, self.is_ipv4,
               self.quic_version, self.client_cid,
               self.server_cid, self.initial_packet_number,
               self.frames, self.token_length,
        )
    }
}
