use crate::common::u8_to_u16_be;

const SHORT_HEADER: u8 = 0b01;
const LONG_HEADER: u8 = 0b11;

const INIT_PACKET: u8 = 0b00;
const ZERO_RTT_PACKET: u8 = 0b01;
const HANDSHAKE_PACKET: u8 = 0b10;
const RETRY_PACKET: u8 = 0b11;

const VERSION_NEGOTIATION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

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
}

#[derive(Debug, Clone)]
pub struct VersionNegotiationPacket {
    dest_cid_len: usize,
    dest_cid: Vec<u8>,
    src_cid_len: usize,
    src_cid: Vec<u8>,
    supported_versions: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct InitialPacket {
    dest_cid_len: usize,
    dest_cid: Vec<u8>,
    src_cid_len: usize,
    src_cid: Vec<u8>,
    token_len: usize,
    token: Vec<u8>,
    packet_len: usize,
    packet_num: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ZeroRttPacket {
    dest_cid_len: usize,
    dest_cid: Vec<u8>,
    src_cid_len: usize,
    src_cid: Vec<u8>,
    token_len: usize,
    token: Vec<u8>,
    packet_len: usize,
    packet_num: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HandshakePacket {
    dest_cid_len: usize,
    dest_cid: Vec<u8>,
    src_cid_len: usize,
    src_cid: Vec<u8>,
    token_len: usize,
    token: Vec<u8>,
    packet_len: usize,
    packet_num: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RetryPacket {
    dest_cid_len: usize,
    dest_cid: Vec<u8>,
    src_cid_len: usize,
    src_cid: Vec<u8>,
    retry_token: Vec<u8>,
    retry_integrity_tag: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct QuicConn {
    pub start_time: i64,
    pub last_updated: i64,
    pub is_ipv4: u8,
    pub server_port: u16,
    pub quic_version: Vec<u8>,
    pub version_negotiation_packets: Vec<VersionNegotiationPacket>,
    pub initial_packets: Vec<InitialPacket>,
    pub zero_rtt_packets: Vec<ZeroRttPacket>,
    pub handshake_packets: Vec<HandshakePacket>,
    pub retry_packets: Vec<RetryPacket>,
    pub server_cids: Vec<Vec<u8>>,
    pub client_cids: Vec<Vec<u8>>,
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
            version_negotiation_packets: Vec::new(),
            initial_packets: Vec::new(),
            zero_rtt_packets: Vec::new(),
            handshake_packets: Vec::new(),
            retry_packets: Vec::new(),
            server_cids: Vec::new(),
            client_cids: Vec::new(),
        })
    }

    pub fn parse_header(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        // The highest order bit indicates the packet form.
        // The second highest order bit is a checkbit that should always be 1;
        let packet_form = record[0] >> 6 & 0b00000011;
        match packet_form {
            SHORT_HEADER => return self.parse_short_header(record, is_client),
            LONG_HEADER => return self.parse_long_header(record, is_client),
            _ => return Err(QuicParseError::UnknownHeaderType)
        }
    }

    pub fn parse_long_header(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortLongHeader);
        }
        let packet_type = record[offset] >> 4 & 0b00000011;
        let _reserved = record[offset] >> 2 & 0b00000011;
        let packet_num_len = ((record[offset] & 0b00000011) as usize) + 1;
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
            return self.parse_version_negotiation(&record[offset..]);
        }
        match packet_type {
            INIT_PACKET => return self.parse_init(&record[offset..], packet_num_len, is_client),
            ZERO_RTT_PACKET => return self.parse_zero_rtt(&record[offset..], packet_num_len),
            HANDSHAKE_PACKET => return self.parse_handshake(&record[offset..], packet_num_len),
            RETRY_PACKET => return self.parse_retry(&record[offset..], is_client),
            _ => return Err(QuicParseError::UnknownPacketType)
        }
    }

    pub fn parse_version_negotiation(&mut self, record: &[u8]) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortVersionNegotiationPacket);
        }
        let dest_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortVersionNegotiationPacket);
        }
        let dest_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortVersionNegotiationPacket);
        }
        let src_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + src_cid_len {
            return Err(QuicParseError::ShortVersionNegotiationPacket);
        }
        let src_cid = &record[offset..offset+src_cid_len];
        offset += src_cid_len;
        let mut supported_versions = Vec::new();
        while offset < record.len() {
            if record.len() - 1 < offset + 4 {
                return Err(QuicParseError::InvalidVersionLength)
            }
            supported_versions.push(record[offset..offset+4].to_vec());
            offset += 4;
        }
        let version_negotiation = VersionNegotiationPacket {
            dest_cid_len: dest_cid_len,
            dest_cid: dest_cid.to_vec(),
            src_cid_len: src_cid_len,
            src_cid: src_cid.to_vec(),
            supported_versions: supported_versions,
        };
        self.version_negotiation_packets.push(version_negotiation);
        return Ok(QuicParseResult::ParsedVersionNegotiation)
    } 

    pub fn parse_init(&mut self, record: &[u8], packet_num_len: usize, is_client: bool) -> Result<QuicParseResult, QuicParseError> {
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
        offset += token_len;
        if record.len() - 1 < offset + 1 {
            return Err(QuicParseError::ShortInitPacket);
        }
        let packet_len = u8_to_u16_be(record[offset], record[offset+1]) as usize;
        offset += 2;
        if record.len() - 1 < offset + packet_num_len {
            return Err(QuicParseError::ShortInitPacket);
        }
        let packet_num = &record[offset..offset+packet_num_len];
        offset += packet_num_len;
        let init = InitialPacket {
            dest_cid_len: dest_cid_len,
            dest_cid: dest_cid.to_vec(),
            src_cid_len: src_cid_len,
            src_cid: src_cid.to_vec(),
            token_len: token_len,
            token: token.to_vec(),
            packet_len: packet_len,
            packet_num: packet_num.to_vec(),
        };
        self.initial_packets.push(init);
        Ok(QuicParseResult::ParsedInit)
    }

    pub fn parse_zero_rtt(&mut self, record: &[u8], packet_num_len: usize) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let dest_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let dest_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let src_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + src_cid_len {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let src_cid = &record[offset..offset+src_cid_len];
        offset += src_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let token_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + token_len {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let token = &record[offset..offset+token_len];
        offset += token_len;
        if record.len() - 1 < offset + 1 {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let packet_len = u8_to_u16_be(record[offset], record[offset+1]) as usize;
        offset += 2;
        if record.len() - 1 < offset + packet_num_len {
            return Err(QuicParseError::ShortZeroRttPacket);
        }
        let packet_num = &record[offset..offset+packet_num_len];
        offset += packet_num_len;
        let zero_rtt = ZeroRttPacket {
            dest_cid_len: dest_cid_len,
            dest_cid: dest_cid.to_vec(),
            src_cid_len: src_cid_len,
            src_cid: src_cid.to_vec(),
            token_len: token_len,
            token: token.to_vec(),
            packet_len: packet_len,
            packet_num: packet_num.to_vec(),
        };
        self.zero_rtt_packets.push(zero_rtt);
        Ok(QuicParseResult::ParsedZeroRTT)
    }

    pub fn parse_handshake(&mut self, record: &[u8], packet_num_len: usize) -> Result<QuicParseResult, QuicParseError> {
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let dest_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let dest_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let src_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + src_cid_len {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let src_cid = &record[offset..offset+src_cid_len];
        offset += src_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let token_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + token_len {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let token = &record[offset..offset+token_len];
        offset += token_len;
        if record.len() - 1 < offset + 1 {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let packet_len = u8_to_u16_be(record[offset], record[offset+1]) as usize;
        offset += 2;
        if record.len() - 1 < offset + packet_num_len {
            return Err(QuicParseError::ShortHandshakePacket);
        }
        let packet_num = &record[offset..offset+packet_num_len];
        offset += packet_num_len;
        let handshake = HandshakePacket {
            dest_cid_len: dest_cid_len,
            dest_cid: dest_cid.to_vec(),
            src_cid_len: src_cid_len,
            src_cid: src_cid.to_vec(),
            token_len: token_len,
            token: token.to_vec(),
            packet_len: packet_len,
            packet_num: packet_num.to_vec(),
        };
        self.handshake_packets.push(handshake);
        Ok(QuicParseResult::ParsedHandshake)
    }

    pub fn parse_retry(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        // Parse packet
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortRetryPacket);
        }
        let dest_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortRetryPacket);
        }
        let dest_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortRetryPacket);
        }
        let src_cid_len = record[offset] as usize;
        offset += 1;
        if record.len() - 1 < offset + src_cid_len {
            return Err(QuicParseError::ShortRetryPacket);
        }
        let src_cid = &record[offset..offset+src_cid_len];
        offset += src_cid_len;
        if offset > record.len()-16 {
            return Err(QuicParseError::ShortRetryPacket);
        }
        let retry_token = &record[offset..record.len()-16];
        offset = record.len()-16;
        let retry_integrity_tag = &record[offset..];

        // Set new server CID
        if !is_client {
            self.server_cids.push(src_cid.to_vec());
        }

        let retry = RetryPacket {
            dest_cid_len: dest_cid_len,
            dest_cid: dest_cid.to_vec(),
            src_cid_len: src_cid_len,
            src_cid: src_cid.to_vec(),
            retry_token: retry_token.to_vec(),
            retry_integrity_tag: retry_integrity_tag.to_vec(),
        };
        self.retry_packets.push(retry);
        Ok(QuicParseResult::ParsedRetry)
    }

    pub fn parse_short_header(&mut self, record: &[u8], is_client: bool) -> Result<QuicParseResult, QuicParseError> {
        let dest_cid_len;
        if is_client {
            if let Some(cid) = self.server_cids.last() {
                dest_cid_len = cid.len();
            } else {
                dest_cid_len = 0;
            }
        } else {
            if let Some(cid) = self.client_cids.last() {
                dest_cid_len = cid.len();
            } else {
                dest_cid_len = 0;
            }
        }
        let mut offset = 0;
        if record.len() - 1 < offset {
            return Err(QuicParseError::ShortShortHeader);
        }
        let _spin_bit = record[offset] >> 5 & 0b00000001;
        let _reserved = record[offset] >> 3 & 0b00000011;
        let _key_phase = record[offset] >> 2 & 0b00000001;
        let packet_num_len = ((record[offset] & 0b00000011) as usize) + 1;
        offset += 1;
        if record.len() - 1 < offset + dest_cid_len {
            return Err(QuicParseError::ShortShortHeader);
        }
        let _dst_cid = &record[offset..offset+dest_cid_len];
        offset += dest_cid_len;
        if record.len() - 1 < offset + packet_num_len {
            return Err(QuicParseError::ShortShortHeader);
        }
        let _packet_number = &record[offset+packet_num_len];
        offset += packet_num_len;
        return Ok(QuicParseResult::ParsedShortHeader)
    }
}