use std::ops::Sub;

use log::{warn, info};

use crate::quic::{QuicParseResult, QuicParseError};

pub struct StatsTracker {
    pub last_print: time::Tm,
    pub total_packets: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub packets_logged: u64,
    pub tcp_packets_seen: u64,
    pub bytes_processed: u64,
    pub bad_checksums: u64,
    pub connections_seen: u64,
    pub connections_started: u64,
    pub connections_closed: u64,

    pub udp_packets_seen: u64,

    //mptcp
    pub mptcp_packets_seen: u64,
    pub mptcp_capable: u64,
    pub mptcp_join: u64,
    pub mptcp_data: u64,
    pub mptcp_add: u64,

    //quic standard
    pub quic_packets: u64,
    pub quic_version_negotiation: u64,
    pub quic_inits: u64,
    pub quic_retries: u64,
    pub quic_handshakes: u64,
    pub quic_zero_rtts: u64,
    pub quic_short_headers: u64,

    //quic error
    pub quic_errors: u64,
    pub quic_unknown_header: u64,
    pub quic_unknown_packet: u64,
    pub quic_short_version_negotiation: u64,
    pub quic_short_retry: u64,
    pub quic_short_init: u64,
    pub quic_short_long_header: u64,
    pub quic_short_short_header: u64,
    pub quic_client_attempted_version_negotiation: u64,
    pub quic_invalid_version_length: u64,
    pub quic_short_handshake: u64,
    pub quic_short_zero_rtt: u64,
}

impl StatsTracker {
    pub fn new() -> StatsTracker {
        StatsTracker {
            last_print: time::now(),

            total_packets: 0,
            ipv4_packets: 0,
            ipv6_packets: 0,
            packets_logged: 0,
            tcp_packets_seen: 0,
            bytes_processed: 0,
            bad_checksums: 0,
            connections_seen: 0,
            connections_started: 0,
            connections_closed: 0,

            udp_packets_seen: 0,

            // mptcp
            mptcp_packets_seen: 0,
            mptcp_capable: 0,
            mptcp_join: 0,
            mptcp_data: 0,
            mptcp_add: 0,

            // quic
            quic_packets: 0,
            quic_version_negotiation: 0,
            quic_inits: 0,
            quic_retries: 0,
            quic_handshakes: 0,
            quic_zero_rtts: 0,
            quic_short_headers: 0,

            quic_errors: 0,
            quic_unknown_header: 0,
            quic_unknown_packet: 0,
            quic_short_version_negotiation: 0,
            quic_short_retry: 0,
            quic_short_init: 0,
            quic_short_long_header: 0,
            quic_short_short_header: 0,
            quic_client_attempted_version_negotiation: 0,
            quic_invalid_version_length: 0,
            quic_short_handshake: 0,
            quic_short_zero_rtt: 0,
        }
    }

    pub fn print_stats(&mut self, curr_drops: i64, total_drops: i64) {
        let curr_time = time::now();
        self.print_general_stats(curr_drops, total_drops);
        self.print_quic_stats();
        self.last_print = curr_time;
    }

    pub fn print_quic_stats(&mut self) {
        info!("[quic stats] quic count: {} [version negotiation: {}, init: {}, retry: {}, handshake: {}, zero rtt: {}, short header: {}] errors: {} [unknown header: {}, unknown packet: {}, short vn: {}, short retry: {}, short init: {},  short handshake: {} short zero rtt: {} short long: {}, short short: {}, client vn: {}, invalid version length: {}]",
            self.quic_packets,
            self.quic_version_negotiation,
            self.quic_inits,
            self.quic_retries,
            self.quic_handshakes,
            self.quic_zero_rtts,
            self.quic_short_headers,
            self.quic_errors,
            self.quic_unknown_header,
            self.quic_unknown_packet,
            self.quic_short_version_negotiation,
            self.quic_short_retry,
            self.quic_short_init,
            self.quic_short_handshake,
            self.quic_short_zero_rtt,
            self.quic_short_long_header,
            self.quic_short_short_header,
            self.quic_client_attempted_version_negotiation,
            self.quic_invalid_version_length,
        );

        //reset quic counts
        self.quic_packets = 0;
        self.quic_version_negotiation = 0;
        self.quic_inits = 0;
        self.quic_retries = 0;
        self.quic_handshakes = 0;
        self.quic_zero_rtts = 0;
        self.quic_short_headers = 0;
        // reset quic errors
        self.quic_errors = 0;
        self.quic_unknown_header = 0;
        self.quic_unknown_packet = 0;
        self.quic_short_version_negotiation = 0;
        self.quic_short_retry = 0;
        self.quic_short_init = 0;
        self.quic_short_handshake = 0;
        self.quic_short_zero_rtt = 0;
        self.quic_short_long_header = 0;
        self.quic_short_short_header = 0;
        self.quic_client_attempted_version_negotiation = 0;
        self.quic_invalid_version_length = 0;
    }

    pub fn print_general_stats(&mut self, curr_drops: i64, total_drops: i64) {
        let curr_time = time::now();
        let diff = curr_time.sub(self.last_print);
        let diff_float = match diff.num_nanoseconds() {
            Some(diff_float) => diff_float as f64 * 0.000000001,
            None => {
                warn!("stats time diff is too big!");
                return
            }
        };
        if diff_float < 10e-3 {
            warn!("print stats slower!");
            return
        }

        const BYTES_TO_GBPS: f64 = (1000 * 1000 * 1000 / 8) as f64;
        info!("[general stats] drops: {} {} all packets: {} [ipv4: {}, ipv6: {}] tcp packets: {} (bad tcp checksums: {}) connections started: {} / connections seen: {}; udp packets: {} mptcp packets seen: {} [capable: {}, join: {}, data: {}, add: {}], Gbps: {:.4}",
                curr_drops,
                total_drops,
                self.total_packets,
                self.ipv4_packets,
                self.ipv6_packets,
                self.tcp_packets_seen,
                self.bad_checksums,
                self.connections_started,
                self.connections_seen,
                self.udp_packets_seen,
                self.mptcp_packets_seen,
                self.mptcp_capable,
                self.mptcp_join,
                self.mptcp_data,
                self.mptcp_add,
                self.bytes_processed as f64 / (BYTES_TO_GBPS * diff_float),
        );

        self.bytes_processed = 0;
        self.total_packets = 0;
        self.ipv4_packets = 0;
        self.ipv6_packets = 0;
        self.tcp_packets_seen = 0;
        self.bad_checksums = 0;
        self.connections_started = 0;
        self.connections_seen = 0;

        self.udp_packets_seen = 0;

        self.mptcp_packets_seen = 0;
        self.mptcp_capable = 0;
        self.mptcp_join = 0;
        self.mptcp_data = 0;
        self.mptcp_add = 0;
    }

    pub fn handle_quic_result(&mut self, res: QuicParseResult) {
        self.quic_packets += 1;
        match res {
            QuicParseResult::ParsedVersionNegotiation => self.quic_version_negotiation += 1,
            QuicParseResult::ParsedHandshake => self.quic_handshakes += 1,
            QuicParseResult::ParsedInit => self.quic_inits += 1,
            QuicParseResult::ParsedZeroRTT => self.quic_zero_rtts += 1,
            QuicParseResult::ParsedRetry => self.quic_retries += 1,
            QuicParseResult::ParsedShortHeader => self.quic_short_headers += 1,
        }
    }

    pub fn handle_quic_error(&mut self, err: QuicParseError) {
        self.quic_errors += 1;
        match err {
            QuicParseError::ClientAttemptedVersionNegotiation => self.quic_client_attempted_version_negotiation += 1,
            QuicParseError::UnknownHeaderType => self.quic_unknown_header += 1,
            QuicParseError::UnknownPacketType => self.quic_unknown_packet += 1,
            QuicParseError::ShortVersionNegotiationPacket => self.quic_short_version_negotiation += 1,
            QuicParseError::ShortRetryPacket => self.quic_short_retry += 1,
            QuicParseError::ShortInitPacket => self.quic_short_init += 1,
            QuicParseError::ShortLongHeader => self.quic_short_long_header += 1,
            QuicParseError::ShortShortHeader => self.quic_short_short_header += 1,
            QuicParseError::InvalidVersionLength => self.quic_invalid_version_length += 1,
            QuicParseError::ShortZeroRttPacket => self.quic_short_zero_rtt += 1,
            QuicParseError::ShortHandshakePacket => self.quic_short_handshake += 1,
        }
    }
}
