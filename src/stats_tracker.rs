use std::ops::Sub;

use log::{warn, info};

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
    pub mptcp_packets_seen: u64,
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
            mptcp_packets_seen: 0,
        }
    }

    pub fn print_stats(&mut self, curr_drops: i64, total_drops: i64) {
        self.print_general_stats(curr_drops, total_drops)
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
        info!("[general stats] drops: {} {} all packets: {} [ipv4: {}, ipv6: {}] tcp packets: {} (bad tcp checksums: {}) connections started: {} / connections seen: {}; udp packets: {} Gbps: {:.4}",
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

        self.last_print = curr_time;
    }
}