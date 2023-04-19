extern crate time;
extern crate postgres;

use std::ops::Sub;
use std::time::{Duration, Instant};
use std::collections::{HashSet, VecDeque};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ip::{IpNextHeaderProtocols};
use std::net::{IpAddr};
use log::info;
use std::{thread};
use postgres::{Client, NoTls};
use std::io::Write;
use std::fs::OpenOptions;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::stats_tracker::{StatsTracker};
use crate::common::{TimedFlow, Flow};
use crate::quic::{QuicConn, QuicParseResult, self};

pub struct FlowTracker {
    flow_timeout: Duration,
    dsn: Option<String>,
    cache: MeasurementCache,
    pub stats: StatsTracker,
    tracked_quic_conns: HashSet<Flow>,
    stale_quic_drops: VecDeque<TimedFlow>,
    pub gre_offset: usize,
}

impl FlowTracker {
    pub fn new(dsn: Option<String>, core_id: i8, total_cores: i32, gre_offset: usize) -> FlowTracker {
        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            dsn: dsn,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            tracked_quic_conns: HashSet::new(),
            stale_quic_drops: VecDeque::with_capacity(65536),
            gre_offset: gre_offset,
        };

        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)
        ));
        ft
    }

    pub fn log_packet(&mut self, contents: &String, file_path: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    pub fn handle_ipv4_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv4_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv4_pkt = match eth_pkt.get_ethertype() {
            EtherTypes::Vlan => Ipv4Packet::new(&eth_pkt.payload()[4..]),
            _ => Ipv4Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv4_pkt) = ipv4_pkt {
            match ipv4_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv4_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V4(ipv4_pkt.get_source()),
                            IpAddr::V4(ipv4_pkt.get_destination()),
                            &udp_pkt,
                        )
                    }
                }
                _ => {}
            }
        }
    }

    pub fn handle_ipv6_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv6_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv6_pkt = match eth_pkt.get_ethertype() {
             EtherTypes::Vlan => Ipv6Packet::new(&eth_pkt.payload()[4..]),
             _ => Ipv6Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv6_pkt) = ipv6_pkt {
            match ipv6_pkt.get_next_header() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv6_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &udp_pkt,
                        )
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, udp_pkt: &UdpPacket) {
        self.stats.udp_packets_seen += 1;
        let flow = Flow::new_udp(&source, &destination, &udp_pkt);
        if udp_pkt.payload().len() == 0 {
            return;
        }
        match (udp_pkt.get_destination(), udp_pkt.get_source()) {
            (443, _) => self.handle_quic_record(true, source, destination, udp_pkt.payload(), &flow),
            (_, _) => {},
        }
        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    pub fn handle_quic_record(&mut self, is_client: bool, source: IpAddr, _destination: IpAddr, record: &[u8], flow: &Flow) {
        let mut measure_conn = true;
        match self.cache.flows.get(flow) {
            Some(last_update) => {
                if time::now().to_timespec().sec - last_update < self.flow_timeout.as_secs() as i64 {
                    measure_conn = false;
                }
                self.cache.add_flow(flow);
            },
            None => self.cache.add_flow(flow),
        }
        if measure_conn {
            let mut conn = QuicConn::new_conn(source.is_ipv4() as u8, 443).unwrap();
            let result = conn.parse_header(record, is_client);
            match result {
                Ok(res) => {
                    match res {
                        QuicParseResult::ParsedInit => {
                            let mut curr_time = time::now();
                            // println!("QuicInit: {{ id: {} {}}}",
                            //     conn.get_fp(), conn);
                            let quic_fp = conn.get_fp() as i64;
                            let tls_fp = conn.tls_fp;
                            self.cache.add_quic_fingerprint(quic_fp, conn);
                            curr_time.tm_nsec = 0; // privacy
                            curr_time.tm_sec = 0;
                            curr_time.tm_min = 0;
                            self.cache.add_quic_measurement(quic_fp, curr_time.to_timespec().sec as i32);
                            if tls_fp != 0 {
                                self.cache.add_tls_measurement(tls_fp, curr_time.to_timespec().sec as i32);
                            }
                        },
                        _ => {},
                    }
                    self.stats.handle_quic_result(res);
                },
                Err(e) => {
                    self.stats.handle_quic_error(e);
                },
            }
        }
    }

    pub fn flush_to_db(&mut self) {
        let quic_fcache = self.cache.flush_fingerprints();
        let quic_mcache = self.cache.flush_quic_measurements();
        let tls_mcache = self.cache.flush_tls_measurements();
        if self.dsn != None {
            let tcp_dsn = self.dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();
                let insert_tls_fingerprint_norm_ext = match thread_db_conn.prepare(
                    "INSERT
                    INTO tls_fingerprints_norm_ext (
                        id,
                        ch_tls_version,
                        cipher_suites,
                        compression_methods,
                        normalized_extensions,
                        named_groups,
                        ec_point_fmt,
                        sig_algs,
                        alpn,
                        key_share,
                        psk_key_exchange_modes,
                        supported_versions,
                        cert_compression_algs,
                        record_size_limit
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    ON CONFLICT (id) DO NOTHING;"
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        println!("Preparing insert_fingerprint_norm_ext failed: {}", e);
                        return;
                    }
                };

                let insert_quic_fingerprint = match thread_db_conn.prepare(
                    "INSERT
                    INTO quic_fingerprints (
                        id,
                        quic_version,
                        client_cid_len,
                        server_cid_len,
                        initial_packet_number,
                        frames,
                        token_length
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (id) DO NOTHING;"
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        println!("Preparing insert_fingerprint_norm_ext failed: {}", e);
                        return;
                    }
                };

                let insert_tls_measurement = match thread_db_conn.prepare(
                    "INSERT
                    INTO tls_measurements_norm_ext (
                        unixtime,
                        id,
                        count
                    )
                    VALUES ($1, $2, $3)
                    ON CONFLICT ON CONSTRAINT tls_measurements_norm_ext_pkey DO UPDATE
                    SET count = tls_measurements_norm_ext.count + $4;"
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        println!("Preparing insert_tls_measurement_norm_ext failed: {}", e);
                        return;
                    }
                };

                let insert_quic_measurement = match thread_db_conn.prepare(
                    "INSERT
                    INTO quic_measurements (
                        unixtime,
                        id,
                        count
                    )
                    VALUES ($1, $2, $3)
                    ON CONFLICT ON CONSTRAINT quic_measurements_pkey DO UPDATE
                    SET count = quic_measurements.count + $4;"
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        println!("Preparing insert_quic_measurement failed: {}", e);
                        return;
                    }
                };

                for (k, count) in quic_mcache {
                    let updated_rows = thread_db_conn.execute(&insert_quic_measurement, &[&(k.1), &(k.0),
                        &(count), &(count)]);
                    if updated_rows.is_err() {
                        println!("Error updating quic measurements: {:?}", updated_rows);
                    }
                }

                for (k, count) in tls_mcache {
                    let updated_rows = thread_db_conn.execute(&insert_tls_measurement, &[&(k.1), &(k.0),
                        &(count), &(count)]);
                    if updated_rows.is_err() {
                        println!("Error updating tls measurements: {:?}", updated_rows);
                    }
                }

                for (quic_fp_id, quic_fp) in quic_fcache {
                    let tls_fp = quic_fp.tls_ch.unwrap();
                    // insert tls fp
                    let mut updated_rows = thread_db_conn.execute(&insert_tls_fingerprint_norm_ext, &[
                        &(quic_fp.tls_fp as i64),
                        &(tls_fp.ch_tls_version as i16),
                        &tls_fp.cipher_suites, &tls_fp.compression_methods, &tls_fp.extensions_norm,
                        &tls_fp.named_groups, &tls_fp.ec_point_fmt, &tls_fp.sig_algs, &tls_fp.alpn,
                        &tls_fp.key_share, &tls_fp.psk_key_exchange_modes, &tls_fp.supported_versions,
                        &tls_fp.cert_compression_algs, &tls_fp.record_size_limit,
                    ]);
                    if updated_rows.is_err() {
                        println!("Error updating tls_fingerprints: {:?}", updated_rows);
                    }

                    //insert quic fp
                    let mut updated_rows = thread_db_conn.execute(&insert_quic_fingerprint, &[
                        &(quic_fp_id as i64),
                        &quic_fp.quic_version,
                        &(quic_fp.client_cid.len() as i16),
                        &(quic_fp.server_cid.len() as i16),
                        &quic_fp.initial_packet_number,
                        &quic_fp.frames,
                        &(quic_fp.token_length as i16),
                    ]);
                    if updated_rows.is_err() {
                        println!("Error updating quic_fingerprints: {:?}", updated_rows);
                    }
                }
                let inserter_thread_end = time::now();
                info!("Updating TCP DB took {:?} ns in separate thread",
                         inserter_thread_end.sub(inserter_thread_start).num_nanoseconds());
            });
        }
    }

    fn begin_tracking_quic_conn(&mut self, flow: &Flow) {
        self.stale_quic_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_quic_conns.insert(*flow);
    }

    pub fn cleanup(&mut self) {
        while !self.stale_quic_drops.is_empty() &&
            self.stale_quic_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_quic_drops.pop_front().unwrap();
            self.tracked_quic_conns.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        self.stats.print_stats(0, 0);
    }
}
