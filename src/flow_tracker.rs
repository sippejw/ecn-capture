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
use rand::prelude::ThreadRng;
use std::net::{IpAddr};
use log::{error, info};
use maxminddb::Reader;
use std::{thread};
use postgres::{Client, NoTls};
use rand::Rng;
use std::io::Write;
use std::fs::OpenOptions;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::stats_tracker::{StatsTracker};
use crate::common::{TimedFlow, Flow};
use crate::quic::{QuicConn, QuicParseError};

pub struct FlowTracker {
    flow_timeout: Duration,
    dsn: Option<String>,
    cache: MeasurementCache,
    pub stats: StatsTracker,
    tracked_quic_conns: HashSet<Flow>,
    stale_quic_drops: VecDeque<TimedFlow>,
    rand: ThreadRng,
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
            rand: rand::thread_rng(),
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
                            ipv4_pkt.get_ecn(),
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
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, udp_pkt: &UdpPacket, ecn: u8) {
        self.stats.udp_packets_seen += 1;
        let flow = Flow::new_udp(&source, &destination, &udp_pkt);
        if udp_pkt.payload().len() == 0 {
            return;
        }
        match (udp_pkt.get_destination(), udp_pkt.get_source()) {
            (443, _) => self.handle_quic_record(true, source, destination, udp_pkt.payload(), &flow),
            (_, 443) => self.handle_quic_record(false, source, destination, udp_pkt.payload(), &flow.reversed_clone()),
            (_, _) => {},
        }
        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    pub fn handle_quic_record(&mut self, is_client: bool, source: IpAddr, _destination: IpAddr, record: &[u8], flow: &Flow) {
        let conn;
        if self.tracked_quic_conns.contains(flow) {
            conn = self.cache.quic_conns_new.get_mut(flow).unwrap();
        } else {
            self.begin_tracking_quic_conn(flow);
            self.cache.add_quic_conn(flow, QuicConn::new_conn(source.is_ipv4() as u8, 443).unwrap());
            if let Some(c) = self.cache.quic_conns_new.get_mut(flow) {
                conn = c;
            } else {
                return
            }
        }
        let result = conn.parse_header(record, is_client);
        match result {
            Ok(res) => {
                self.stats.handle_quic_result(res);
            },
            Err(e) => {
                self.stats.handle_quic_error(e);
            },
        }
    }

    pub fn flush_to_db(&mut self) {
        let quic_ecn_cache = self.cache.flush_quic_conns();

        if self.dsn != None {
            let tcp_dsn = self.dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();

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
