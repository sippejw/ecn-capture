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
use pnet::packet::tcp::{TcpPacket, TcpFlags, ipv4_checksum, ipv6_checksum};
use rand::prelude::ThreadRng;
use std::net::{IpAddr};
use log::{error, info};
use maxminddb::Reader;
use std::{thread};
use postgres::{Client, NoTls};
use rand::Rng;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::stats_tracker::{StatsTracker};
use crate::common::{TimedFlow, Flow};
use crate::ecn_structs::{TCP_ECN, UDP_ECN};

pub struct FlowTracker {
    flow_timeout: Duration,
    tcp_dsn: Option<String>,
    cache: MeasurementCache,
    pub stats: StatsTracker,
    country: Reader<Vec<u8>>,
    tracked_tcp_flows: HashSet<Flow>,
    stale_tcp_drops: VecDeque<TimedFlow>,
    tracked_udp_flows: HashSet<Flow>,
    stale_udp_drops: VecDeque<TimedFlow>,
    rand: ThreadRng,
    pub gre_offset: usize,
}

impl FlowTracker {
    pub fn new(tcp_dsn: Option<String>, core_id: i8, total_cores: i32, gre_offset: usize) -> FlowTracker {
        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tcp_dsn: tcp_dsn,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            country:  Reader::open_readfile("data/GeoLite2-Country.mmdb").unwrap(),
            tracked_tcp_flows: HashSet::new(),
            stale_tcp_drops: VecDeque::with_capacity(65536),
            tracked_udp_flows: HashSet::new(),
            stale_udp_drops: VecDeque::with_capacity(65536),
            rand: rand::thread_rng(),
            gre_offset: gre_offset,
        };

        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)
        ));
        ft
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
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(&ipv4_pkt.payload()) {
                        if ipv4_checksum(&tcp_pkt, &ipv4_pkt.get_source(), &ipv4_pkt.get_destination()) == tcp_pkt.get_checksum() {
                            self.handle_tcp_packet(
                                IpAddr::V4(ipv4_pkt.get_source()),
                                IpAddr::V4(ipv4_pkt.get_destination()),
                                &tcp_pkt,
                                ipv4_pkt.get_ecn(),
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                },
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
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(ipv6_pkt.payload()) {
                        if ipv6_checksum(&tcp_pkt, &ipv6_pkt.get_source(), &ipv6_pkt.get_destination()) ==
                            tcp_pkt.get_checksum() {
                            self.handle_tcp_packet(
                                IpAddr::V6(ipv6_pkt.get_source()),
                                IpAddr::V6(ipv6_pkt.get_destination()),
                                &tcp_pkt,
                                ipv6_pkt.get_traffic_class() & 0b0000011,
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, udp_pkt: &UdpPacket, ecn: u8) {
        self.stats.udp_packets_seen += 1;
        let flow = Flow::new_udp(&source, &destination, &udp_pkt);
        if self.tracked_udp_flows.contains(&flow) {
            let conn = self.cache.tcp_measurements_new.get_mut(&flow);
            if let Some(measurement) = conn{
                measurement.measure(source, ecn);
            }
        } else if self.tracked_udp_flows.contains(&flow.reversed_clone()) {
            let conn = self.cache.tcp_measurements_new.get_mut(&flow.reversed_clone());
            if let Some(measurement) = conn {
                measurement.measure(source, ecn);
            }
        } else {
            self.begin_tracking_udp_flow(&flow);

            let src_cc = self.country.lookup(source).unwrap_or(None);
            let dst_cc = self.country.lookup(destination).unwrap_or(None);
            let mut measurement = UDP_ECN::new(udp_pkt.get_destination(), source, destination, src_cc, dst_cc);
            measurement.measure(source, ecn);
            self.cache.add_udp_measurement(&flow, measurement);
        }
    }

    pub fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket, ecn: u8) {
        self.stats.tcp_packets_seen += 1;
        let flow = Flow::new_tcp(&source, &destination, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            self.stats.connections_seen += 1;
            if self.rand.gen_range(0..10) > -1 {
                self.stats.connections_started += 1;
                self.begin_tracking_tcp_flow(&flow, tcp_pkt.packet().to_vec());
                let src_cc = self.country.lookup(source).unwrap_or(None);
                let dst_cc = self.country.lookup(destination).unwrap_or(None);
                let measurement = TCP_ECN::syn(tcp_pkt.get_destination(), source, destination, src_cc, dst_cc, tcp_flags);
                self.cache.add_tcp_measurement(&flow, measurement);
            }
            return
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) != 0 {
            if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                let conn = self.cache.tcp_measurements_new.get_mut(&flow.reversed_clone());
                if let Some(ecn) = conn{
                    ecn.syn_ack(tcp_flags);
                }
            }
            return
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            if self.tracked_tcp_flows.contains(&flow) {
                let conn = self.cache.tcp_measurements_new.get_mut(&flow);
                if let Some(ecn) = conn{
                    ecn.close(source, tcp_flags);
                }
            } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                let conn = self.cache.tcp_measurements_new.get_mut(&flow.reversed_clone());
                if let Some(ecn) = conn {
                    ecn.close(source, tcp_flags);
                }
            }
            self.tracked_tcp_flows.remove(&flow);
            self.stats.connections_closed += 1;
            return
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }
        if self.tracked_tcp_flows.contains(&flow) {
            let conn = self.cache.tcp_measurements_new.get_mut(&flow);
            if let Some(measurement) = conn{
                measurement.measure(source, ecn);
            } 
        } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
            let conn = self.cache.tcp_measurements_new.get_mut(&flow.reversed_clone());
            if let Some(measurement) = conn {
                measurement.measure(source, ecn);
            }
        }
        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    pub fn flush_to_db(&mut self) {
        let tcp_ecn_cache = self.cache.flush_tcp_measurements();
        let udp_ecn_cache = self.cache.flush_udp_measurements();

        if self.tcp_dsn != None {
            let tcp_dsn = self.tcp_dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();

                let insert_tcp_measurement = match thread_db_conn.prepare(
                    "INSERT
                    INTO ecn_measurements (
                        start_time,
                        last_updated,
                        server_port,
                        is_ipv4,
                        client_cc,
                        server_cc,
                        client_ece,
                        client_cwr,
                        server_ece,
                        client_fin,
                        client_rst,
                        server_fin,
                        server_rst,
                        stale,
                        client_00,
                        client_01,
                        client_10,
                        client_11,
                        server_00,
                        server_01,
                        server_10,
                        server_11)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22);"
                )
                {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        error!("Preparing insert_measurement failed: {}", e);
                        return
                    }
                };
                for (_k, ecn) in tcp_ecn_cache {
                    let updated_rows = thread_db_conn.execute(&insert_tcp_measurement, &[&(ecn.start_time),
                        &(ecn.last_updated), &(ecn.server_port as i16), &(ecn.is_ipv4 as i16), &(ecn.client_cc), &(ecn.server_cc),
                        &(ecn.client_ece as i16), &(ecn.client_cwr as i16), &(ecn.server_ece as i16), &(ecn.client_fin as i16),
                        &(ecn.client_rst as i16), &(ecn.server_fin as i16), &(ecn.server_rst as i16), &(ecn.stale as i16), &(ecn.client_00),
                        &(ecn.client_01), &(ecn.client_10), &(ecn.client_11), &(ecn.server_00), &(ecn.server_01),
                        &(ecn.server_10), &(ecn.server_11)]);
                    if updated_rows.is_err() {
                        error!("Error updating TCP ECN measurements: {:?}", updated_rows);
                    }
                }

                let insert_udp_measurement = match thread_db_conn.prepare(
                    "INSERT
                    INTO udp_ecn_measurements (
                        start_time,
                        last_updated,
                        server_port,
                        is_ipv4,
                        client_cc,
                        server_cc,
                        client_00,
                        client_01,
                        client_10,
                        client_11,
                        server_00,
                        server_01,
                        server_10,
                        server_11)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);"
                )
                {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        error!("Preparing insert_measurement failed: {}", e);
                        return
                    }
                };
                for (_k, ecn) in udp_ecn_cache {
                    let updated_rows = thread_db_conn.execute(&insert_udp_measurement, &[&(ecn.start_time),
                        &(ecn.last_updated), &(ecn.server_port as i16), &(ecn.is_ipv4 as i16), &(ecn.client_cc), &(ecn.server_cc), &(ecn.client_00),
                        &(ecn.client_01), &(ecn.client_10), &(ecn.client_11), &(ecn.server_00), &(ecn.server_01),
                        &(ecn.server_10), &(ecn.server_11)]);
                    if updated_rows.is_err() {
                        error!("Error updating UDP ECN measurements: {:?}", updated_rows);
                    }
                }

                let inserter_thread_end = time::now();
                info!("Updating TCP DB took {:?} ns in separate thread",
                         inserter_thread_end.sub(inserter_thread_start).num_nanoseconds());
            });
        }
    }

    fn begin_tracking_tcp_flow(&mut self, flow: &Flow, _syn_data: Vec<u8>) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_tcp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_tcp_flows.insert(*flow);
    }

    fn begin_tracking_udp_flow(&mut self, flow: &Flow) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_udp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_udp_flows.insert(*flow);
    }

    pub fn cleanup(&mut self) {
        while !self.stale_tcp_drops.is_empty() &&
            self.stale_tcp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_tcp_drops.pop_front().unwrap();
            self.tracked_tcp_flows.remove(&cur.flow);
        }
        while !self.stale_udp_drops.is_empty() &&
            self.stale_udp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_udp_drops.pop_front().unwrap();
            self.tracked_udp_flows.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        info!("tracked_tcp_flows: {} stale__tcp_drops: {}", self.tracked_tcp_flows.len(), self.stale_tcp_drops.len());
        info!("tracked_udp_flows: {} stale__udo_drops: {}", self.tracked_udp_flows.len(), self.stale_udp_drops.len());
        self.stats.print_stats(0, 0);
    }
}
