pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::collections::{HashMap, HashSet};

use crate::{ecn_structs::{TcpEcn, UdpEcn}, common::Flow, quic::QuicConn};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub tcp_ecn_measurements_new: HashMap<Flow, TcpEcn>,
    tcp_ecn_measurements_flushed: HashSet<Flow>,
    pub udp_ecn_measurements_new: HashMap<Flow, UdpEcn>,
    udp_ecn_measurements_flushed: HashSet<Flow>,
    pub quic_conns_new: HashMap<Flow, QuicConn>,
    quic_conns_flushed: HashSet<Flow>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            tcp_ecn_measurements_new: HashMap::new(),
            tcp_ecn_measurements_flushed: HashSet::new(),
            udp_ecn_measurements_new: HashMap::new(),
            udp_ecn_measurements_flushed: HashSet::new(),
            quic_conns_new: HashMap::new(),
            quic_conns_flushed: HashSet::new(),
        }
    }

    pub fn add_tcp_ecn_measurement(&mut self, flow: &Flow, ecn: TcpEcn) {
        if !self.tcp_ecn_measurements_flushed.contains(&flow) {
            self.tcp_ecn_measurements_new.insert(*flow, ecn);
        }
    }

    pub fn add_udp_ecn_measurement(&mut self, flow: &Flow, ecn: UdpEcn) {
        if !self.udp_ecn_measurements_flushed.contains(&flow) {
            self.udp_ecn_measurements_new.insert(*flow, ecn);
        }
    }

    pub fn add_quic_conn(&mut self, flow: &Flow, quic_conn: QuicConn) {
        if !self.quic_conns_flushed.contains(&flow) {
            self.quic_conns_new.insert(*flow, quic_conn);
        }
    }

    pub fn flush_tcp_ecn_measurements(&mut self) -> HashMap<Flow, TcpEcn> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, TcpEcn>::new();
        let mut stale_measurement_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, ecn) in self.tcp_ecn_measurements_new.iter_mut() {
            if ecn.client_fin != 0 || ecn.client_rst != 0 || ecn.server_fin != 0 || ecn.server_rst != 0 {
                self.tcp_ecn_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            } else if curr_time - ecn.last_updated > TCP_CONNECTION_TIMEOUT {
                ecn.stale = 1;
                self.tcp_ecn_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            }
        }
        for flow in stale_measurement_flows {
            measurements_ready.insert(flow, self.tcp_ecn_measurements_new.remove(&flow).unwrap());
        }
        return measurements_ready
    }

    pub fn flush_udp_ecn_measurements(&mut self) -> HashMap<Flow, UdpEcn> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, UdpEcn>::new();
        let mut stale_measurement_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, ecn) in self.udp_ecn_measurements_new.iter_mut() {
            if curr_time - ecn.last_updated > UDP_CONNECTION_TIMEOUT {
                self.udp_ecn_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            }
        }
        for flow in stale_measurement_flows {
            measurements_ready.insert(flow, self.udp_ecn_measurements_new.remove(&flow).unwrap());
        }
        return measurements_ready
    }

    pub fn flush_quic_conns(&mut self) -> HashMap<Flow, QuicConn> {
        self.last_flush = time::now();
        let mut conns_ready = HashMap::<Flow, QuicConn>::new();
        let mut stale_conn_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, conn) in self.quic_conns_new.iter_mut() {
            if curr_time - conn.last_updated > UDP_CONNECTION_TIMEOUT {
                self.quic_conns_flushed.insert(*flow);
                stale_conn_flows.insert(*flow);
            }
        }
        for flow in stale_conn_flows {
            conns_ready.insert(flow, self.quic_conns_new.remove(&flow).unwrap());
        }
        return conns_ready;
    }
}