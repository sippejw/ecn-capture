pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::collections::{HashMap, HashSet};

use crate::{ecn_structs::{TCP_ECN, UDP_ECN}, common::Flow};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub tcp_measurements_new: HashMap<Flow, TCP_ECN>,
    tcp_measurements_flushed: HashSet<Flow>,
    pub udp_measurements_new: HashMap<Flow, UDP_ECN>,
    udp_measurements_flushed: HashSet<Flow>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            tcp_measurements_new: HashMap::new(),
            tcp_measurements_flushed: HashSet::new(),
            udp_measurements_new: HashMap::new(),
            udp_measurements_flushed: HashSet::new(),
        }
    }

    pub fn add_tcp_measurement(&mut self, flow: &Flow, ecn: TCP_ECN) {
        if !self.tcp_measurements_flushed.contains(&flow) {
            self.tcp_measurements_new.insert(*flow, ecn);
        }
    }

    pub fn add_udp_measurement(&mut self, flow: &Flow, ecn: UDP_ECN) {
        if !self.udp_measurements_flushed.contains(&flow) {
            self.udp_measurements_new.insert(*flow, ecn);
        }
    }

    pub fn flush_tcp_measurements(&mut self) -> HashMap<Flow, TCP_ECN> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, TCP_ECN>::new();
        let mut stale_measurement_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, ecn) in self.tcp_measurements_new.iter_mut() {
            if ecn.client_fin != 0 || ecn.client_rst != 0 || ecn.server_fin != 0 || ecn.server_rst != 0 {
                self.tcp_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            } else if curr_time - ecn.last_updated > TCP_CONNECTION_TIMEOUT {
                ecn.stale = 1;
                self.tcp_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            }
        }
        for flow in stale_measurement_flows {
            measurements_ready.insert(flow, self.tcp_measurements_new.remove(&flow).unwrap());
        }
        return measurements_ready
    }

    pub fn flush_udp_measurements(&mut self) -> HashMap<Flow, UDP_ECN> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, UDP_ECN>::new();
        let mut stale_measurement_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, ecn) in self.udp_measurements_new.iter_mut() {
            if curr_time - ecn.last_updated > UDP_CONNECTION_TIMEOUT {
                self.tcp_measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            }
        }
        for flow in stale_measurement_flows {
            measurements_ready.insert(flow, self.udp_measurements_new.remove(&flow).unwrap());
        }
        return measurements_ready
    }
}