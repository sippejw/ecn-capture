pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;

use std::collections::{HashMap, HashSet};

use crate::{ecn_structs::ECN, common::Flow};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub measurements_new: HashMap<Flow, ECN>,
    measurements_flushed: HashSet<Flow>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            measurements_new: HashMap::new(),
            measurements_flushed: HashSet::new(),
        }
    }

    pub fn add_measurement(&mut self, flow: &Flow, ecn: ECN) {
        if !self.measurements_flushed.contains(&flow) {
            self.measurements_new.insert(*flow, ecn);
        }
    }

    pub fn flush_measurements(&mut self) -> HashMap<Flow, ECN> {
        self.last_flush = time::now();
        let mut measurements_ready = HashMap::<Flow, ECN>::new();
        let mut stale_measurement_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, ecn) in self.measurements_new.iter_mut() {
            if ecn.client_fin != 0 || ecn.client_rst != 0 || ecn.server_fin != 0 || ecn.server_rst != 0 {
                self.measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            } else if curr_time - ecn.last_updated > TCP_CONNECTION_TIMEOUT {
                ecn.stale = 1;
                self.measurements_flushed.insert(*flow);
                stale_measurement_flows.insert(*flow);
            }
        }
        for flow in stale_measurement_flows {
            measurements_ready.insert(flow, self.measurements_new.remove(&flow).unwrap());
        }
        return measurements_ready
    }
}