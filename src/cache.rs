pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::collections::{HashMap, HashSet};

use crate::{common::Flow, quic::QuicConn};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub quic_conns_new: HashMap<Flow, QuicConn>,
    quic_conns_flushed: HashSet<Flow>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            quic_conns_new: HashMap::new(),
            quic_conns_flushed: HashSet::new(),
        }
    }

    pub fn add_quic_conn(&mut self, flow: &Flow, quic_conn: QuicConn) {
        if !self.quic_conns_flushed.contains(&flow) {
            self.quic_conns_new.insert(*flow, quic_conn);
        }
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