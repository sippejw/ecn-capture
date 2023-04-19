pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::{collections::{HashMap, HashSet}, mem};

use crate::{common::Flow, quic::QuicConn};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub flows: HashMap<Flow, i64>,
    pub quic_fps_new: HashMap<i64, QuicConn>,
    quic_fps_flushed: HashSet<i64>,
    pub quic_measurements: HashMap<(i64, i32), i32>,
    pub tls_measurements: HashMap<(i64, i32), i32>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            flows: HashMap::new(),
            quic_fps_new: HashMap::new(),
            quic_fps_flushed: HashSet::new(),
            quic_measurements: HashMap::new(),
            tls_measurements: HashMap::new(),
        }
    }

    pub fn add_flow(&mut self, flow: &Flow) {
        let curr_time = time::now().to_timespec().sec;
        match self.flows.remove(flow) {
            Some(_) => {
                self.flows.insert(*flow, curr_time);
            }
            None => {
                self.flows.insert(*flow, curr_time);
            }
        }
    }

    pub fn add_quic_fingerprint(&mut self, fp: i64, quic_conn: QuicConn) {
        if !self.quic_fps_flushed.contains(&fp) {
            self.quic_fps_new.insert(fp, quic_conn);
        }
    }

    pub fn add_tls_measurement(&mut self, fp: i64, ts: i32) {
        let key = (fp, ts);
        let counter = self.tls_measurements.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn add_quic_measurement(&mut self, fp: i64, ts: i32) {
        let key = (fp, ts);
        let counter = self.quic_measurements.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn flush_fingerprints(&mut self) -> HashMap<i64, QuicConn> {
        self.last_flush = time::now();
        for (fp_id, _) in self.quic_fps_new.iter() {
            self.quic_fps_flushed.insert(*fp_id);
        }
        mem::replace(&mut self.quic_fps_new, HashMap::new())
    }

    // returns cached HashMap of measurements, empties it in object
    pub fn flush_quic_measurements(&mut self) -> HashMap<(i64, i32), i32> {
        self.last_flush = time::now();
        mem::replace(&mut self.quic_measurements, HashMap::new())
    }

    pub fn flush_tls_measurements(&mut self) -> HashMap<(i64, i32), i32> {
        self.last_flush = time::now();
        mem::replace(&mut self.tls_measurements, HashMap::new())
    }
}