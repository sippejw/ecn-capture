pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
// pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
// pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::{collections::{HashMap, HashSet}, mem};

use byteorder::{BigEndian, ByteOrder};
use crypto::{sha1::Sha1, digest::Digest};

use crate::{common::{Flow, hash_u64}, quic::QuicConn};

pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub flows: HashMap<Flow, i64>,
    pub quic_fps_new: HashMap<i64, QuicConn>,
    quic_fps_flushed: HashSet<i64>,
    pub super_fps_new: HashMap<i64, (i64, i64, i64)>,
    super_fps_flushed: HashSet<i64>,
    pub quic_measurements: HashMap<(i64, i32), i32>,
    pub tls_measurements: HashMap<(i64, i32), i32>,
    pub qtp_measurements: HashMap<(i64, i32), i32>,
    pub super_measurements: HashMap<(i64, i32), i32>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            flows: HashMap::new(),
            quic_fps_new: HashMap::new(),
            quic_fps_flushed: HashSet::new(),
            super_fps_new: HashMap::new(),
            super_fps_flushed: HashSet::new(),
            quic_measurements: HashMap::new(),
            tls_measurements: HashMap::new(),
            qtp_measurements: HashMap::new(),
            super_measurements: HashMap::new(),
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

    pub fn add_qtp_measurement(&mut self, fp: i64, ts: i32) {
        let key = (fp, ts);
        let counter = self.qtp_measurements.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn add_super_measurement(&mut self, fp: i64, ts: i32) {
        let key = (fp, ts);
        let counter = self.super_measurements.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn add_super_fingerprint(&mut self, quic_fp: i64, tls_fp: i64, qtp_fp: i64) -> i64 {
        let mut hasher = Sha1::new();
        hash_u64(&mut hasher, quic_fp as u64);
        hash_u64(&mut hasher, tls_fp as u64);
        hash_u64(&mut hasher, qtp_fp as u64);
        let mut result = [0; 20];
        hasher.result(&mut result);
        let super_fp = BigEndian::read_u64(&result[0..8]) as i64;
        if !self.super_fps_flushed.contains(&super_fp) {
            self.super_fps_new.insert(super_fp, (quic_fp, tls_fp, qtp_fp));
        }
        return super_fp;
    }

    pub fn flush_quic_fingerprints(&mut self) -> HashMap<i64, QuicConn> {
        self.last_flush = time::now();
        for (fp_id, _) in self.quic_fps_new.iter() {
            self.quic_fps_flushed.insert(*fp_id);
        }
        mem::replace(&mut self.quic_fps_new, HashMap::new())
    }

    pub fn flush_super_fingerprints(&mut self) -> HashMap<i64, (i64, i64, i64)> {
        self.last_flush = time::now();
        for (fp_id, _) in self.super_fps_new.iter() {
            self.super_fps_flushed.insert(*fp_id);
        }
        mem::replace(&mut self.super_fps_new, HashMap::new())
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

    pub fn flush_qtp_measurements(&mut self) -> HashMap<(i64, i32), i32> {
        self.last_flush = time::now();
        mem::replace(&mut self.qtp_measurements, HashMap::new())
    }

    pub fn flush_super_measurements(&mut self) -> HashMap<(i64, i32), i32> {
        self.last_flush = time::now();
        mem::replace(&mut self.super_measurements, HashMap::new())
    }
}