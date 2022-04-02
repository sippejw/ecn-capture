use pnet::packet::tcp::{TcpFlags};
use maxminddb::geoip2::{Country};

#[derive(Clone)]
pub struct ECN {
    pub start_time: i64,
    pub last_updated: i64,

    server_ip: u32,
    client_ip: u32,

    pub server_port: u16,
    // IP country codes for anon
    pub client_cc: Option<String>,
    pub server_cc: Option<String>,
    // TCP handshake flags
    pub client_ece: u8,
    pub client_cwr: u8,
    pub server_ece: u8,
    // TCP close
    pub client_fin: u8,
    pub client_rst: u8,
    pub server_fin: u8,
    pub server_rst: u8,
    // Closed because connections went stale
    pub stale: u8,
    // Packets from client measurements
    pub client_00: i32,
    pub client_01: i32,
    pub client_10: i32,
    pub client_11: i32,
    // Packets from server measurements
    pub server_00: i32,
    pub server_01: i32,
    pub server_10: i32,
    pub server_11: i32,
}

impl ECN {
    pub fn syn(dst_port: u16, src_ip: u32, dst_ip: u32, src_country: Option<Country>, dst_country: Option<Country>, tcp_flags: u16) -> ECN {
        let curr_time = time::now().to_timespec().sec;
        let mut server_cc: Option<String> = None;
        let mut client_cc: Option<String> = None;
        if let Some(country) = src_country {
            client_cc = Some(country.country.unwrap().iso_code.unwrap().to_string());
        }
        if let Some(country) = dst_country {
            server_cc = Some(country.country.unwrap().iso_code.unwrap().to_string())
        }
        ECN {
            start_time: curr_time,
            last_updated: curr_time,
            server_port: dst_port,
            server_ip: dst_ip,
            client_ip: src_ip,
            server_cc: server_cc,
            client_cc: client_cc,
            client_ece: ((tcp_flags & TcpFlags::ECE) >> 6) as u8,
            client_cwr: ((tcp_flags & TcpFlags::CWR) >> 7) as u8,
            server_ece: 0,
            client_fin: 0,
            client_rst: 0,
            server_fin: 0,
            server_rst: 0,
            stale: 0,
            client_00: 0,
            client_01: 0,
            client_10: 0,
            client_11: 0,
            server_00: 0,
            server_01: 0,
            server_10: 0,
            server_11: 0,
        }
    }

    pub fn syn_ack(&mut self, tcp_flags: u16) {
        self.server_ece = ((tcp_flags & TcpFlags::ECE) >> 6) as u8;
        self.last_updated = time::now().to_timespec().sec;
    }

    pub fn close(&mut self, src_ip: u32, tcp_flags: u16) {
        if src_ip == self.client_ip {
            self.client_fin = ((tcp_flags & TcpFlags::FIN) >> 0) as u8;
            self.client_rst = ((tcp_flags & TcpFlags::RST) >> 2) as u8;
        } else {
            self.server_fin = ((tcp_flags & TcpFlags::FIN) >> 0) as u8;
            self.server_rst = ((tcp_flags & TcpFlags::RST) >> 2) as u8;
        }
    }

    pub fn measure(&mut self, src_ip: u32, ecn: u8) {
        match ecn {
            0b00 => {
                if src_ip == self.client_ip {
                    self.client_00 += 1;
                } else {
                    self.server_00 += 1;
                }
            },
            0b01 => {
                if src_ip == self.client_ip {
                    self.client_01 += 1;
                } else {
                    self.server_01 += 1;
                }
            },
            0b10 => {
                if src_ip == self.client_ip {
                    self.client_10 += 1;
                } else {
                    self.server_10 += 1;
                }
            },
            0b11 => {
                if src_ip == self.client_ip {
                    self.client_11 += 1;
                } else {
                    self.server_11 += 1;
                }
            },
            _ => {}
        }
        self.last_updated = time::now().to_timespec().sec;
    }
}

