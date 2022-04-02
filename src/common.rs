use std::net::Ipv4Addr;
use std::hash::{Hash, Hasher};
use std::time::{Instant};

use pnet::packet::tcp::TcpPacket;

#[derive(Copy, Clone)]
pub struct Flow {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Flow {
    pub fn new(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, tcp_pkt: &TcpPacket) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: tcp_pkt.get_source(),
            dst_port: tcp_pkt.get_destination(),
        }
    }

    pub fn reversed_clone(&self) -> Flow {
        Flow{src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

impl PartialEq for Flow {
    fn eq(&self, other: &Flow) -> bool {
        (self.src_ip == other.src_ip && self.dst_ip == other.dst_ip && self.src_port == other.src_port && self.dst_port == other.dst_port) ||
        (self.src_ip == other.dst_ip && self.dst_ip == other.src_ip && self.src_port == other.dst_port && self.dst_port == other.src_port)
    }
}

impl Eq for Flow {}

impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
    }
}

pub struct TimedFlow {
    pub event_time: Instant,
    pub flow: Flow,
}

pub fn u8array_to_u32_be(oct: [u8; 4]) -> u32 {
    (oct[0] as u32) << 24 | (oct[1] as u32) << 16 | (oct[2] as u32) << 8 | (oct[3] as u32)
}