use std::net::{IpAddr};
use std::hash::{Hash, Hasher};
use std::time::{Instant};
use ::crypto::digest::Digest;
use pnet::packet::udp::UdpPacket;

#[derive(Copy, Clone)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Flow {
    pub fn new_udp(src_ip: &IpAddr, dst_ip: &IpAddr, udp_pkt: &UdpPacket) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: udp_pkt.get_source(),
            dst_port: udp_pkt.get_destination(),
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

pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u8_to_u32_be(first_byte: u8, second_byte: u8, third_byte: u8, fourth_byte: u8) -> u32 {
    (first_byte as u32) << 24 | (second_byte as u32) << 16 | (third_byte as u32) << 8 | (fourth_byte as u32)
}

pub fn hash_u32<D: Digest>(h: &mut D, n: u32) {
    h.input(&[((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8]);
}

// Doesn't check that a.len() % 2 == 1.
pub fn vec_u8_to_vec_u16_be(a: &Vec<u8>) -> Vec<u16> {
    let mut result = Vec::with_capacity(a.len() / 2);
    for i in 0..result.capacity() {
        result.push(u8_to_u16_be(a[2 * i], a[2 * i + 1]));
    }
    result
}

pub fn vec_u16_to_vec_u8_be(a: &Vec<u16>) -> Vec<u8> {
    let mut result = Vec::with_capacity(a.len() * 2);
    for i in a {
        result.append(&mut u16_to_u8_be(*i));
    }
    result
}

pub fn u16_to_u8_be(double: u16) -> Vec<u8> {
    let mut res = Vec::new();
    res.push((double >> 8) as u8);
    res.push((double & 0x00ff) as u8);
    res
}