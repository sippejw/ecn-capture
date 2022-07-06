mod flow_tracker;
mod common;
mod cache;
mod ecn_structs;
mod quic;
mod crypto;
mod stats_tracker;

extern crate env_logger;
extern crate clap;
extern crate pnet;
extern crate pcap;

use clap::{App, Arg, value_t};
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use log::{info, warn, error};
use std::time::{Duration, Instant};
use pcap::Capture;
use flow_tracker::FlowTracker;

fn main() {
    env_logger::init();

    let cl_args = App::new("ECN Capture")
        .about("Reads from either PCAP or interface for debugging the ECN Capture \
            too. Defaults \nto reading from PCAP and writing to terminal if no \
            input or database \nis specified.")
        .version("1.0")
        .arg(Arg::with_name("pcap")
            .short("p")
            .long("pcap")
            .value_name("FILE")
            .help("PCAP file to open")
            .takes_value(true))
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Interface from which to read live packets")
            .takes_value(true))
        .arg(Arg::with_name("tcp_database")
            .short("d")
            .long("tcp_database")
            .value_name("TCP_DSN_URL")
            .help("Enable writing of TCP connections to database and use provided \
                \ncredentials to connect to postgresql.")
            .takes_value(true))
        .arg(Arg::with_name("gre_offset")
            .short("g")
            .long("gre_offset")
            .value_name("GRE_OFFSET")
            .help("Specifies a parsing offset for packets with GRE"))
        .get_matches();

    let gre_offset = value_t!(cl_args.value_of("gre_offset"), usize).unwrap_or_else(|e| e.exit());
    let pcap_filename = cl_args.value_of("pcap");
    let tcp_dsn = cl_args.value_of("tcp_database").map(str::to_string);

    match cl_args.value_of("interface") {
        Some(interface_name) => {
            let interface_ref_closure = |iface: &NetworkInterface| iface.name == interface_name;

            // Find the network interface with the provided name
            let interfaces = datalink::interfaces();

            match interfaces.into_iter().find(interface_ref_closure) {
                Some(interface) => {
                    run_from_interface(&interface, tcp_dsn, gre_offset);
                },
                None => {
                    warn!("Unknown interface '{}' attempting to read from pcap.\n",
                        interface_name);
                    if let Some(pcap_file) = pcap_filename {
                        info!("Reading from pcap: {}", pcap_file);
                        run_from_pcap(pcap_file, tcp_dsn, gre_offset);
                    } else {
                        error!("No interface or pcap specified");
                        return
                    }
                }
            }
        },
        None => {
            if let Some(pcap_file) = pcap_filename {
                info!("No interface specified, from pcap: {}", pcap_file);
                run_from_pcap(pcap_file, tcp_dsn, gre_offset);
            } else {
                error!("No interface or pcap specified");
                return
            }
        }
    }
}

fn run_from_pcap(pcap_filename: &str, tcp_dsn: Option<String>, gre_offset: usize) {
    match Capture::from_file(pcap_filename) {
        Ok(mut cap) => {
            let mut ft = FlowTracker::new(tcp_dsn, 1, 1, gre_offset);

            while let Ok(cap_pkt) = cap.next() {
                let pnet_pkt = EthernetPacket::new(cap_pkt.data);
                match pnet_pkt {
                    Some(eth_pkt) => {
                        match eth_pkt.get_ethertype() {
                            EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                            EtherTypes::Ipv6 => ft.handle_ipv6_packet(&eth_pkt),
                            _ => warn!("Could not parse packet (EtherType: {})", eth_pkt.get_ethertype()),
                        }
                    }
                    None => {
                        warn!("Could not parse packet");
                    }
                }
            }
            ft.flush_to_db();
        }
        Err(e) => {
            error!("PCAP parse error with file '{}'.", pcap_filename);
            error!("{}", e);
        }
    }
}

fn run_from_interface(interface: &NetworkInterface, tcp_dsn: Option<String>, gre_offset: usize) {
    let mut ft = FlowTracker::new(tcp_dsn, 1, 1, gre_offset);

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            warn!("Unhandled channel type");
            return
        }
        Err(e) => {
            error!("An error occurred when creating the datalink channel: {}", e);
            return
        }
    };

    let cleanup_frequency = Duration::from_secs(1);
    let mut last_cleanup = Instant::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                match EthernetPacket::new(packet) {
                    Some(eth_pkt) => {
                        match eth_pkt.get_ethertype() {
                            EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                            _ => continue,
                        }
                    }
                    None => {
                        warn!("Could not parse packet: {:?}", packet);
                        continue;
                    }
                }
                if last_cleanup.elapsed() >= cleanup_frequency {
                    ft.cleanup();
                    last_cleanup = Instant::now();
                    ft.debug_print();
                }
            }
            Err(e) => {
                error!("An error occured while reading: {:?}", e);
            }
        }
    }
}