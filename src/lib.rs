mod flow_tracker;
mod cache;
mod common;
mod stats_tracker;
mod ecn_structs;

use libc::{size_t, c_char};
use pnet::packet::{ethernet::{EthernetPacket, EtherTypes}, Packet};

use std::{os::raw::c_void, slice, ffi::CStr, intrinsics::transmute};

use flow_tracker::FlowTracker;

#[repr(C)]
pub struct RustGlobalsStruct
{
    ft: *mut FlowTracker,
}

#[no_mangle]
pub extern "C" fn rust_init(core_id: i8, cores_total: i32, tcp_dsn_ptr: *const c_char, gre_offset: usize) -> RustGlobalsStruct {
    env_logger::init();

    let tcp_dsn_c_str: &CStr = unsafe { CStr::from_ptr(tcp_dsn_ptr) };
    let tcp_dsn_string: Option<String>;
    if tcp_dsn_c_str.to_str().unwrap().eq("") {
        tcp_dsn_string = None;
    } else {
        tcp_dsn_string = Some(tcp_dsn_c_str.to_str().unwrap().to_owned());
    }

    let ft = FlowTracker::new(tcp_dsn_string, core_id, cores_total, gre_offset as usize);
    RustGlobalsStruct { ft: unsafe { transmute(Box::new(ft)) } }
}

#[no_mangle]
pub extern "C" fn rust_process_packet(globals_ptr: *mut RustGlobalsStruct, raw_ethframe: *mut c_void, frame_len: size_t) {
    let globals = unsafe { &mut *globals_ptr };
    let ft = unsafe { &mut *globals.ft };
    let rust_view = unsafe {
        slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len as usize)
    };

    match EthernetPacket::new(&rust_view[ft.gre_offset..]) {
        Some(pkt) => {
            match pkt.get_ethertype() {
                EtherTypes::Vlan => {
                    let payload = pkt.payload();
                    if payload[2] == 0x08 && payload[3] == 0x00 {
                        ft.handle_ipv4_packet(&pkt);
                    }
                }
                EtherTypes::Ipv4 => ft.handle_ipv4_packet(&pkt),
                _ => return,
            }
        }
        None => return,
    };
}

#[no_mangle]
pub extern "C" fn rust_print_avg_stats(globals_ptr: *mut RustGlobalsStruct, current: i64, total: i64) {
    let globals = unsafe { &mut *globals_ptr };
    let ft = unsafe { &mut *globals.ft };

    ft.stats.print_stats(current, total);
}

#[no_mangle]
pub extern "C" fn rust_periodic_cleanup(globals_ptr: *mut RustGlobalsStruct) {
    let globals = unsafe { &mut *globals_ptr };
    let ft = unsafe { &mut *globals.ft };

    ft.cleanup();
}
