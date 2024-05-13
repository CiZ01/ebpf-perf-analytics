use bpf::query::MapInfo;
use libbpf_rs as bpf;
use std::ffi::CString;
use std::{
    borrow::Borrow,
    env,
    os::fd::{AsFd, AsRawFd},
};

fn main() {
    // Retrieve command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check if there's exactly one argument
    if args.len() != 2 {
        eprintln!("Usage: {} <integer>", args[0]);
        return;
    }

    let mut percpu_map;
    // Parse the integer argument
    let mut map_iter = bpf::query::MapInfoIter::default();
    while let Some(map) = map_iter.find_map(|s: MapInfo| {
        let name_cstring = CString::new("percpu_output").unwrap();
        if s.name == name_cstring {
            Some(s)
        } else {
            None
        }
    }) {
        percpu_map = map;
        break;
    }

    // Retrieve the map data
    let zero = 0;
    let mut map_data = percpu_map
        .lookup_elem(&mut percpu_map, &zero, )
        .unwrap();

    // Print the map data
    println!("Data: {:?}", map_data);
}
