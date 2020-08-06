// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use bcc::perf_event::{Event, HardwareEvent};
use bcc::BccError;
use bcc::{PerfEvent, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{ptr, thread, time};

// Both consants are arbitrary
const DEFAULT_SAMPLE_FREQ: u64 = 49; // Hertz
const DEFAULT_DURATION: u64 = 10; // Seconds

#[repr(C)]
struct key_t {
    cpu: u32,
    pid: u32,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("cpi")
        .arg(
            Arg::with_name("sample_frequency")
                .long("frequency")
                .short("F")
                .help("Sample frequency, Hertz")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sample_period")
                .long("sample_period")
                .short("P")
                .help("Sample period, every P events")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .help("How long to run this trace for (in seconds)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("percpu")
                .long("percpu")
                .help("Display context switches per cpu")
                .takes_value(false),
        )
        .get_matches();

    let mut sample_frequency: Option<u64> = matches
        .value_of("sample_frequency")
        .map(|v| v.parse().expect("Invalid sample frequency"));

    let sample_period: Option<u64> = matches
        .value_of("sample_period")
        .map(|v| v.parse().expect("Invalid sample period"));

    if sample_frequency.is_none() && sample_period.is_none() {
        sample_frequency = Some(DEFAULT_SAMPLE_FREQ);
    }

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    let mut code = include_str!("cpi.c").to_string();
    if matches.is_present("percpu") {
        code = format!("{}\n{}", "#define PERCPU", code);
    }

    let mut bpf = BPF::new(&code)?;
    PerfEvent::new()
        .handler("cnt_cycles")
        .event(Event::Hardware(HardwareEvent::RefCpuCycles))
        .sample_period(sample_period)
        .sample_frequency(sample_frequency)
        .attach(&mut bpf)?;
    PerfEvent::new()
        .handler("cnt_instr")
        .event(Event::Hardware(HardwareEvent::Instructions))
        .sample_period(sample_period)
        .sample_frequency(sample_frequency)
        .attach(&mut bpf)?;

    println!("Running for {} seconds", duration);

    let mut elapsed = 0;
    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(1, 0));

        if elapsed == duration {
            break;
        }
        elapsed += 1;
    }

    let mut cycle_table = bpf.table("cycle_cnt");
    let mut instr_table = bpf.table("instr_cnt");

    let mut total_cycles = 0;
    let mut total_instr = 0;
    if matches.is_present("percpu") {
        let cycles_map = to_map_struct(&mut cycle_table);
        let instr_map = to_map_struct(&mut instr_table);

        println!("{:<-8} {:<-4} {:>12} {:>12} {:>8}", "PID", "CPU", "CYCLES", "INSTR", "CPI");
        for (key, value) in instr_map.iter() {
            if *value == 0 {
                continue;
            }

            let cycles = cycles_map.get(&key).unwrap_or(&0);
            let cpi = *cycles as f32 / *value as f32;

            total_instr += *value;

            println!("{:<-8} {:<-4} {:>12} {:>12} {:>8}", key.0, key.1, cycles, value, cpi);
        }
    } else {
        let cycles_map = to_map(&mut cycle_table);
        let instr_map = to_map(&mut instr_table);

        println!("{:<-8} {:>12} {:>12} {:>8}", "PID",  "CYCLES", "INSTR", "CPI");
        for (key, value) in instr_map.iter() {
            if *value == 0 {
                continue;
            }

            let cycles = cycles_map.get(&key).unwrap_or(&0);
            let cpi = *cycles as f32 / *value as f32;

            total_instr += *value;

            println!("{:<-8} {:>12} {:>12} {:>8}", key, cycles, value, cpi);
        }
    }

    // In case some cycle don't have an intruction entry
    for entry in cycle_table.iter() {
        let value = parse_u64(entry.value);
        total_cycles += value;
    }

    println!("{:<-12} {:<-12} {:<-12}", "TOTAL_CYCLES", "TOTAL_INSTR", "CPI");
    println!("{:<-12} {:<-12} {:<-12}", total_cycles, total_instr, total_cycles as f32 / total_instr as f32);

    Ok(())
}

fn to_map(table: &mut bcc::table::Table) -> HashMap<u32, u64> {
    let mut map = HashMap::new();

    for entry in table.iter() {
        let key = parse_u32(entry.key);
        let value = parse_u64(entry.value);

        map.insert(key, value);
    }

    map
}

fn to_map_struct(table: &mut bcc::table::Table) -> HashMap<(u32, u32), u64> {
    let mut map = HashMap::new();

    for entry in table.iter() {
        let key = parse_struct(&entry.key);
        let value = parse_u64(entry.value);

        map.insert((key.pid, key.cpu), value);
    }

    map
}

fn parse_u32(x: Vec<u8>) -> u32 {
    let mut v = [0_u8; 4];
    for (i, byte) in v.iter_mut().enumerate() {
        *byte = *x.get(i).unwrap_or(&0);
    }

    u32::from_ne_bytes(v)
}

fn parse_u64(x: Vec<u8>) -> u64 {
    let mut v = [0_u8; 8];
    for (i, byte) in v.iter_mut().enumerate() {
        *byte = *x.get(i).unwrap_or(&0);
    }

    u64::from_ne_bytes(v)
}

fn parse_struct(x: &[u8]) -> key_t {
    unsafe { ptr::read(x.as_ptr() as *const key_t) }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}
