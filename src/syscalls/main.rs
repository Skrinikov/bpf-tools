use bcc::core::BPF;
use bcc::BccError;
use clap::{App, Arg, ArgMatches};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{mem, ptr, thread, time};

mod syscall;

// A tool for reporting syscall count and latency
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/syscount.py

#[repr(C)]
struct data_key_t {
    count: u64,
    total_ns: u64,
}

const MILLISECOND: u64 = 1_000 * MICROSECOND;
const MICROSECOND: u64 = 1_000 * NANOSECOND;    
const NANOSECOND: u64 = 1; 

fn get_code(matches: &ArgMatches) -> String {
    let code = include_str!("bpf.c");
    let code = if matches.is_present("pid") {
        let pid: u32 = matches
            .value_of("pid")
            .unwrap_or("1")
            .parse()
            .expect("Invalid pid");

        format!("#define FILTER_PID {} \n {}", pid, code)
    } else {
        code.to_string()
    };

    let code = if matches.is_present("failures") {
        format!("#define FILTER_FAILED {}", code)
    } else {
        code
    };
    
    let code = if matches.is_present("errorno") {
        let errorno = matches
            .value_of("errorno")
            .unwrap_or("0");

        format!("#define FILTER_ERRNO {} \n {}", errorno, code)
    } else {
        code
    };

    let code = if matches.is_present("latency") {
        format!("#define LATENCY \n {}", code)
    } else {
        code
    };

    code
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("syscalls")
        .about("Summarize number of syscalls and their latencies")
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .value_name("Seconds")
                .help("Integration window duration and period for stats output")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("windows")
                .long("windows")
                .value_name("Count")
                .help("The number of intervals before exit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("milliseconds")
                .long("milliseconds")
                .short("M")
                .help("Display the timestamps in milliseconds")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("microseconds")
                .long("microseconds")
                .short("m")
                .help("Display the timestamps in microseconds")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .help("Trace only the given pid")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("top")
                .long("top")
                .short("t")
                .help("Display the top syscalls by count or latency")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("errorno")
                .long("errorno")
                .short("e")
                .help("Trace only the syscalls that return the given error (numeric or EPERM, ...)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("failures")
                .long("failures")
                .short("x")
                .help("Trace only failed syscalls")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("latency")
                .long("latency")
                .short("L")
                .help("Collect syscall latency")
                .takes_value(false),
        )
        .get_matches();

    let interval: usize = matches
        .value_of("interval")
        .unwrap_or("1")
        .parse()
        .expect("Invalid number of interval");
    
    let windows: Option<usize> = matches
        .value_of("windows")
        .map(|v| v.parse().expect("Invalud argument for windows"));

   
    let code = get_code(&matches);
    let mut bpf = BPF::new(&code)?;
    
    let sys_exit = bpf.load_tracepoint("sys_exit")?;
    bpf.attach_tracepoint("raw_syscalls", "sys_exit", sys_exit)?;

    if matches.is_present("latency") {
        let sys_enter = bpf.load_tracepoint("sys_enter")?;
        bpf.attach_tracepoint("raw_syscalls", "sys_enter", sys_enter)?;
    }

    let mut table = bpf.table("data");
    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));

        if matches.is_present("latency") {
            print_latency(&table, &matches);
        } else {
            print_count(&table, &matches);
        }
        let _ = table.delete_all();

        if let Some(windows) = windows {
            window += 1;
            if window >= windows {
                return Ok(());
            }
        }
        println!();
    }
    Ok(())
}

fn print_latency(table: &bcc::table::Table, matches: &ArgMatches) {
    let mut vals: Vec<(u32, data_key_t)> = vec![];

    for entry in table.iter() {
        let key = parse_u32(entry.key);
        let value = parse_struct(&entry.value);

        vals.push((key, value));
    }
    vals.sort_by(|x, y| y.1.total_ns.cmp(&x.1.total_ns));

    let top: Option<usize> = if matches.is_present("top") {
        let t = matches
            .value_of("top")
            .unwrap_or("0")
            .parse()
            .expect("Invalid top value");
        Some(t)
    } else {
        None
    };

    let (time_str, time_factor) = if matches.is_present("milliseconds") {
        ("time (ms)", MILLISECOND)
    } else if matches.is_present("microseconds") {
        ("time (us)", MICROSECOND)
    } else {
        ("time (ns)", NANOSECOND)
    };

    println!("{:<-22} {:<-6} {:<-16}", "SYSCALL", "COUNT", time_str);
    for (i, value) in vals.iter().enumerate() {
        if top.is_some() && top.unwrap() == i {
            break;
        }
        println!("{:<-22} {:<-6} {:<-16}",
            syscall::syscall_name(value.0).unwrap_or("unknown"), 
            value.1.count, 
            value.1.total_ns / time_factor);
    }
}

fn print_count(table: &bcc::table::Table, matches: &ArgMatches) {
    let mut vals: Vec<(u32, u64)> = vec![];

    for entry in table.iter() {
        let key = parse_u32(entry.key);
        let value = parse_u64(entry.value);

        vals.push((key, value));
    }
    vals.sort_by(|x, y| y.1.cmp(&x.1));

    let top: Option<usize> = if matches.is_present("top") {
        let t = matches
            .value_of("top")
            .unwrap_or("0")
            .parse()
            .expect("Invalid top value");
        Some(t)
    } else {
        None
    };

    println!("{:<-22} {:<-6}", "SYSCALL", "COUNT");
    for (i, value) in vals.iter().enumerate() {
        if top.is_some() && top.unwrap() == i {
            break;
        }
        println!("{:<-22} {:<-6}", 
            syscall::syscall_name(value.0).unwrap_or("unknown"), 
            value.1);
    }
}

fn parse_struct(x: &[u8]) -> data_key_t {
    unsafe { ptr::read(x.as_ptr() as *const data_key_t) }
}

fn parse_u64(x: Vec<u8>) -> u64 {
    let mut v = [0_u8; 8];
    for i in 0..8 {
        v[i] = *x.get(i).unwrap_or(&0);
    }

    unsafe { mem::transmute(v) }
}

fn parse_u32(x: Vec<u8>) -> u32 {
    let mut v = [0_u8; 4];
    for i in 0..4 {
        v[i] = *x.get(i).unwrap_or(&0);
    }

    unsafe { mem::transmute(v) }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            std::process::exit(1);
        }
        _ => {}
    }
}