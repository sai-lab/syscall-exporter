use std::str;

use libbpf_rs::PerfBufferBuilder;
use plain::Plain;

mod bpf;
use bpf::*;

#[repr(C)]
#[derive(Default, Debug)]
struct SysExitEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgid: u64,
    pub syscall_nr: u32,
    pub latency: u64,
    pub comm: [u8; 32],
}

unsafe impl Plain for SysExitEvent {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = SysExitEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short or invalid");

    let comm = str::from_utf8(&event.comm).unwrap().trim_end_matches('\0');

    println!(
        "{:8} {:8} {:8} {:8} {: <16} {:16}",
        event.pid,
        event.uid,
        event.cgid,
        event.syscall_nr,
        event.latency as f64 / 1000_000_000.0,
        comm
    )
}

fn handle_lost_event(cpu: i32, count: u64) {
    eprintln!("Lost event (CPU: {}, COUNT: {})", cpu, count)
}

fn main() -> anyhow::Result<()> {
    let mut skel_builder = SyslatencySkelBuilder::default();
    let syslatency_skel = skel_builder.open()?;

    let mut skel = syslatency_skel.load()?;
    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps().sys_exit_events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_event)
        .build()?;

    println!(
        "{:8} {:8} {:8} {:8} {:8} {:8}",
        "PID", "UID", "CGROUP_ID", "SYSCALL", "LATENCY(ns)", "COMMAND"
    );

    loop {
        perf.poll(std::time::Duration::from_millis(100))?;
    }
}
