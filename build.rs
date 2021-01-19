use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

fn prepare_vmlinux() {
    let mut vmlinux = File::create(PathBuf::from("src/bpf/vmlinux.h")).unwrap();

    let output = Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c")
        .output()
        .unwrap();

    vmlinux.write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
}

fn main() {
    prepare_vmlinux();
}
