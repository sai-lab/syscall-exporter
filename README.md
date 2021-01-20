## Environment

- Ubuntu 20.10
- Linux 5.4 (BTF support)
- Rust
- cargo-libbpf

## Running on Ubuntu 20.10

```
git clone git@github.com:sai-lab/syscall-latency-exporter.git
cd syscall-latency-exporter
cargo libbpf make
./target/debug/syscall-latency-exporter
```


## Generate `vmlinux.h`

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```
