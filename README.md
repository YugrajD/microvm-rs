# microvm-rs

A minimal, lightweight virtual machine monitor (VMM) built in Rust using Linux KVM. Designed for fast, secure boot of Linux guests in cloud-native environments.

## What is microvm-rs?

microvm-rs is a from-scratch hypervisor that interfaces directly with the Linux KVM API to create and run virtual machines. It prioritizes simplicity, speed, and a minimal attack surface — making it suitable for serverless, container-adjacent, and edge computing workloads.

## Planned Features

- **Linux guest boot** — Boot a minimal Linux kernel with initrd
- **Serial console** — Basic I/O for guest interaction and debugging
- **virtio devices** — virtio-net, virtio-blk for networking and storage
- **AI-powered CI/CD tooling** — Intelligent build and test automation

## Getting Started

### Requirements

- Linux host with KVM support (`/dev/kvm` must exist)
- Rust toolchain (stable)
- User must be in the `kvm` group

### Quick Start

```bash
# Verify KVM is available
ls /dev/kvm

# Clone and build
git clone https://github.com/yourusername/microvm-rs.git
cd microvm-rs
cargo build --release

# Run (requires KVM access)
cargo run
```

## Project Status

| Component | Status |
|-----------|--------|
| Open `/dev/kvm` | ✅ Done |
| Verify KVM API | ✅ Done |
| Create VM | 🔲 Planned |
| Create vCPU | 🔲 Planned |
| Setup guest memory | 🔲 Planned |
| Load kernel | 🔲 Planned |
| Boot guest | 🔲 Planned |
| Serial console | 🔲 Planned |
| virtio-net | 🔲 Planned |
| virtio-blk | 🔲 Planned |

## License

MIT

---

*microvm-rs is in early development. APIs and features will change.*
