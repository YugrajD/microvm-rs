use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

// KVM ioctl numbers (from linux/kvm.h)
// These are constructed as _IO(KVMIO, nr) where KVMIO = 0xAE
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;

fn main() -> std::io::Result<()> {
    // Open /dev/kvm to get a handle to the KVM subsystem
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")?;

    println!("✓ Opened /dev/kvm (fd: {})", kvm.as_raw_fd());

    // Verify KVM API version - should be 12 (stable since Linux 2.6.x)
    let api_version = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0) };

    if api_version < 0 {
        return Err(std::io::Error::last_os_error());
    }

    println!("✓ KVM API version: {}", api_version);

    if api_version != 12 {
        eprintln!("⚠ Warning: Expected API version 12, got {}", api_version);
    }

    Ok(())
}
