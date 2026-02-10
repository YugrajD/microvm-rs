use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, RawFd};

// KVM ioctl numbers (from linux/kvm.h)
// _IO(KVMIO, nr) where KVMIO = 0xAE
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_CREATE_VM: libc::c_ulong = 0xAE01;
const KVM_CREATE_VCPU: libc::c_ulong = 0xAE41;

/// Wrapper for the KVM system interface
struct Kvm {
    fd: RawFd,
}

impl Kvm {
    /// Open /dev/kvm and return a Kvm instance
    fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")?;

        let fd = file.as_raw_fd();
        std::mem::forget(file);

        Ok(Kvm { fd })
    }

    /// Get the KVM API version
    fn api_version(&self) -> std::io::Result<i32> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_API_VERSION, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ret)
    }

    /// Create a new VM and return its file descriptor
    fn create_vm(&self) -> std::io::Result<Vm> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VM, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Vm { fd: ret })
    }
}

impl Drop for Kvm {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Wrapper for a KVM virtual machine
struct Vm {
    fd: RawFd,
}

impl Vm {
    /// Create a vCPU with the given ID (usually 0 for the first one)
    fn create_vcpu(&self, id: u64) -> std::io::Result<Vcpu> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VCPU, id) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Vcpu { fd: ret })
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Wrapper for a KVM virtual CPU
struct Vcpu {
    fd: RawFd,
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn main() -> std::io::Result<()> {
    // Step 1: Open /dev/kvm
    let kvm = Kvm::new()?;
    println!("✓ Opened /dev/kvm (fd: {})", kvm.fd);

    // Step 2: Check API version
    let api_version = kvm.api_version()?;
    println!("✓ KVM API version: {}", api_version);

    if api_version != 12 {
        eprintln!("⚠ Warning: Expected API version 12, got {}", api_version);
    }

    // Step 3: Create a VM
    let vm = kvm.create_vm()?;
    println!("✓ Created VM (fd: {})", vm.fd);

    // Step 4: Create a vCPU
    let vcpu = vm.create_vcpu(0)?;
    println!("✓ Created vCPU (fd: {})", vcpu.fd);

    Ok(())
}
