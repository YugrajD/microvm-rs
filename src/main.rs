use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

// KVM ioctl numbers (from linux/kvm.h)
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_CREATE_VM: libc::c_ulong = 0xAE01;
const KVM_CREATE_VCPU: libc::c_ulong = 0xAE41;
const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0xAE04;
const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x4020AE46;

// Memory region structure for KVM_SET_USER_MEMORY_REGION
#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

/// Wrapper for the KVM system interface
struct Kvm {
    fd: RawFd,
}

impl Kvm {
    fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")?;
        let fd = file.as_raw_fd();
        std::mem::forget(file);
        Ok(Kvm { fd })
    }

    fn api_version(&self) -> std::io::Result<i32> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_API_VERSION, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ret)
    }

    fn create_vm(&self) -> std::io::Result<Vm> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VM, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Vm { fd: ret })
    }

    fn vcpu_mmap_size(&self) -> std::io::Result<usize> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_VCPU_MMAP_SIZE, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ret as usize)
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
    fn create_vcpu(&self, id: u64) -> std::io::Result<Vcpu> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VCPU, id) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Vcpu { fd: ret })
    }

    fn set_user_memory_region(&self, slot: u32, guest_addr: u64, size: u64, host_addr: u64) -> std::io::Result<()> {
        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: 0,
            guest_phys_addr: guest_addr,
            memory_size: size,
            userspace_addr: host_addr,
        };
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_USER_MEMORY_REGION, &region) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
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

/// Guest memory - mmap'd region that becomes guest physical memory
struct GuestMemory {
    ptr: *mut u8,
    size: usize,
}

impl GuestMemory {
    fn new(size: usize) -> std::io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(GuestMemory {
            ptr: ptr as *mut u8,
            size,
        })
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn write(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
    }
}

fn main() -> std::io::Result<()> {
    // Step 1: Open /dev/kvm
    let kvm = Kvm::new()?;
    println!("✓ Opened /dev/kvm (fd: {})", kvm.fd);

    // Step 2: Check API version
    let api_version = kvm.api_version()?;
    println!("✓ KVM API version: {}", api_version);

    // Step 3: Create a VM
    let vm = kvm.create_vm()?;
    println!("✓ Created VM (fd: {})", vm.fd);

    // Step 4: Allocate guest memory (1 MB)
    let mem_size = 1 << 20; // 1 MB
    let guest_mem = GuestMemory::new(mem_size)?;
    println!("✓ Allocated {} bytes of guest memory", mem_size);

    // Step 5: Register memory with KVM
    vm.set_user_memory_region(0, 0, mem_size as u64, guest_mem.as_ptr() as u64)?;
    println!("✓ Registered guest memory with KVM");

    // Step 6: Load tiny guest code at address 0
    // This x86 code outputs "Hi!\n" to serial port 0x3f8 then halts
    //
    // Assembly:
    //   mov dx, 0x3f8   ; Serial port COM1
    //   mov al, 'H'
    //   out dx, al
    //   mov al, 'i'
    //   out dx, al
    //   mov al, '!'
    //   out dx, al
    //   mov al, 0x0a    ; newline
    //   out dx, al
    //   hlt
    let guest_code: [u8; 16] = [
        0xba, 0xf8, 0x03, // mov dx, 0x3f8
        0xb0, 0x48,       // mov al, 'H'
        0xee,             // out dx, al
        0xb0, 0x69,       // mov al, 'i'
        0xee,             // out dx, al
        0xb0, 0x21,       // mov al, '!'
        0xee,             // out dx, al
        0xb0, 0x0a,       // mov al, n\
        0xee,             // out dx, al
        0xf4,             // hlt
    ];
    guest_mem.write(0, &guest_code);
    println!("✓ Loaded guest code ({} bytes)", guest_code.len());
    println!("  Guest will output \"Hi!\" to serial port 0x3f8");

    // Step 7: Create vCPU
    let vcpu = vm.create_vcpu(0)?;
    println!("✓ Created vCPU (fd: {})", vcpu.fd);

    // Get vCPU mmap size (needed for KVM_RUN later)
    let vcpu_mmap_size = kvm.vcpu_mmap_size()?;
    println!("✓ vCPU mmap size: {} bytes", vcpu_mmap_size);

    println!("\n🎉 Guest VM is ready! Next step: set up registers and run it.");

    Ok(())
}
