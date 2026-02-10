use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

// KVM ioctl numbers
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const KVM_CREATE_VM: libc::c_ulong = 0xAE01;
const KVM_CREATE_VCPU: libc::c_ulong = 0xAE41;
const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0xAE04;
const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x4020AE46;
const KVM_RUN: libc::c_ulong = 0xAE80;
const KVM_GET_SREGS: libc::c_ulong = 0x8138AE83;
const KVM_SET_SREGS: libc::c_ulong = 0x4138AE84;
const KVM_GET_REGS: libc::c_ulong = 0x8090AE81;
const KVM_SET_REGS: libc::c_ulong = 0x4090AE82;

// KVM exit reasons
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_IO_OUT: u8 = 1;

// Memory region structure
#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

// Segment register
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmSegment {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    _padding: u8,
}

// Descriptor table register
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmDtable {
    base: u64,
    limit: u16,
    _padding: [u16; 3],
}

// Special registers (segment registers, etc)
#[repr(C)]
#[derive(Default)]
struct KvmSregs {
    cs: KvmSegment,
    ds: KvmSegment,
    es: KvmSegment,
    fs: KvmSegment,
    gs: KvmSegment,
    ss: KvmSegment,
    tr: KvmSegment,
    ldt: KvmSegment,
    gdt: KvmDtable,
    idt: KvmDtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

// General purpose registers
#[repr(C)]
#[derive(Default)]
struct KvmRegs {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rsp: u64, rbp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    rip: u64, rflags: u64,
}

// kvm_run structure (partial - we only need the header and IO union member)
#[repr(C)]
struct KvmRun {
    request_interrupt_window: u8,
    immediate_exit: u8,
    _padding1: [u8; 6],
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    // Union starts here - we'll access IO fields via offset
    _union: [u8; 256],
}

// IO exit info (at offset of _union in KvmRun)
#[repr(C)]
struct KvmRunExitIo {
    direction: u8,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
}

struct Kvm {
    fd: RawFd,
}

impl Kvm {
    fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
        let fd = file.as_raw_fd();
        std::mem::forget(file);
        Ok(Kvm { fd })
    }

    fn api_version(&self) -> std::io::Result<i32> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_API_VERSION, 0) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(ret)
    }

    fn create_vm(&self) -> std::io::Result<Vm> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VM, 0) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(Vm { fd: ret })
    }

    fn vcpu_mmap_size(&self) -> std::io::Result<usize> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_VCPU_MMAP_SIZE, 0) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(ret as usize)
    }
}

impl Drop for Kvm {
    fn drop(&mut self) { unsafe { libc::close(self.fd) }; }
}

struct Vm {
    fd: RawFd,
}

impl Vm {
    fn create_vcpu(&self, id: u64) -> std::io::Result<Vcpu> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VCPU, id) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(Vcpu { fd: ret })
    }

    fn set_user_memory_region(&self, slot: u32, guest_addr: u64, size: u64, host_addr: u64) -> std::io::Result<()> {
        let region = KvmUserspaceMemoryRegion {
            slot, flags: 0, guest_phys_addr: guest_addr, memory_size: size, userspace_addr: host_addr,
        };
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_USER_MEMORY_REGION, &region) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) { unsafe { libc::close(self.fd) }; }
}

struct Vcpu {
    fd: RawFd,
}

impl Vcpu {
    fn get_sregs(&self) -> std::io::Result<KvmSregs> {
        let mut sregs = KvmSregs::default();
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_SREGS, &mut sregs) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(sregs)
    }

    fn set_sregs(&self, sregs: &KvmSregs) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_SREGS, sregs) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }

    fn set_regs(&self, regs: &KvmRegs) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_REGS, regs) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }

    fn run(&self) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_RUN, 0) };
        if ret < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }

    fn mmap_run(&self, size: usize) -> std::io::Result<*mut KvmRun> {
        let ptr = unsafe {
            libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_SHARED, self.fd, 0)
        };
        if ptr == libc::MAP_FAILED { return Err(std::io::Error::last_os_error()); }
        Ok(ptr as *mut KvmRun)
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) { unsafe { libc::close(self.fd) }; }
}

struct GuestMemory {
    ptr: *mut u8,
    size: usize,
}

impl GuestMemory {
    fn new(size: usize) -> std::io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        if ptr == libc::MAP_FAILED { return Err(std::io::Error::last_os_error()); }
        Ok(GuestMemory { ptr: ptr as *mut u8, size })
    }

    fn as_ptr(&self) -> *mut u8 { self.ptr }

    fn write(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()); }
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) { unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) }; }
}

fn main() -> std::io::Result<()> {
    println!("=== microvm-rs ===\n");

    // 1. Open KVM
    let kvm = Kvm::new()?;
    println!("✓ Opened /dev/kvm");

    // 2. Check API version
    let api_version = kvm.api_version()?;
    println!("✓ KVM API version: {}", api_version);

    // 3. Create VM
    let vm = kvm.create_vm()?;
    println!("✓ Created VM");

    // 4. Allocate guest memory (1 MB)
    let mem_size = 128 << 20; // 128 MB
    let guest_mem = GuestMemory::new(mem_size)?;
    println!("✓ Allocated {} MB guest memory", mem_size / (1024 * 1024));

    // 5. Register memory with KVM
    vm.set_user_memory_region(0, 0, mem_size as u64, guest_mem.as_ptr() as u64)?;
    println!("✓ Registered memory with KVM");

    // 6. Load guest code - outputs "Hi!" to serial port then halts
    let guest_code: [u8; 16] = [
        0xba, 0xf8, 0x03, // mov dx, 0x3f8
        0xb0, 0x48,       // mov al, 'H'
        0xee,             // out dx, al
        0xb0, 0x69,       // mov al, 'i'
        0xee,             // out dx, al
        0xb0, 0x21,       // mov al, '!'
        0xee,             // out dx, al
        0xb0, 0x0a,       // mov al, '\n'
        0xee,             // out dx, al
        0xf4,             // hlt
    ];
    guest_mem.write(0, &guest_code);
    println!("✓ Loaded guest code ({} bytes)", guest_code.len());

    // 7. Create vCPU
    let vcpu = vm.create_vcpu(0)?;
    println!("✓ Created vCPU");

    // 8. Map kvm_run structure
    let vcpu_mmap_size = kvm.vcpu_mmap_size()?;
    let kvm_run = vcpu.mmap_run(vcpu_mmap_size)?;
    println!("✓ Mapped kvm_run structure");

    // 9. Set up segment registers for real mode
    let mut sregs = vcpu.get_sregs()?;
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs)?;
    println!("✓ Set segment registers (real mode at 0x0)");

    // 10. Set up general registers
    let mut regs = KvmRegs::default();
    regs.rip = 0;           // Start execution at address 0
    regs.rflags = 0x2;      // Required: bit 1 must be set
    vcpu.set_regs(&regs)?;
    println!("✓ Set registers (RIP=0x0)");

    println!("\n▶ Running guest...\n");

    // 11. Run the vCPU in a loop
    let mut output = String::new();
    loop {
        vcpu.run()?;

        let exit_reason = unsafe { (*kvm_run).exit_reason };

        match exit_reason {
            KVM_EXIT_HLT => {
                println!("Guest output: {}", output);
                println!("\n✓ Guest halted (HLT instruction)");
                break;
            }
            KVM_EXIT_IO => {
                // Get IO info from the union
                let io = unsafe {
                    &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo)
                };

                if io.direction == KVM_EXIT_IO_OUT && io.port == 0x3f8 {
                    // Get the data that was written
                    let data_ptr = unsafe {
                        (kvm_run as *const u8).add(io.data_offset as usize)
                    };
                    let byte = unsafe { *data_ptr };

                    if byte == 0x0a {
                        // newline
                    } else {
                        output.push(byte as char);
                    }
                }
            }
            _ => {
                println!("⚠ Unexpected exit reason: {}", exit_reason);
                break;
            }
        }
    }

    println!("\n=== VM exited successfully ===");
    Ok(())
}
