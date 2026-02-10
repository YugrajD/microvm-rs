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
const KVM_SET_REGS: libc::c_ulong = 0x4090AE82;

// KVM exit reasons
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_IO_OUT: u8 = 1;

// Control register bits
const CR0_PE: u64 = 1 << 0;   // Protected Mode Enable
const CR0_PG: u64 = 1 << 31;  // Paging
const CR4_PAE: u64 = 1 << 5;  // Physical Address Extension
const EFER_LME: u64 = 1 << 8; // Long Mode Enable
const EFER_LMA: u64 = 1 << 10; // Long Mode Active

// Memory layout constants
const BOOT_GDT_ADDR: u64 = 0x1000;
const BOOT_PML4_ADDR: u64 = 0x2000;
const BOOT_PDPT_ADDR: u64 = 0x3000;
const BOOT_PD_ADDR: u64 = 0x4000;
const BOOT_CODE_ADDR: u64 = 0x10000; // 64KB - where our code will be

// Page table entry flags
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;  // 2MB page (in PD)

// GDT segment selectors
const GDT_KERNEL_CODE: u16 = 1 << 3;  // Index 1, RPL 0
const GDT_KERNEL_DATA: u16 = 2 << 3;  // Index 2, RPL 0

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

// Special registers
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
    _union: [u8; 256],
}

#[repr(C)]
struct KvmRunExitIo {
    direction: u8,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
}

struct Kvm { fd: RawFd }

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

struct Vm { fd: RawFd }

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

struct Vcpu { fd: RawFd }

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

struct GuestMemory { ptr: *mut u8, size: usize }

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
    
    fn write_u64(&self, offset: usize, val: u64) {
        assert!(offset + 8 <= self.size);
        unsafe { ptr::write_unaligned(self.ptr.add(offset) as *mut u64, val); }
    }
    
    fn write(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()); }
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) { unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) }; }
}

/// Set up page tables for identity-mapped long mode
fn setup_page_tables(mem: &GuestMemory) {
    // PML4[0] -> PDPT
    mem.write_u64(BOOT_PML4_ADDR as usize, BOOT_PDPT_ADDR | PTE_PRESENT | PTE_WRITABLE);
    
    // PDPT[0] -> PD
    mem.write_u64(BOOT_PDPT_ADDR as usize, BOOT_PD_ADDR | PTE_PRESENT | PTE_WRITABLE);
    
    // PD entries: identity map first 1GB using 2MB huge pages (512 entries * 2MB = 1GB)
    for i in 0..512u64 {
        let addr = i * (2 << 20); // 2MB per entry
        mem.write_u64((BOOT_PD_ADDR + i * 8) as usize, addr | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE);
    }
}

/// Set up GDT for 64-bit long mode
fn setup_gdt(mem: &GuestMemory) {
    // GDT layout:
    // [0] NULL descriptor
    // [1] 64-bit code segment (0x00af9a000000ffff)
    // [2] 64-bit data segment (0x00cf92000000ffff)
    
    // NULL descriptor
    mem.write_u64(BOOT_GDT_ADDR as usize, 0);
    
    // Code segment: base=0, limit=0xfffff, type=0xa (execute/read), S=1, DPL=0, P=1, L=1, D=0, G=1
    // 0x00af9a000000ffff
    mem.write_u64((BOOT_GDT_ADDR + 8) as usize, 0x00af9a000000ffff);
    
    // Data segment: base=0, limit=0xfffff, type=0x2 (read/write), S=1, DPL=0, P=1, L=0, D=1, G=1
    // 0x00cf92000000ffff
    mem.write_u64((BOOT_GDT_ADDR + 16) as usize, 0x00cf92000000ffff);
}

/// Create a 64-bit code segment descriptor for KVM
fn make_code_segment() -> KvmSegment {
    KvmSegment {
        base: 0,
        limit: 0xffffffff,
        selector: GDT_KERNEL_CODE,
        type_: 11,     // Execute/Read, accessed
        present: 1,
        dpl: 0,
        db: 0,         // Must be 0 for 64-bit
        s: 1,          // Code/data segment
        l: 1,          // 64-bit mode
        g: 1,          // 4KB granularity
        avl: 0,
        unusable: 0,
        _padding: 0,
    }
}

/// Create a 64-bit data segment descriptor for KVM
fn make_data_segment() -> KvmSegment {
    KvmSegment {
        base: 0,
        limit: 0xffffffff,
        selector: GDT_KERNEL_DATA,
        type_: 3,      // Read/Write, accessed
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        _padding: 0,
    }
}

fn main() -> std::io::Result<()> {
    println!("=== microvm-rs (64-bit long mode) ===\n");

    let kvm = Kvm::new()?;
    println!("✓ Opened /dev/kvm");
    println!("✓ KVM API version: {}", kvm.api_version()?);

    let vm = kvm.create_vm()?;
    println!("✓ Created VM");

    // Allocate 128 MB guest memory
    let mem_size = 128 << 20;
    let guest_mem = GuestMemory::new(mem_size)?;
    println!("✓ Allocated {} MB guest memory", mem_size / (1024 * 1024));

    vm.set_user_memory_region(0, 0, mem_size as u64, guest_mem.as_ptr() as u64)?;
    println!("✓ Registered memory with KVM");

    // Set up page tables for long mode (identity map first 1GB)
    setup_page_tables(&guest_mem);
    println!("✓ Set up page tables (identity-mapped 1GB with 2MB pages)");
    println!("    PML4 @ 0x{:x}, PDPT @ 0x{:x}, PD @ 0x{:x}", BOOT_PML4_ADDR, BOOT_PDPT_ADDR, BOOT_PD_ADDR);

    // Set up GDT
    setup_gdt(&guest_mem);
    println!("✓ Set up GDT @ 0x{:x}", BOOT_GDT_ADDR);
    println!("    [0] NULL, [1] Code64, [2] Data64");

    // 64-bit guest code - outputs "Hi!" to serial then halts
    let guest_code: [u8; 25] = [
        // mov dx, 0x3f8
        0x66, 0xba, 0xf8, 0x03,
        // mov al, 'H'
        0xb0, 0x48,
        // out dx, al
        0xee,
        // mov al, 'i'
        0xb0, 0x69,
        // out dx, al
        0xee,
        // mov al, '!'
        0xb0, 0x21,
        // out dx, al
        0xee,
        // mov al, '\n'
        0xb0, 0x0a,
        // out dx, al
        0xee,
        // cli
        0xfa,
        // hlt (loop forever)
        0xf4,
        // jmp to hlt
        0xeb, 0xfd,
        // padding
        0x90, 0x90, 0x90, 0x90, 0x90,
    ];
    guest_mem.write(BOOT_CODE_ADDR as usize, &guest_code);
    println!("✓ Loaded 64-bit guest code @ 0x{:x} ({} bytes)", BOOT_CODE_ADDR, guest_code.len());

    let vcpu = vm.create_vcpu(0)?;
    println!("✓ Created vCPU");

    let vcpu_mmap_size = kvm.vcpu_mmap_size()?;
    let kvm_run = vcpu.mmap_run(vcpu_mmap_size)?;
    println!("✓ Mapped kvm_run structure");

    // Set up special registers for 64-bit long mode
    let mut sregs = vcpu.get_sregs()?;
    
    // Set up segments
    sregs.cs = make_code_segment();
    sregs.ds = make_data_segment();
    sregs.es = make_data_segment();
    sregs.fs = make_data_segment();
    sregs.gs = make_data_segment();
    sregs.ss = make_data_segment();
    
    // Set up GDT
    sregs.gdt.base = BOOT_GDT_ADDR;
    sregs.gdt.limit = 23; // 3 entries * 8 bytes - 1
    
    // Set up control registers for long mode
    sregs.cr0 = CR0_PE | CR0_PG;  // Protected mode + Paging
    sregs.cr3 = BOOT_PML4_ADDR;   // Page table root
    sregs.cr4 = CR4_PAE;          // PAE required for long mode
    sregs.efer = EFER_LME | EFER_LMA; // Long mode enable + active
    
    vcpu.set_sregs(&sregs)?;
    println!("✓ Set up special registers:");
    println!("    CR0 = 0x{:x} (PE + PG)", sregs.cr0);
    println!("    CR3 = 0x{:x} (PML4)", sregs.cr3);
    println!("    CR4 = 0x{:x} (PAE)", sregs.cr4);
    println!("    EFER = 0x{:x} (LME + LMA)", sregs.efer);

    // Set up general registers
    let mut regs = KvmRegs::default();
    regs.rip = BOOT_CODE_ADDR;
    regs.rflags = 0x2;
    regs.rsp = 0x8000; // Stack pointer
    vcpu.set_regs(&regs)?;
    println!("✓ Set registers: RIP=0x{:x}, RSP=0x{:x}", regs.rip, regs.rsp);

    println!("\n▶ Running 64-bit guest...\n");

    let mut output = String::new();
    loop {
        vcpu.run()?;
        let exit_reason = unsafe { (*kvm_run).exit_reason };

        match exit_reason {
            KVM_EXIT_HLT => {
                println!("Guest output: {}", output);
                println!("\n✓ Guest halted (HLT)");
                break;
            }
            KVM_EXIT_IO => {
                let io = unsafe { &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo) };
                if io.direction == KVM_EXIT_IO_OUT && io.port == 0x3f8 {
                    let data_ptr = unsafe { (kvm_run as *const u8).add(io.data_offset as usize) };
                    let byte = unsafe { *data_ptr };
                    if byte != 0x0a { output.push(byte as char); }
                }
            }
            _ => {
                println!("⚠ Unexpected exit: {}", exit_reason);
                break;
            }
        }
    }

    println!("\n=== VM exited successfully (64-bit mode) ===");
    Ok(())
}
