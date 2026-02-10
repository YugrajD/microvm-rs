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
const KVM_GET_REGS: libc::c_ulong = 0x8090AE81;

// KVM exit reasons
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_IO_OUT: u8 = 1;

// Control register bits
const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

// Memory layout
const BOOT_GDT_ADDR: u64 = 0x1000;
const BOOT_PML4_ADDR: u64 = 0x2000;
const BOOT_PDPT_ADDR: u64 = 0x3000;
const BOOT_PD_ADDR: u64 = 0x4000;
const BOOT_CODE_ADDR: u64 = 0x10000;

// Page table flags
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

const GDT_KERNEL_CODE: u16 = 1 << 3;
const GDT_KERNEL_DATA: u16 = 2 << 3;

#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32, flags: u32, guest_phys_addr: u64, memory_size: u64, userspace_addr: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmSegment {
    base: u64, limit: u32, selector: u16, type_: u8, present: u8, dpl: u8, db: u8,
    s: u8, l: u8, g: u8, avl: u8, unusable: u8, _padding: u8,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmDtable { base: u64, limit: u16, _padding: [u16; 3] }

#[repr(C)]
#[derive(Default)]
struct KvmSregs {
    cs: KvmSegment, ds: KvmSegment, es: KvmSegment, fs: KvmSegment,
    gs: KvmSegment, ss: KvmSegment, tr: KvmSegment, ldt: KvmSegment,
    gdt: KvmDtable, idt: KvmDtable,
    cr0: u64, cr2: u64, cr3: u64, cr4: u64, cr8: u64, efer: u64,
    apic_base: u64, interrupt_bitmap: [u64; 4],
}

#[repr(C)]
#[derive(Default, Debug)]
struct KvmRegs {
    rax: u64, rbx: u64, rcx: u64, rdx: u64, rsi: u64, rdi: u64, rsp: u64, rbp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64, r12: u64, r13: u64, r14: u64, r15: u64,
    rip: u64, rflags: u64,
}

#[repr(C)]
struct KvmRun {
    request_interrupt_window: u8, immediate_exit: u8, _padding1: [u8; 6],
    exit_reason: u32, ready_for_interrupt_injection: u8, if_flag: u8, flags: u16,
    cr8: u64, apic_base: u64, _union: [u8; 256],
}

#[repr(C)]
struct KvmRunExitIo { direction: u8, size: u8, port: u16, count: u32, data_offset: u64 }

struct Kvm { fd: RawFd }
impl Kvm {
    fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
        let fd = file.as_raw_fd(); std::mem::forget(file); Ok(Kvm { fd })
    }
    fn api_version(&self) -> std::io::Result<i32> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_API_VERSION, 0) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(ret) }
    }
    fn create_vm(&self) -> std::io::Result<Vm> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VM, 0) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(Vm { fd: ret }) }
    }
    fn vcpu_mmap_size(&self) -> std::io::Result<usize> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_VCPU_MMAP_SIZE, 0) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(ret as usize) }
    }
}
impl Drop for Kvm { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct Vm { fd: RawFd }
impl Vm {
    fn create_vcpu(&self, id: u64) -> std::io::Result<Vcpu> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_CREATE_VCPU, id) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(Vcpu { fd: ret }) }
    }
    fn set_user_memory_region(&self, slot: u32, guest_addr: u64, size: u64, host_addr: u64) -> std::io::Result<()> {
        let region = KvmUserspaceMemoryRegion { slot, flags: 0, guest_phys_addr: guest_addr, memory_size: size, userspace_addr: host_addr };
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_USER_MEMORY_REGION, &region) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }
}
impl Drop for Vm { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct Vcpu { fd: RawFd }
impl Vcpu {
    fn get_sregs(&self) -> std::io::Result<KvmSregs> {
        let mut sregs = KvmSregs::default();
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_SREGS, &mut sregs) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(sregs) }
    }
    fn set_sregs(&self, sregs: &KvmSregs) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_SREGS, sregs) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }
    fn get_regs(&self) -> std::io::Result<KvmRegs> {
        let mut regs = KvmRegs::default();
        let ret = unsafe { libc::ioctl(self.fd, KVM_GET_REGS, &mut regs) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(regs) }
    }
    fn set_regs(&self, regs: &KvmRegs) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_SET_REGS, regs) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }
    fn run(&self) -> std::io::Result<()> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_RUN, 0) };
        if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }
    fn mmap_run(&self, size: usize) -> std::io::Result<*mut KvmRun> {
        let ptr = unsafe { libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, self.fd, 0) };
        if ptr == libc::MAP_FAILED { Err(std::io::Error::last_os_error()) } else { Ok(ptr as *mut KvmRun) }
    }
}
impl Drop for Vcpu { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct GuestMemory { ptr: *mut u8, size: usize }
impl GuestMemory {
    fn new(size: usize) -> std::io::Result<Self> {
        let ptr = unsafe { libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if ptr == libc::MAP_FAILED { Err(std::io::Error::last_os_error()) } else { Ok(GuestMemory { ptr: ptr as *mut u8, size }) }
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
impl Drop for GuestMemory { fn drop(&mut self) { unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) }; } }

fn setup_page_tables(mem: &GuestMemory) {
    mem.write_u64(BOOT_PML4_ADDR as usize, BOOT_PDPT_ADDR | PTE_PRESENT | PTE_WRITABLE);
    mem.write_u64(BOOT_PDPT_ADDR as usize, BOOT_PD_ADDR | PTE_PRESENT | PTE_WRITABLE);
    for i in 0..512u64 {
        mem.write_u64((BOOT_PD_ADDR + i * 8) as usize, (i * (2 << 20)) | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE);
    }
}

fn setup_gdt(mem: &GuestMemory) {
    mem.write_u64(BOOT_GDT_ADDR as usize, 0);
    mem.write_u64((BOOT_GDT_ADDR + 8) as usize, 0x00af9a000000ffff);  // Code64
    mem.write_u64((BOOT_GDT_ADDR + 16) as usize, 0x00cf92000000ffff); // Data64
}

fn make_code_segment() -> KvmSegment {
    KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_CODE, type_: 11, present: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, avl: 0, unusable: 0, _padding: 0 }
}

fn make_data_segment() -> KvmSegment {
    KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_DATA, type_: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0, _padding: 0 }
}

fn main() -> std::io::Result<()> {
    println!("=== microvm-rs: 64-bit Long Mode Verification ===\n");

    let kvm = Kvm::new()?;
    println!("✓ KVM API version: {}", kvm.api_version()?);

    let vm = kvm.create_vm()?;
    let mem_size = 128 << 20;
    let guest_mem = GuestMemory::new(mem_size)?;
    vm.set_user_memory_region(0, 0, mem_size as u64, guest_mem.as_ptr() as u64)?;
    println!("✓ VM created with {} MB RAM", mem_size >> 20);

    setup_page_tables(&guest_mem);
    setup_gdt(&guest_mem);
    println!("✓ Page tables & GDT initialized");

    // 64-bit guest code that PROVES we're in long mode:
    // 1. Load a 64-bit immediate into RAX (only works in 64-bit mode)
    // 2. Use R8 register (doesn't exist in 32-bit mode)
    // 3. Do 64-bit arithmetic
    // 4. Output result to serial port
    //
    // If this runs successfully, we MUST be in 64-bit mode!
    
    #[rustfmt::skip]
    let guest_code: &[u8] = &[
        // mov rax, 0xDEADBEEF12345678  (64-bit immediate - ONLY valid in long mode!)
        0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xef, 0xbe, 0xad, 0xde,
        
        // mov r8, rax  (R8 register - ONLY exists in 64-bit mode!)
        0x49, 0x89, 0xc0,
        
        // shr r8, 32  (shift right 32 bits to get upper half)
        0x49, 0xc1, 0xe8, 0x20,
        
        // cmp r8d, 0xDEADBEEF  (verify upper 32 bits)
        0x41, 0x81, 0xf8, 0xef, 0xbe, 0xad, 0xde,
        
        // jne fail (if not equal, we're not in 64-bit mode)
        0x75, 0x30,
        
        // === SUCCESS: Output "64-bit OK!" ===
        // mov dx, 0x3f8
        0x66, 0xba, 0xf8, 0x03,
        
        // Output '6'
        0xb0, 0x36, 0xee,
        // Output '4'
        0xb0, 0x34, 0xee,
        // Output '-'
        0xb0, 0x2d, 0xee,
        // Output 'b'
        0xb0, 0x62, 0xee,
        // Output 'i'
        0xb0, 0x69, 0xee,
        // Output 't'
        0xb0, 0x74, 0xee,
        // Output ' '
        0xb0, 0x20, 0xee,
        // Output 'O'
        0xb0, 0x4f, 0xee,
        // Output 'K'
        0xb0, 0x4b, 0xee,
        // Output '!'
        0xb0, 0x21, 0xee,
        // Output '\n'
        0xb0, 0x0a, 0xee,
        
        // Store magic value in RAX for verification: 0x6464 ("dd" = 64-bit mode marker)
        0x48, 0xc7, 0xc0, 0x64, 0x64, 0x00, 0x00,
        
        // hlt
        0xf4,
        
        // === FAIL path ===
        // Output "FAIL"
        0x66, 0xba, 0xf8, 0x03,
        0xb0, 0x46, 0xee,  // 'F'
        0xb0, 0x41, 0xee,  // 'A'
        0xb0, 0x49, 0xee,  // 'I'
        0xb0, 0x4c, 0xee,  // 'L'
        0xb0, 0x0a, 0xee,  // '\n'
        
        // Store 0 in RAX to indicate failure
        0x48, 0x31, 0xc0,
        
        // hlt
        0xf4,
    ];
    
    guest_mem.write(BOOT_CODE_ADDR as usize, guest_code);
    println!("✓ Loaded 64-bit verification code ({} bytes)", guest_code.len());
    println!("  Test: Load 0xDEADBEEF12345678 into RAX, verify with R8");

    let vcpu = vm.create_vcpu(0)?;
    let vcpu_mmap_size = kvm.vcpu_mmap_size()?;
    let kvm_run = vcpu.mmap_run(vcpu_mmap_size)?;

    let mut sregs = vcpu.get_sregs()?;
    sregs.cs = make_code_segment();
    sregs.ds = make_data_segment();
    sregs.es = make_data_segment();
    sregs.fs = make_data_segment();
    sregs.gs = make_data_segment();
    sregs.ss = make_data_segment();
    sregs.gdt.base = BOOT_GDT_ADDR;
    sregs.gdt.limit = 23;
    sregs.cr0 = CR0_PE | CR0_PG;
    sregs.cr3 = BOOT_PML4_ADDR;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME | EFER_LMA;
    vcpu.set_sregs(&sregs)?;
    println!("✓ Long mode enabled (EFER.LME=1, EFER.LMA=1)");

    let mut regs = KvmRegs::default();
    regs.rip = BOOT_CODE_ADDR;
    regs.rflags = 0x2;
    regs.rsp = 0x8000;
    vcpu.set_regs(&regs)?;

    println!("\n▶ Running 64-bit verification test...\n");

    let mut output = String::new();
    loop {
        vcpu.run()?;
        let exit_reason = unsafe { (*kvm_run).exit_reason };

        match exit_reason {
            KVM_EXIT_HLT => {
                let final_regs = vcpu.get_regs()?;
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Guest output: {}", output);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("\nFinal register state:");
                println!("  RAX = 0x{:016x}", final_regs.rax);
                println!("  R8  = 0x{:016x}", final_regs.r8);
                println!("  RIP = 0x{:016x}", final_regs.rip);
                
                if final_regs.rax == 0x6464 {
                    println!("\n🎉 SUCCESS: 64-bit long mode VERIFIED!");
                    println!("   ✓ 64-bit immediate load worked");
                    println!("   ✓ R8 register accessible");
                    println!("   ✓ 64-bit shift operation worked");
                } else {
                    println!("\n❌ FAILED: Not in 64-bit mode!");
                }
                break;
            }
            KVM_EXIT_IO => {
                let io = unsafe { &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo) };
                if io.direction == KVM_EXIT_IO_OUT && io.port == 0x3f8 {
                    let byte = unsafe { *(kvm_run as *const u8).add(io.data_offset as usize) };
                    if byte != 0x0a { output.push(byte as char); }
                }
            }
            _ => {
                println!("⚠ Unexpected exit: {}", exit_reason);
                break;
            }
        }
    }

    println!("\n=== Test complete ===");
    Ok(())
}
