use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
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
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_SHUTDOWN: u32 = 8;
const KVM_EXIT_IO_OUT: u8 = 1;

// Control register bits
const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

// Memory layout
const BOOT_GDT_ADDR: u64 = 0x500;
const BOOT_PARAMS_ADDR: u64 = 0x7000;
const CMDLINE_ADDR: u64 = 0x20000;
const BOOT_PML4_ADDR: u64 = 0x9000;
const BOOT_PDPT_ADDR: u64 = 0xa000;
const BOOT_PD_ADDR: u64 = 0xb000;
const KERNEL_LOAD_ADDR: u64 = 0x100000;

// Page table flags
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

const GDT_KERNEL_CODE: u16 = 1 << 3;
const GDT_KERNEL_DATA: u16 = 2 << 3;

// Linux boot protocol constants
const BOOT_FLAG: u16 = 0xAA55;
const HDRS_MAGIC: u32 = 0x53726448;
const SETUP_HEADER_OFFSET: u64 = 0x1f1;
const SETUP_HEADER_SIZE: usize = 0x7f;  // From 0x1f1 to ~0x270

// E820 memory map
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

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
#[derive(Default)]
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

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct E820Entry { addr: u64, size: u64, type_: u32 }

struct BzImage {
    setup_header: Vec<u8>,
    protected_mode_kernel: Vec<u8>,
    protocol_version: u16,
    setup_sects: u8,
}

impl BzImage {
    fn load(path: &str) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        
        // Read boot flag
        file.seek(SeekFrom::Start(0x1fe))?;
        let mut buf = [0u8; 2];
        file.read_exact(&mut buf)?;
        if u16::from_le_bytes(buf) != BOOT_FLAG {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid boot flag"));
        }

        // Read header magic
        file.seek(SeekFrom::Start(0x202))?;
        let mut buf4 = [0u8; 4];
        file.read_exact(&mut buf4)?;
        if u32::from_le_bytes(buf4) != HDRS_MAGIC {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid header magic"));
        }

        // Read protocol version
        file.seek(SeekFrom::Start(0x206))?;
        file.read_exact(&mut buf)?;
        let protocol_version = u16::from_le_bytes(buf);

        // Read setup_sects
        file.seek(SeekFrom::Start(0x1f1))?;
        let mut buf1 = [0u8; 1];
        file.read_exact(&mut buf1)?;
        let setup_sects = if buf1[0] == 0 { 4 } else { buf1[0] };

        // Read entire setup header (from 0x1f1 to end of setup)
        file.seek(SeekFrom::Start(SETUP_HEADER_OFFSET))?;
        let mut setup_header = vec![0u8; SETUP_HEADER_SIZE];
        file.read_exact(&mut setup_header)?;

        // Calculate protected mode kernel location
        let setup_size = (setup_sects as u64 + 1) * 512;
        file.seek(SeekFrom::End(0))?;
        let file_size = file.stream_position()?;
        let pm_size = file_size - setup_size;

        // Read protected mode kernel
        file.seek(SeekFrom::Start(setup_size))?;
        let mut protected_mode_kernel = vec![0u8; pm_size as usize];
        file.read_exact(&mut protected_mode_kernel)?;

        Ok(BzImage { setup_header, protected_mode_kernel, protocol_version, setup_sects })
    }
}

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
    fn write_u8(&self, offset: usize, val: u8) { unsafe { *self.ptr.add(offset) = val; } }
    fn write_u32(&self, offset: usize, val: u32) { unsafe { ptr::write_unaligned(self.ptr.add(offset) as *mut u32, val); } }
    fn write_u64(&self, offset: usize, val: u64) { unsafe { ptr::write_unaligned(self.ptr.add(offset) as *mut u64, val); } }
    fn write(&self, offset: usize, data: &[u8]) { unsafe { ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()); } }
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
    mem.write_u64((BOOT_GDT_ADDR + 8) as usize, 0x00af9a000000ffff);
    mem.write_u64((BOOT_GDT_ADDR + 16) as usize, 0x00cf92000000ffff);
}

fn setup_boot_params(mem: &GuestMemory, bzimage: &BzImage, cmdline: &str, mem_size: u64) {
    let bp = BOOT_PARAMS_ADDR as usize;
    
    // Copy the setup header from bzImage
    mem.write(bp + SETUP_HEADER_OFFSET as usize, &bzimage.setup_header);
    
    // Override/set specific fields
    // type_of_loader at 0x210
    mem.write_u8(bp + 0x210, 0xFF);
    
    // loadflags at 0x211: LOADED_HIGH | CAN_USE_HEAP | KEEP_SEGMENTS
    mem.write_u8(bp + 0x211, 0x81);
    
    // heap_end_ptr at 0x224
    mem.write_u32(bp + 0x224, 0xfe00);
    
    // cmd_line_ptr at 0x228
    mem.write_u32(bp + 0x228, CMDLINE_ADDR as u32);
    
    // Write command line
    mem.write(CMDLINE_ADDR as usize, cmdline.as_bytes());
    mem.write_u8(CMDLINE_ADDR as usize + cmdline.len(), 0);
    
    // E820 memory map at 0x2d0, count at 0x1e8
    // Entry 0: Usable RAM below 640KB
    let e820_0 = E820Entry { addr: 0, size: 0x9fc00, type_: E820_RAM };
    mem.write(bp + 0x2d0, unsafe { std::slice::from_raw_parts(&e820_0 as *const _ as *const u8, 20) });
    
    // Entry 1: Reserved (EBDA, ROM, etc)
    let e820_1 = E820Entry { addr: 0x9fc00, size: 0x60400, type_: E820_RESERVED };
    mem.write(bp + 0x2d0 + 20, unsafe { std::slice::from_raw_parts(&e820_1 as *const _ as *const u8, 20) });
    
    // Entry 2: Usable RAM above 1MB
    let e820_2 = E820Entry { addr: 0x100000, size: mem_size - 0x100000, type_: E820_RAM };
    mem.write(bp + 0x2d0 + 40, unsafe { std::slice::from_raw_parts(&e820_2 as *const _ as *const u8, 20) });
    
    mem.write_u8(bp + 0x1e8, 3); // 3 e820 entries
    
    // vid_mode at 0x1fa (0xFFFF = normal)
    mem.write_u32(bp + 0x1fa, 0xFFFF);
}

fn make_code_segment() -> KvmSegment {
    KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_CODE, type_: 11, present: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, avl: 0, unusable: 0, _padding: 0 }
}

fn make_data_segment() -> KvmSegment {
    KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_DATA, type_: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0, unusable: 0, _padding: 0 }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <bzImage> [cmdline]", args[0]);
        return Ok(());
    }
    
    let kernel_path = &args[1];
    let cmdline = args.get(2).map(|s| s.as_str()).unwrap_or("console=ttyS0 earlyprintk=serial,ttyS0,115200");
    
    println!("=== microvm-rs: Linux Boot ===\n");

    // Load bzImage
    let bzimage = BzImage::load(kernel_path)?;
    println!("✓ Loaded bzImage:");
    println!("    Protocol: {}.{}", bzimage.protocol_version >> 8, bzimage.protocol_version & 0xff);
    println!("    Setup sectors: {}", bzimage.setup_sects);
    println!("    Kernel size: {} KB", bzimage.protected_mode_kernel.len() / 1024);

    let kvm = Kvm::new()?;
    println!("✓ KVM API version: {}", kvm.api_version()?);

    let vm = kvm.create_vm()?;
    let mem_size: usize = 128 << 20;
    let guest_mem = GuestMemory::new(mem_size)?;
    vm.set_user_memory_region(0, 0, mem_size as u64, guest_mem.as_ptr() as u64)?;
    println!("✓ VM: {} MB RAM", mem_size >> 20);

    setup_page_tables(&guest_mem);
    setup_gdt(&guest_mem);
    println!("✓ Page tables & GDT ready");

    // Load kernel at 1MB
    guest_mem.write(KERNEL_LOAD_ADDR as usize, &bzimage.protected_mode_kernel);
    println!("✓ Kernel loaded at 0x{:x}", KERNEL_LOAD_ADDR);

    setup_boot_params(&guest_mem, &bzimage, cmdline, mem_size as u64);
    println!("✓ Boot params at 0x{:x}", BOOT_PARAMS_ADDR);
    println!("✓ Cmdline: \"{}\"", cmdline);

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

    let mut regs = KvmRegs::default();
    regs.rip = KERNEL_LOAD_ADDR + 0x200;  // 64-bit entry point
    regs.rsi = BOOT_PARAMS_ADDR;
    regs.rflags = 0x2;
    vcpu.set_regs(&regs)?;
    println!("✓ vCPU: RIP=0x{:x}, RSI=0x{:x}", regs.rip, regs.rsi);

    println!("\n▶ Booting...\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let mut line = String::new();
    let mut exit_count = 0u64;
    loop {
        vcpu.run()?;
        let exit_reason = unsafe { (*kvm_run).exit_reason };
        exit_count += 1;

        match exit_reason {
            KVM_EXIT_IO => { let io = unsafe { &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo) }; if io.port != 0x3f8 && io.port != 0x80 { eprintln!("IO: port=0x{:x} dir={} size={}", io.port, io.direction, io.size); }
                let io = unsafe { &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo) };
                if io.direction == KVM_EXIT_IO_OUT && io.port == 0x3f8 {
                    let byte = unsafe { *(kvm_run as *const u8).add(io.data_offset as usize) };
                    if byte == b'\n' || byte == b'\r' {
                        if !line.is_empty() || byte == b'\n' {
                            println!("{}", line);
                            line.clear();
                        }
                    } else if byte >= 0x20 || byte == b'\t' {
                        line.push(byte as char);
                    }
                }
            }
            KVM_EXIT_HLT => {
                if !line.is_empty() { println!("{}", line); }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("\n✓ HLT after {} VM exits", exit_count);
                break;
            }
            KVM_EXIT_SHUTDOWN => {
                if !line.is_empty() { println!("{}", line); }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("\n⚠ SHUTDOWN after {} VM exits", exit_count);
                break;
            }
            KVM_EXIT_MMIO => {}
            _ => {
                if !line.is_empty() { println!("{}", line); }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("\n⚠ Exit reason {} after {} VM exits", exit_reason, exit_count);
                break;
            }
        }
        if exit_count > 100_000_000 { println!("\n⚠ Too many exits"); break; }
    }
    Ok(())
}
