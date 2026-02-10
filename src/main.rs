use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

// KVM Constants
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

const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_SHUTDOWN: u32 = 8;
const KVM_EXIT_IO_OUT: u8 = 1;

const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

// Memory Layout
const BOOT_GDT_ADDR: u64 = 0x500;
const ZERO_PAGE_ADDR: u64 = 0x7000;
const CMDLINE_ADDR: u64 = 0x20000;
const KERNEL_LOAD_ADDR: u64 = 0x100000;

// Page table addresses
const PML4_ADDR: u64 = 0x1000;
const PDPT_LOW_ADDR: u64 = 0x2000;   // For identity mapping (0-512GB)
const PD_LOW_ADDR: u64 = 0x3000;     // Page directory for first 1GB
const PDPT_HIGH_ADDR: u64 = 0x4000;  // For kernel high addresses
const PD_HIGH_ADDR: u64 = 0x5000;    // Page directory for kernel

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

const GDT_KERNEL_CODE: u16 = 1 << 3;
const GDT_KERNEL_DATA: u16 = 2 << 3;

const HDRS_MAGIC: u32 = 0x53726448;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

const COM1_PORT: u16 = 0x3f8;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_TEMT: u8 = 0x40;
const LCR_DLAB: u8 = 0x80;

#[repr(C)]
struct KvmUserspaceMemoryRegion { slot: u32, flags: u32, guest_phys_addr: u64, memory_size: u64, userspace_addr: u64 }

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmSegment { base: u64, limit: u32, selector: u16, type_: u8, present: u8, dpl: u8, db: u8, s: u8, l: u8, g: u8, avl: u8, unusable: u8, _padding: u8 }

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmDtable { base: u64, limit: u16, _padding: [u16; 3] }

#[repr(C)]
#[derive(Default)]
struct KvmSregs { cs: KvmSegment, ds: KvmSegment, es: KvmSegment, fs: KvmSegment, gs: KvmSegment, ss: KvmSegment, tr: KvmSegment, ldt: KvmSegment, gdt: KvmDtable, idt: KvmDtable, cr0: u64, cr2: u64, cr3: u64, cr4: u64, cr8: u64, efer: u64, apic_base: u64, interrupt_bitmap: [u64; 4] }

#[repr(C)]
#[derive(Default)]
struct KvmRegs { rax: u64, rbx: u64, rcx: u64, rdx: u64, rsi: u64, rdi: u64, rsp: u64, rbp: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64, r13: u64, r14: u64, r15: u64, rip: u64, rflags: u64 }

#[repr(C)]
struct KvmRun { request_interrupt_window: u8, immediate_exit: u8, _padding1: [u8; 6], exit_reason: u32, ready_for_interrupt_injection: u8, if_flag: u8, flags: u16, cr8: u64, apic_base: u64, _union: [u8; 256] }

#[repr(C)]
struct KvmRunExitIo { direction: u8, size: u8, port: u16, count: u32, data_offset: u64 }

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct E820Entry { addr: u64, size: u64, type_: u32 }

// 8250 UART
struct Serial8250 { ier: u8, iir: u8, lcr: u8, mcr: u8, lsr: u8, msr: u8, scr: u8, dll: u8, dlh: u8 }

impl Serial8250 {
    fn new() -> Self { Serial8250 { ier: 0, iir: 0x01, lcr: 0x03, mcr: 0x08, lsr: LSR_THR_EMPTY | LSR_TEMT, msr: 0xb0, scr: 0, dll: 0x01, dlh: 0 } }
    
    fn read(&mut self, offset: u16) -> u8 {
        let dlab = (self.lcr & LCR_DLAB) != 0;
        match offset {
            0 if dlab => self.dll,
            0 => 0,
            1 if dlab => self.dlh,
            1 => self.ier,
            2 => self.iir,
            3 => self.lcr,
            4 => self.mcr,
            5 => { let v = self.lsr; self.lsr = LSR_THR_EMPTY | LSR_TEMT; v }
            6 => self.msr,
            7 => self.scr,
            _ => 0,
        }
    }
    
    fn write(&mut self, offset: u16, val: u8) {
        let dlab = (self.lcr & LCR_DLAB) != 0;
        match offset {
            0 if dlab => self.dll = val,
            0 => { let _ = std::io::stdout().write_all(&[val]); let _ = std::io::stdout().flush(); }
            1 if dlab => self.dlh = val,
            1 => self.ier = val & 0x0f,
            2 => if val & 1 != 0 { self.iir |= 0xc0; },
            3 => self.lcr = val,
            4 => self.mcr = val & 0x1f,
            7 => self.scr = val,
            _ => {}
        }
    }
    
    fn handle(&mut self, port: u16, is_write: bool, data: &mut u8) {
        if is_write { self.write(port - COM1_PORT, *data); }
        else { *data = self.read(port - COM1_PORT); }
    }
}

struct BzImage { setup_header: Vec<u8>, kernel: Vec<u8>, protocol_version: u16 }

impl BzImage {
    fn load(path: &str) -> std::io::Result<Self> {
        let mut f = File::open(path)?;
        let mut buf2 = [0u8; 2]; let mut buf4 = [0u8; 4];
        
        f.seek(SeekFrom::Start(0x1fe))?; f.read_exact(&mut buf2)?;
        if u16::from_le_bytes(buf2) != 0xAA55 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Bad boot flag")); }
        
        f.seek(SeekFrom::Start(0x202))?; f.read_exact(&mut buf4)?;
        if u32::from_le_bytes(buf4) != HDRS_MAGIC { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Bad header")); }
        
        f.seek(SeekFrom::Start(0x206))?; f.read_exact(&mut buf2)?;
        let protocol_version = u16::from_le_bytes(buf2);
        
        f.seek(SeekFrom::Start(0x1f1))?;
        let mut buf1 = [0u8; 1]; f.read_exact(&mut buf1)?;
        let setup_sects = if buf1[0] == 0 { 4 } else { buf1[0] };
        
        f.seek(SeekFrom::Start(0x1f1))?;
        let mut setup_header = vec![0u8; 0x7f]; f.read_exact(&mut setup_header)?;
        
        let setup_end = (setup_sects as u64 + 1) * 512;
        f.seek(SeekFrom::End(0))?; let size = f.stream_position()?;
        f.seek(SeekFrom::Start(setup_end))?;
        let mut kernel = vec![0u8; (size - setup_end) as usize]; f.read_exact(&mut kernel)?;
        
        Ok(BzImage { setup_header, kernel, protocol_version })
    }
}

struct Kvm { fd: RawFd }
impl Kvm {
    fn new() -> std::io::Result<Self> { let f = OpenOptions::new().read(true).write(true).open("/dev/kvm")?; let fd = f.as_raw_fd(); std::mem::forget(f); Ok(Kvm { fd }) }
    fn api_version(&self) -> i32 { unsafe { libc::ioctl(self.fd, KVM_GET_API_VERSION, 0) } }
    fn create_vm(&self) -> std::io::Result<Vm> { let r = unsafe { libc::ioctl(self.fd, KVM_CREATE_VM, 0) }; if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(Vm { fd: r }) } }
    fn vcpu_mmap_size(&self) -> usize { unsafe { libc::ioctl(self.fd, KVM_GET_VCPU_MMAP_SIZE, 0) as usize } }
}
impl Drop for Kvm { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct Vm { fd: RawFd }
impl Vm {
    fn create_vcpu(&self, id: u64) -> std::io::Result<Vcpu> { let r = unsafe { libc::ioctl(self.fd, KVM_CREATE_VCPU, id) }; if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(Vcpu { fd: r }) } }
    fn set_memory(&self, slot: u32, addr: u64, size: u64, host: u64) -> std::io::Result<()> { let r = KvmUserspaceMemoryRegion { slot, flags: 0, guest_phys_addr: addr, memory_size: size, userspace_addr: host }; let ret = unsafe { libc::ioctl(self.fd, KVM_SET_USER_MEMORY_REGION, &r) }; if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) } }
}
impl Drop for Vm { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct Vcpu { fd: RawFd }
impl Vcpu {
    fn get_sregs(&self) -> KvmSregs { let mut s = KvmSregs::default(); unsafe { libc::ioctl(self.fd, KVM_GET_SREGS, &mut s) }; s }
    fn set_sregs(&self, s: &KvmSregs) { unsafe { libc::ioctl(self.fd, KVM_SET_SREGS, s) }; }
    fn get_regs(&self) -> KvmRegs { let mut r = KvmRegs::default(); unsafe { libc::ioctl(self.fd, KVM_GET_REGS, &mut r) }; r }
    fn set_regs(&self, r: &KvmRegs) { unsafe { libc::ioctl(self.fd, KVM_SET_REGS, r) }; }
    fn run(&self) { unsafe { libc::ioctl(self.fd, KVM_RUN, 0) }; }
    fn mmap_run(&self, sz: usize) -> *mut KvmRun { unsafe { libc::mmap(ptr::null_mut(), sz, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, self.fd, 0) as *mut KvmRun } }
}
impl Drop for Vcpu { fn drop(&mut self) { unsafe { libc::close(self.fd) }; } }

struct GuestMemory { ptr: *mut u8, size: usize }
impl GuestMemory {
    fn new(size: usize) -> std::io::Result<Self> { let p = unsafe { libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) }; if p == libc::MAP_FAILED { Err(std::io::Error::last_os_error()) } else { Ok(GuestMemory { ptr: p as *mut u8, size }) } }
    fn as_ptr(&self) -> *mut u8 { self.ptr }
    fn write_u8(&self, o: usize, v: u8) { unsafe { *self.ptr.add(o) = v; } }
    fn write_u16(&self, o: usize, v: u16) { unsafe { ptr::write_unaligned(self.ptr.add(o) as *mut u16, v); } }
    fn write_u32(&self, o: usize, v: u32) { unsafe { ptr::write_unaligned(self.ptr.add(o) as *mut u32, v); } }
    fn write_u64(&self, o: usize, v: u64) { unsafe { ptr::write_unaligned(self.ptr.add(o) as *mut u64, v); } }
    fn write(&self, o: usize, d: &[u8]) { unsafe { ptr::copy_nonoverlapping(d.as_ptr(), self.ptr.add(o), d.len()); } }
}
impl Drop for GuestMemory { fn drop(&mut self) { unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) }; } }

fn setup_page_tables(mem: &GuestMemory) {
    // PML4: entry 0 -> PDPT_LOW (identity map), entry 511 -> PDPT_HIGH (kernel high addresses)
    mem.write_u64(PML4_ADDR as usize, PDPT_LOW_ADDR | PTE_PRESENT | PTE_WRITABLE);
    mem.write_u64((PML4_ADDR + 511 * 8) as usize, PDPT_HIGH_ADDR | PTE_PRESENT | PTE_WRITABLE);
    
    // PDPT_LOW: entry 0 -> PD_LOW (first 1GB identity mapped)
    mem.write_u64(PDPT_LOW_ADDR as usize, PD_LOW_ADDR | PTE_PRESENT | PTE_WRITABLE);
    
    // PDPT_HIGH: entry 510 -> PD_HIGH (for 0xFFFFFFFF80000000 - kernel)
    // Entry 510 because: 0xFFFFFFFF80000000 >> 39 & 0x1FF = 510
    mem.write_u64((PDPT_HIGH_ADDR + 510 * 8) as usize, PD_HIGH_ADDR | PTE_PRESENT | PTE_WRITABLE);
    
    // PD_LOW: identity map first 1GB with 2MB pages
    for i in 0..512u64 {
        mem.write_u64((PD_LOW_ADDR + i * 8) as usize, (i * 0x200000) | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE);
    }
    
    // PD_HIGH: map to same physical addresses (kernel expects physical = virtual - 0xFFFFFFFF80000000)
    for i in 0..512u64 {
        mem.write_u64((PD_HIGH_ADDR + i * 8) as usize, (i * 0x200000) | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE);
    }
}

fn setup_gdt(mem: &GuestMemory) {
    mem.write_u64(BOOT_GDT_ADDR as usize, 0);
    mem.write_u64((BOOT_GDT_ADDR + 8) as usize, 0x00af9a000000ffff);
    mem.write_u64((BOOT_GDT_ADDR + 16) as usize, 0x00cf92000000ffff);
}

fn setup_zero_page(mem: &GuestMemory, hdr: &[u8], cmdline: &str, mem_size: u64) {
    let zp = ZERO_PAGE_ADDR as usize;
    for i in 0..4096 { mem.write_u8(zp + i, 0); }
    
    mem.write(zp + 0x1f1, hdr);
    mem.write_u8(zp + 0x210, 0xff);
    mem.write_u8(zp + 0x211, 0x81);
    mem.write_u16(zp + 0x224, 0xfe00);
    mem.write_u32(zp + 0x228, CMDLINE_ADDR as u32);
    
    mem.write(CMDLINE_ADDR as usize, cmdline.as_bytes());
    mem.write_u8(CMDLINE_ADDR as usize + cmdline.len(), 0);
    
    // E820 map
    let e = [
        E820Entry { addr: 0, size: 0x9fc00, type_: E820_RAM },
        E820Entry { addr: 0x9fc00, size: 0x60400, type_: E820_RESERVED },
        E820Entry { addr: 0x100000, size: mem_size - 0x100000, type_: E820_RAM },
    ];
    for (i, entry) in e.iter().enumerate() {
        mem.write(zp + 0x2d0 + i * 20, unsafe { std::slice::from_raw_parts(entry as *const _ as *const u8, 20) });
    }
    mem.write_u8(zp + 0x1e8, e.len() as u8);
}

fn make_code_seg() -> KvmSegment { KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_CODE, type_: 11, present: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, ..Default::default() } }
fn make_data_seg() -> KvmSegment { KvmSegment { base: 0, limit: 0xffffffff, selector: GDT_KERNEL_DATA, type_: 3, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, ..Default::default() } }

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { eprintln!("Usage: {} <bzImage> [cmdline]", args[0]); return Ok(()); }
    let cmdline = args.get(2).map(|s| s.as_str()).unwrap_or("console=ttyS0 earlyprintk=serial,ttyS0,115200 nokaslr noapic nolapic");

    eprintln!("=== microvm-rs ===\n");

    let bzimage = BzImage::load(&args[1])?;
    eprintln!("✓ bzImage: v{}.{}, {} KB", bzimage.protocol_version >> 8, bzimage.protocol_version & 0xff, bzimage.kernel.len() / 1024);

    let kvm = Kvm::new()?;
    eprintln!("✓ KVM v{}", kvm.api_version());

    let vm = kvm.create_vm()?;
    let mem_size: usize = 128 << 20;
    let mem = GuestMemory::new(mem_size)?;
    vm.set_memory(0, 0, mem_size as u64, mem.as_ptr() as u64)?;
    eprintln!("✓ RAM: {} MB", mem_size >> 20);

    setup_page_tables(&mem);
    setup_gdt(&mem);
    eprintln!("✓ Page tables (low + high half)");

    mem.write(KERNEL_LOAD_ADDR as usize, &bzimage.kernel);
    setup_zero_page(&mem, &bzimage.setup_header, cmdline, mem_size as u64);
    eprintln!("✓ Kernel @ 0x{:x}, zero page @ 0x{:x}", KERNEL_LOAD_ADDR, ZERO_PAGE_ADDR);
    eprintln!("✓ cmdline: {}", cmdline);

    let vcpu = vm.create_vcpu(0)?;
    let kvm_run = vcpu.mmap_run(kvm.vcpu_mmap_size());

    let mut sregs = vcpu.get_sregs();
    sregs.cs = make_code_seg(); sregs.ds = make_data_seg(); sregs.es = make_data_seg();
    sregs.fs = make_data_seg(); sregs.gs = make_data_seg(); sregs.ss = make_data_seg();
    sregs.gdt.base = BOOT_GDT_ADDR; sregs.gdt.limit = 23;
    sregs.cr0 = CR0_PE | CR0_PG | (1<<1) | (1<<4) | (1<<5) | (1<<16); sregs.cr3 = PML4_ADDR; sregs.cr4 = CR4_PAE | (1<<9) | (1<<10); sregs.efer = EFER_LME | EFER_LMA;
    vcpu.set_sregs(&sregs);

    let mut regs = KvmRegs::default();
    regs.rip = KERNEL_LOAD_ADDR + 0x200; regs.rsi = ZERO_PAGE_ADDR; regs.rflags = 0x2;
    vcpu.set_regs(&regs);
    eprintln!("✓ vCPU: RIP=0x{:x}\n", regs.rip);

    let mut serial = Serial8250::new();
    eprintln!("━━━━━━━━━ BOOT ━━━━━━━━━");

    let mut exits = 0u64;
    loop {
        vcpu.run();
        let reason = unsafe { (*kvm_run).exit_reason };
        exits += 1;

        match reason {
            KVM_EXIT_IO => {
                let io = unsafe { &*((&(*kvm_run)._union) as *const _ as *const KvmRunExitIo) };
                let dp = unsafe { (kvm_run as *mut u8).add(io.data_offset as usize) };
                eprintln!("IO 0x{:x}", io.port); if io.port >= COM1_PORT && io.port < COM1_PORT + 8 {
                    serial.handle(io.port, io.direction == KVM_EXIT_IO_OUT, unsafe { &mut *dp });
                }
            }
            KVM_EXIT_HLT => { let r = vcpu.get_regs(); eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━"); eprintln!("HLT @ 0x{:x} ({} exits)", r.rip, exits); break; }
            KVM_EXIT_SHUTDOWN => { let r = vcpu.get_regs(); eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━"); eprintln!("SHUTDOWN @ 0x{:x} ({} exits)", r.rip, exits); break; }
            KVM_EXIT_MMIO => { eprintln!("MMIO"); }
            _ => { eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━"); eprintln!("Exit {} ({} exits)", reason, exits); break; }
        }
        if exits > 100_000_000 { eprintln!("\nLimit"); break; }
    }
    Ok(())
}
