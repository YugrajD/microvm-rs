use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

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
const KVM_SET_CPUID2: libc::c_ulong = 0x4008AE90;
const KVM_GET_SUPPORTED_CPUID: libc::c_ulong = 0xC008AE05;

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

const ZERO_PAGE_ADDR: u64 = 0x7000;
const CMDLINE_ADDR: u64 = 0x20000;
const KERNEL_LOAD_ADDR: u64 = 0x100000;
const PML4_ADDR: u64 = 0x1000;
const PDPT_LOW_ADDR: u64 = 0x2000;
const PD_LOW_ADDR: u64 = 0x3000;
const PDPT_HIGH_ADDR: u64 = 0x4000;
const PD_HIGH_ADDR: u64 = 0x5000;
const BOOT_GDT_ADDR: u64 = 0x500;

const PTE_P: u64 = 1; const PTE_W: u64 = 2; const PTE_PS: u64 = 0x80;
const GDT_CODE: u16 = 8; const GDT_DATA: u16 = 16;
const COM1: u16 = 0x3f8;
const E820_RAM: u32 = 1; const E820_RESERVED: u32 = 2;

#[repr(C)] struct MemRegion { slot: u32, flags: u32, gpa: u64, size: u64, hva: u64 }
#[repr(C, packed)] #[derive(Copy, Clone)] struct CpuidEntry { function: u32, index: u32, flags: u32, eax: u32, ebx: u32, ecx: u32, edx: u32, _pad: [u32; 3] }
#[repr(C)] struct Cpuid2 { nent: u32, _pad: u32, entries: [CpuidEntry; 100] }
#[repr(C)] #[derive(Default, Copy, Clone)] struct Seg { base: u64, limit: u32, sel: u16, ty: u8, p: u8, dpl: u8, db: u8, s: u8, l: u8, g: u8, avl: u8, un: u8, _p: u8 }
#[repr(C)] #[derive(Default, Copy, Clone)] struct Dtable { base: u64, limit: u16, _p: [u16;3] }
#[repr(C)] #[derive(Default)] struct Sregs { cs: Seg, ds: Seg, es: Seg, fs: Seg, gs: Seg, ss: Seg, tr: Seg, ldt: Seg, gdt: Dtable, idt: Dtable, cr0: u64, cr2: u64, cr3: u64, cr4: u64, cr8: u64, efer: u64, apic_base: u64, int_bmp: [u64;4] }
#[repr(C)] #[derive(Default)] struct Regs { rax: u64, rbx: u64, rcx: u64, rdx: u64, rsi: u64, rdi: u64, rsp: u64, rbp: u64, r8: u64, r9: u64, r10: u64, r11: u64, r12: u64, r13: u64, r14: u64, r15: u64, rip: u64, rflags: u64 }
#[repr(C)] struct KvmRun { _h: [u8; 8], exit_reason: u32, _h2: [u8; 20], io: KvmIo }
#[repr(C)] struct KvmIo { dir: u8, sz: u8, port: u16, cnt: u32, off: u64 }
#[repr(C, packed)] #[derive(Default, Copy, Clone)] struct E820 { addr: u64, size: u64, ty: u32 }

struct Serial { lcr: u8, lsr: u8 }
impl Serial {
    fn new() -> Self { Serial { lcr: 0, lsr: 0x60 } }
    fn io(&mut self, port: u16, wr: bool, d: &mut u8) {
        let off = port - COM1;
        if wr {
            match off { 0 => if self.lcr & 0x80 == 0 { print!("{}", *d as char); let _ = std::io::stdout().flush(); }, 3 => self.lcr = *d, _ => {} }
        } else {
            *d = match off { 3 => self.lcr, 5 => self.lsr, _ => 0 };
        }
    }
}

struct Mem { p: *mut u8, sz: usize }
impl Mem {
    fn new(sz: usize) -> Self { let p = unsafe { libc::mmap(std::ptr::null_mut(), sz, 3, 0x22, -1, 0) }; Mem { p: p as *mut u8, sz } }
    fn w8(&self, o: usize, v: u8) { unsafe { *self.p.add(o) = v; } }
    fn w16(&self, o: usize, v: u16) { unsafe { ptr::write_unaligned(self.p.add(o) as *mut u16, v); } }
    fn w32(&self, o: usize, v: u32) { unsafe { ptr::write_unaligned(self.p.add(o) as *mut u32, v); } }
    fn w64(&self, o: usize, v: u64) { unsafe { ptr::write_unaligned(self.p.add(o) as *mut u64, v); } }
    fn write(&self, o: usize, d: &[u8]) { unsafe { ptr::copy_nonoverlapping(d.as_ptr(), self.p.add(o), d.len()); } }
}
impl Drop for Mem { fn drop(&mut self) { unsafe { libc::munmap(self.p as _, self.sz) }; } }

fn setup_pt(m: &Mem) {
    m.w64(PML4_ADDR as usize, PDPT_LOW_ADDR | PTE_P | PTE_W);
    m.w64((PML4_ADDR + 511*8) as usize, PDPT_HIGH_ADDR | PTE_P | PTE_W);
    m.w64(PDPT_LOW_ADDR as usize, PD_LOW_ADDR | PTE_P | PTE_W);
    m.w64((PDPT_HIGH_ADDR + 510*8) as usize, PD_HIGH_ADDR | PTE_P | PTE_W);
    for i in 0..512u64 { m.w64((PD_LOW_ADDR + i*8) as usize, (i * 0x200000) | PTE_P | PTE_W | PTE_PS); }
    for i in 0..512u64 { m.w64((PD_HIGH_ADDR + i*8) as usize, (i * 0x200000) | PTE_P | PTE_W | PTE_PS); }
}

fn setup_gdt(m: &Mem) {
    m.w64(BOOT_GDT_ADDR as usize, 0);
    m.w64((BOOT_GDT_ADDR + 8) as usize, 0x00af9a000000ffff);
    m.w64((BOOT_GDT_ADDR + 16) as usize, 0x00cf92000000ffff);
}

fn setup_zp(m: &Mem, hdr: &[u8], cmd: &str, msz: u64) {
    let zp = ZERO_PAGE_ADDR as usize;
    for i in 0..4096 { m.w8(zp + i, 0); }
    m.write(zp + 0x1f1, hdr);
    m.w8(zp + 0x210, 0xff);
    m.w8(zp + 0x211, 0x81);
    m.w16(zp + 0x224, 0xfe00);
    m.w32(zp + 0x228, CMDLINE_ADDR as u32);
    m.write(CMDLINE_ADDR as usize, cmd.as_bytes());
    m.w8(CMDLINE_ADDR as usize + cmd.len(), 0);
    let e = [E820 { addr: 0, size: 0x9fc00, ty: E820_RAM }, E820 { addr: 0x9fc00, size: 0x60400, ty: E820_RESERVED }, E820 { addr: 0x100000, size: msz - 0x100000, ty: E820_RAM }];
    for (i, x) in e.iter().enumerate() { m.write(zp + 0x2d0 + i*20, unsafe { std::slice::from_raw_parts(x as *const _ as *const u8, 20) }); }
    m.w8(zp + 0x1e8, e.len() as u8);
}

fn load_bz(path: &str) -> std::io::Result<(Vec<u8>, Vec<u8>, u16)> {
    let mut f = File::open(path)?;
    let mut b2 = [0u8;2]; let mut b4 = [0u8;4];
    f.seek(SeekFrom::Start(0x1fe))?; f.read_exact(&mut b2)?;
    if u16::from_le_bytes(b2) != 0xAA55 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "boot")); }
    f.seek(SeekFrom::Start(0x202))?; f.read_exact(&mut b4)?;
    if u32::from_le_bytes(b4) != 0x53726448 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "hdr")); }
    f.seek(SeekFrom::Start(0x206))?; f.read_exact(&mut b2)?;
    let ver = u16::from_le_bytes(b2);
    f.seek(SeekFrom::Start(0x1f1))?;
    let mut b1 = [0u8;1]; f.read_exact(&mut b1)?;
    let ss = if b1[0] == 0 { 4 } else { b1[0] };
    f.seek(SeekFrom::Start(0x1f1))?;
    let mut hdr = vec![0u8; 0x7f]; f.read_exact(&mut hdr)?;
    let se = (ss as u64 + 1) * 512;
    f.seek(SeekFrom::End(0))?; let sz = f.stream_position()?;
    f.seek(SeekFrom::Start(se))?;
    let mut k = vec![0u8; (sz - se) as usize]; f.read_exact(&mut k)?;
    Ok((hdr, k, ver))
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { eprintln!("Usage: {} <bzImage>", args[0]); return Ok(()); }
    let cmd = args.get(2).map(|s| s.as_str()).unwrap_or("console=ttyS0 earlyprintk=serial nokaslr noapic nolapic tsc=reliable no_timer_check");

    eprintln!("=== microvm-rs ===\n");
    let (hdr, kernel, ver) = load_bz(&args[1])?;
    eprintln!("✓ bzImage v{}.{}, {} KB", ver >> 8, ver & 0xff, kernel.len() / 1024);

    let kvm_fd = unsafe { libc::open(b"/dev/kvm\0".as_ptr() as _, 2) };
    eprintln!("✓ KVM");

    let vm_fd = unsafe { libc::ioctl(kvm_fd, KVM_CREATE_VM, 0) };
    let msz: usize = 256 << 20;
    let mem = Mem::new(msz);
    let mr = MemRegion { slot: 0, flags: 0, gpa: 0, size: msz as u64, hva: mem.p as u64 };
    unsafe { libc::ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mr) };
    eprintln!("✓ RAM: {} MB", msz >> 20);

    setup_pt(&mem);
    setup_gdt(&mem);
    mem.write(KERNEL_LOAD_ADDR as usize, &kernel);
    setup_zp(&mem, &hdr, cmd, msz as u64);
    eprintln!("✓ Kernel loaded");
    eprintln!("✓ cmdline: {}", cmd);

    let vcpu_fd = unsafe { libc::ioctl(vm_fd, KVM_CREATE_VCPU, 0) };
    let run_sz = unsafe { libc::ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0) } as usize;
    let run = unsafe { libc::mmap(std::ptr::null_mut(), run_sz, 3, 1, vcpu_fd, 0) } as *mut KvmRun;

    // Setup CPUID from host
    let mut cpuid = Cpuid2 { nent: 100, _pad: 0, entries: [CpuidEntry { function: 0, index: 0, flags: 0, eax: 0, ebx: 0, ecx: 0, edx: 0, _pad: [0;3] }; 100] };
    unsafe { libc::ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &mut cpuid) };
    unsafe { libc::ioctl(vcpu_fd, KVM_SET_CPUID2, &cpuid) };
    eprintln!("✓ CPUID ({} entries)", cpuid.nent);

    let mut sregs = Sregs::default();
    unsafe { libc::ioctl(vcpu_fd, KVM_GET_SREGS, &mut sregs) };
    sregs.cs = Seg { base: 0, limit: 0xffffffff, sel: GDT_CODE, ty: 11, p: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, ..Default::default() };
    sregs.ds = Seg { base: 0, limit: 0xffffffff, sel: GDT_DATA, ty: 3, p: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, ..Default::default() };
    sregs.es = sregs.ds; sregs.fs = sregs.ds; sregs.gs = sregs.ds; sregs.ss = sregs.ds;
    sregs.gdt = Dtable { base: BOOT_GDT_ADDR, limit: 23, _p: [0;3] };
    sregs.cr0 = CR0_PE | CR0_PG | (1<<1) | (1<<4) | (1<<5) | (1<<16);
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_PAE | (1<<9) | (1<<10);
    sregs.efer = EFER_LME | EFER_LMA;
    unsafe { libc::ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) };

    let mut regs = Regs::default();
    regs.rip = KERNEL_LOAD_ADDR + 0x200;
    regs.rsi = ZERO_PAGE_ADDR;
    regs.rflags = 2;
    unsafe { libc::ioctl(vcpu_fd, KVM_SET_REGS, &regs) };
    eprintln!("✓ vCPU ready\n");

    eprintln!("━━━━━━━━━ BOOT ━━━━━━━━━\n");

    let mut serial = Serial::new();
    let mut exits = 0u64;
    loop {
        unsafe { libc::ioctl(vcpu_fd, KVM_RUN, 0) };
        let reason = unsafe { (*run).exit_reason };
        exits += 1;

        match reason {
            KVM_EXIT_IO => {
                let io = unsafe { &(*run).io };
                let dp = unsafe { (run as *mut u8).add(io.off as usize) };
                if io.port >= COM1 && io.port < COM1 + 8 {
                    serial.io(io.port, io.dir == KVM_EXIT_IO_OUT, unsafe { &mut *dp });
                }
            }
            KVM_EXIT_HLT => { eprintln!("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━"); eprintln!("HLT ({} exits)", exits); break; }
            KVM_EXIT_SHUTDOWN => { 
                let mut r = Regs::default();
                unsafe { libc::ioctl(vcpu_fd, KVM_GET_REGS, &mut r) };
                eprintln!("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━"); 
                eprintln!("SHUTDOWN @ 0x{:x} ({} exits)", r.rip, exits); 
                break; 
            }
            KVM_EXIT_MMIO => {}
            _ => { eprintln!("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━"); eprintln!("Exit {} ({} exits)", reason, exits); break; }
        }
        if exits > 500_000_000 { eprintln!("\nLimit"); break; }
    }
    Ok(())
}
