use std::arch::asm;

fn cmos_read(offset: u8) -> u8 {
    let val: u8;
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0x70u16,
            in("al") offset,
            options(nomem, nostack),
        );
        asm!(
            "in al, dx",
            in("dx") 0x71u16,
            out("al") val,
            options(nomem, nostack),
        );
    }
    val
}

fn cmos_write(offset: u8, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0x70u16,
            in("al") offset,
            options(nomem, nostack),
        );
        asm!(
            "out dx, al",
            in("dx") 0x71u16,
            in("al") value,
            options(nomem, nostack),
        );
    }
}

fn main() {
    println!("=== CMOS Freeze Diagnostic Reader ===\n");

    let magic = cmos_read(0x40);
    if magic != 0xDE {
        println!("[!] No freeze data found (magic=0x{:02x}, expected 0xDE)", magic);
        println!("    Either no freeze occurred, or CMOS was cleared.");
        return;
    }

    println!("[+] Freeze data FOUND in CMOS!\n");

    let cpu1 = cmos_read(0x41);
    let mut rip1: u64 = 0;
    for b in 0..8u8 {
        rip1 |= (cmos_read(0x42 + b) as u64) << (b * 8);
    }
    let stuck_lo = cmos_read(0x4A) as u16;
    let stuck_hi = cmos_read(0x4B) as u16;
    let stuck_count = stuck_lo | (stuck_hi << 8);
    let total_stuck = cmos_read(0x4C);

    let cpu2 = cmos_read(0x4D);
    let mut rip2: u64 = 0;
    for b in 0..8u8 {
        rip2 |= (cmos_read(0x4E + b) as u64) << (b * 8);
    }

    println!("  Most-stuck CPU:    #{}", cpu1);
    println!("  Stuck RIP:         {:#018x}", rip1);
    println!("  Stuck count:       {} (~{:.1}s)", stuck_count, stuck_count as f64 * 0.05);
    println!("  Total stuck CPUs:  {} (count > 50)", total_stuck);
    println!();
    println!("  Second CPU:        #{}", cpu2);
    println!("  Second RIP:        {:#018x}", rip2);
    println!();

    if rip1 >> 47 == 0x1FFFF {
        println!("  [i] RIP is in KERNEL space (KVAS high half)");
        println!("      Use 'ln {:#x}' in WinDbg or check ntoskrnl symbols", rip1);
    } else if rip1 >> 47 == 0 {
        println!("  [i] RIP is in USER space");
    }

    if rip1 == rip2 && cpu1 != cpu2 {
        println!("  [!] BOTH CPUs stuck at SAME address — likely spinlock deadlock!");
    }

    // Clear CMOS data after reading
    println!("\n  Clearing CMOS freeze data...");
    cmos_write(0x40, 0x00);
    println!("  Done. Run again after next freeze to read new data.");
}
