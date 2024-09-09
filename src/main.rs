#![no_std]
#![no_main]

#[macro_use]
mod sel4;
mod debug;
mod memory;
mod sys;

use core::arch::global_asm;

use memory::{map_dev_range, map_pagetables, MemoryManager, Untyped};
use sel4::x86::PAGE_TABLE_SIZE;
use sel4::{Empty, IpcBuffer, MessageInfo, Word, IPC_BUFFER, PAGE_SIZE};

// Define small, static stack
global_asm! {
r#"
    .section .bss
    .align 4096
        _stack_bottom:
        .space 524288 // 512K
        _stack_top:
"#
}

// Define bootstrapping code executed at elf entry
// Usually rust would do that for us but it can't know what setup we want
global_asm! {
r#"
    .section .text

    .global _start
    _start:
        // Bootinfo pointer was put in rdi

        // Setup stack
        lea rsp, _stack_top
        mov rbp, rsp
        push rbp

        // 16-byte align stack pointer (required before calling a function)
        and rsp, 0xFFFFFFFFFFFFFFF0

        call entry

        // Infinite loop in case we return for some reason
        loop: jmp loop
"#
}

// Called from global_asm
#[no_mangle]
extern "C" fn entry(bootinfo: *mut sys::seL4_BootInfo) {
    unsafe { IPC_BUFFER = (*bootinfo).ipcBuffer as *mut IpcBuffer }

    let mut empty = unsafe {
        Empty {
            start: (*bootinfo).empty.start as Word,
            end: (*bootinfo).empty.end as Word,
            current_slot_pos: 0,
        }
    };

    let mut untyped =
        unsafe { Untyped::new((*bootinfo).untyped.start as usize, &(*bootinfo).untypedList) };

    const VIRT_BASE_ADDR: usize = 0x8000000000;
    map_pagetables(VIRT_BASE_ADDR, &mut empty, &mut untyped).unwrap();

    let mut mem_manager = MemoryManager {
        cur_vaddr: VIRT_BASE_ADDR,
        max_vaddr: VIRT_BASE_ADDR + PAGE_TABLE_SIZE,
    };

    main(&mut empty, &mut untyped, &mut mem_manager);
}

// Called from entry
fn main(empty: &mut Empty, untyped: &mut Untyped, mem_manager: &mut MemoryManager) {
    // Qemu defaults for bochs-display figured out by counting pixels
    const WIDTH: usize = 1280;
    const HEIGHT: usize = 800;
    const BYTES_PER_PIXEL: usize = 4;

    const FRAMEBUFFER_NUM_PAGES: usize =
        (WIDTH * HEIGHT * BYTES_PER_PIXEL).next_multiple_of(4096) / PAGE_SIZE;

    // Framebuffer address is normally discovered through the pci subsytem but we don't deal with that here
    // Can be found using the "info pci" command when inside qemu monitor (Ctrl-x + c in stdout or sometimes under "View" in the qemu window)
    const FRAMEBUFFER_PADDR: usize = 0xfe400000;

    let framebuffer = map_dev_range(
        FRAMEBUFFER_PADDR,
        FRAMEBUFFER_NUM_PAGES,
        empty,
        untyped,
        mem_manager,
    )
    .unwrap();

    let mut hue = 0.0;

    loop {
        let color = next_color(&mut hue);

        fill_screen(framebuffer as *mut u32, WIDTH * HEIGHT, color);
    }
}

fn fill_screen(fb: *mut u32, num_pixels: usize, color: u32) {
    for i in 0..num_pixels {
        unsafe { *fb.add(i) = color };
    }
}

pub fn next_color(hue: &mut f64) -> u32 {
    if *hue >= 359.0 {
        *hue = 0.0;
    }

    *hue += 0.01;

    let (r, g, b) = hsv_to_rgb(*hue, 1.0, 1.0);
    let (r, g, b) = (r as u32, b as u32, g as u32);

    let mut color = 0;
    color |= b << 0;
    color |= g << 8;
    color |= r << 16;

    color
}

// Adapted from https://docs.rs/hsv/0.1.1/src/hsv/lib.rs.html#33-64
// (For some reason no-std rust does not appear to have f64::abs ???)
pub fn hsv_to_rgb(hue: f64, saturation: f64, value: f64) -> (u8, u8, u8) {
    fn is_between(value: f64, min: f64, max: f64) -> bool {
        min <= value && value < max
    }

    fn abs(this: f64) -> f64 {
        if this.is_sign_negative() {
            -this
        } else {
            this
        }
    }

    check_bounds(hue, saturation, value);

    let c = value * saturation;
    let h = hue / 60.0;
    let x = c * (1.0 - abs((h % 2.0) - 1.0));
    let m = value - c;

    let (r, g, b): (f64, f64, f64) = if is_between(h, 0.0, 1.0) {
        (c, x, 0.0)
    } else if is_between(h, 1.0, 2.0) {
        (x, c, 0.0)
    } else if is_between(h, 2.0, 3.0) {
        (0.0, c, x)
    } else if is_between(h, 3.0, 4.0) {
        (0.0, x, c)
    } else if is_between(h, 4.0, 5.0) {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

fn check_bounds(hue: f64, saturation: f64, value: f64) {
    fn panic_bad_params(name: &str, from_value: &str, to_value: &str, supplied: f64) -> ! {
        panic!(
            "param {} must be between {} and {} inclusive; was: {}",
            name, from_value, to_value, supplied
        )
    }

    if !(0.0..=360.0).contains(&hue) {
        panic_bad_params("hue", "0.0", "360.0", hue)
    } else if !(0.0..=1.0).contains(&saturation) {
        panic_bad_params("saturation", "0.0", "1.0", saturation)
    } else if !(0.0..=1.0).contains(&value) {
        panic_bad_params("value", "0.0", "1.0", value)
    }
}

#[panic_handler]
pub fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    debug::println!();
    debug::println!("-- ROOT TASK PANICKED --");
    debug::println!("{info}");
    debug::println!("-- ROOT TASK PANICKED --");
    debug::println!();

    loop {}
}
