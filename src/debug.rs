use crate::{MessageInfo, Word};
use core::{arch::asm, fmt};

struct DebugWritePutChar;

const SYSCALL_DEBUG_PUTCHAR: isize = -9;

impl fmt::Write for DebugWritePutChar {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &c in s.as_bytes() {
            sys_send_recv_debug(
                SYSCALL_DEBUG_PUTCHAR,
                c as Word,
                MessageInfo::zero(),
                &mut 0,
                &mut 0,
                &mut 0,
                &mut 0,
            );
        }
        Ok(())
    }
}

// Copy of sys_send_recv so debug statements work in the lowest level functions
fn sys_send_recv_debug(
    sys: isize,
    dest: Word,
    info: MessageInfo,
    mr0: &mut Word,
    mr1: &mut Word,
    mr2: &mut Word,
    mr3: &mut Word,
) -> (MessageInfo, Word) {
    let out_info: Word;
    let out_badge: Word;

    unsafe {
        asm!(
            "mov r14, rsp",
            "syscall",
            "mov rsp, r14",

            in   ("rdx")  sys,
            inout("rdi")  dest => out_badge,
            inout("rsi")  info.data => out_info,

            inout("r10")  *mr0,
            inout("r8")   *mr1,
            inout("r9")   *mr2,
            inout("r15")  *mr3,

            lateout("rcx") _,
            lateout("r11") _,
            lateout("r14") _,
        );
    }

    (MessageInfo { data: out_info }, out_badge)
}

pub fn _debug_print_putchar(args: fmt::Arguments) {
    fmt::write(&mut DebugWritePutChar {}, args).unwrap();
}

macro_rules! print {
    ($($arg:tt)*) => ($crate::debug::_debug_print_putchar(format_args!($($arg)*)));
}

macro_rules! println {
               () => ($crate::debug::print!("\n"));
    ($($arg:tt)*) => ($crate::debug::print!("{}\n", format_args!($($arg)*)));
}

pub(crate) use print;
pub(crate) use println;

// Taken from https://github.com/smol-rs/fastrand/tree/7e60c7f688f9be3dcd4f59f216c87dac88ca2902
pub struct Rng(u64);
impl Rng {
    pub fn new() -> Self {
        Rng(0x4d595df4d0f33173)
    }

    pub fn gen_u64(&mut self) -> u64 {
        // Constants for WyRand taken from: https://github.com/wangyi-fudan/wyhash/blob/master/wyhash.h#L151
        // Updated for the final v4.2 implementation with improved constants for better entropy output.
        const WY_CONST_0: u64 = 0x2d35_8dcc_aa6c_78a5;
        const WY_CONST_1: u64 = 0x8bb8_4b93_962e_acc9;

        let s = self.0.wrapping_add(WY_CONST_0);
        self.0 = s;
        let t = u128::from(s) * u128::from(s ^ WY_CONST_1);
        (t as u64) ^ (t >> 64) as u64
    }
}
