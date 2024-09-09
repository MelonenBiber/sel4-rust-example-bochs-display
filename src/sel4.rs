use core::alloc::Layout;

use crate::sys;

pub const CNODE: SlotPos = sys::seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as Word;
pub const VSPACE: SlotPos = sys::seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace as Word;
pub const VMATTR: Word = sys::seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes as Word;

pub const PAGE_SIZE: Word = 1 << sys::seL4_PageBits;

pub const UNTYPED_CAPS: Word = sys::CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS as Word;

const _: () = assert!(size_of::<usize>() == size_of::<sys::seL4_Word>());
const _: () = assert!(size_of::<u64>() == size_of::<sys::seL4_Word>());
const _: () = assert!(size_of::<Word>() == size_of::<sys::seL4_Word>());
pub type Word = usize;

const _: () = assert!(size_of::<CPtr>() == size_of::<sys::seL4_CPtr>());
pub type CPtr = Word;

const _: () = assert!(size_of::<SlotPos>() == size_of::<sys::seL4_SlotPos>());
pub type SlotPos = Word;

const _: () = assert!(size_of::<MessageInfo>() == size_of::<sys::seL4_MessageInfo>());
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct MessageInfo {
    pub data: Word,
}

impl MessageInfo {
    pub fn zero() -> Self {
        Self { data: 0 }
    }

    #[allow(clippy::identity_op)]
    pub fn new(label: u64, caps_unwrapped: u64, extra_caps: u64, length: u64) -> Self {
        let data: Word = 0
            | (label as usize & 0xfffffffffffff) << 12
            | (caps_unwrapped as usize & 0x7) << 9
            | (extra_caps as usize & 0x3) << 7
            | (length as usize & 0x7f);

        Self { data }
    }

    pub fn label(self) -> Word {
        ((self.data as i64) >> 12) as Word
    }

    pub fn length(self) -> u8 {
        (self.data & 0b01111111) as u8
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct UntypedDesc {
    pub paddr: Word,
    pub size_bits: u8,
    pub is_device: bool,
    pub padding: [u8; 6],
}

pub static mut IPC_BUFFER: *mut IpcBuffer = unsafe { core::mem::zeroed() };

const _: () = assert!(size_of::<IpcBuffer>() == size_of::<sys::seL4_IPCBuffer>());
const _: () =
    assert!(Layout::new::<IpcBuffer>().align() == Layout::new::<sys::seL4_IPCBuffer>().align());
const _: () =
    assert!(Layout::new::<IpcBuffer>().size() == Layout::new::<sys::seL4_IPCBuffer>().size());

#[repr(C)]
#[derive(Debug)]
pub struct IpcBuffer {
    pub tag: MessageInfo,
    pub msg: [Word; 120usize],
    pub user_data: Word,
    pub caps_or_badges: [Word; 3usize],
    pub receive_cnode: CPtr,
    pub receive_index: CPtr,
    pub receive_depth: Word,
}

pub fn set_cap(index: usize, cptr: Word) {
    unsafe {
        (*IPC_BUFFER).caps_or_badges[index] = cptr;
    }
}

pub fn set_mr(index: usize, mr: Word) {
    unsafe {
        (*IPC_BUFFER).msg[index] = mr;
    }
}

const _: () = assert!(sys::seL4_Error_seL4_NumErrors == 11);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sel4Error {
    InvalidArgument,
    InvalidCapability,
    IllegalOperation,
    RangeError,
    AlignmentError,
    FailedLookup,
    TruncatedMessage,
    DeleteFirst,
    RevokeFirst,
    NotEnoughMemory,
    // Not from seL4 but a custom error type
    Other,
}

pub fn wrap_err(err: Word) -> Result<(), Sel4Error> {
    match err {
        0 => Ok(()),
        _ => Err(Sel4Error::from_syscall(err)),
    }
}

impl Sel4Error {
    fn from_syscall(value: Word) -> Self {
        match value {
            1 => Sel4Error::InvalidArgument,
            2 => Sel4Error::InvalidCapability,
            3 => Sel4Error::IllegalOperation,
            4 => Sel4Error::RangeError,
            5 => Sel4Error::AlignmentError,
            6 => Sel4Error::FailedLookup,
            7 => Sel4Error::TruncatedMessage,
            8 => Sel4Error::DeleteFirst,
            9 => Sel4Error::RevokeFirst,
            10 => Sel4Error::NotEnoughMemory,
            x => panic!("Encountered unknown error type {x}"),
        }
    }
}

pub struct Empty {
    pub start: Word, /* first CNode slot position OF region */
    pub end: Word,   /* first CNode slot position AFTER region */
    pub current_slot_pos: Word,
}

#[must_use]
pub fn next_slots<const N: usize>(empty: &mut Empty) -> [SlotPos; N] {
    let mut slots = [0; N];

    if empty.current_slot_pos + N as Word >= empty.end {
        panic!("Could not get all slots.");
    }

    for slot in &mut slots {
        *slot = empty.current_slot_pos + empty.start;
        empty.current_slot_pos += 1;
    }

    slots
}

#[must_use]
pub fn next_slot(empty: &mut Empty) -> SlotPos {
    let next_slot = empty.start + empty.current_slot_pos as Word;

    if next_slot >= empty.end {
        panic!("Could not get next slot.");
    }

    empty.current_slot_pos += 1;
    next_slot as SlotPos
}

pub fn untyped_retype(
    service: Word,
    r#type: Word,
    size_bits: Word,
    root: Word,
    node_index: Word,
    node_depth: Word,
    node_offset: Word,
    num_objects: Word,
) -> Result<(), Sel4Error> {
    let tag = MessageInfo::new(InvocationLabel::UntypedRetype as u64, 0, 1, 6);

    set_cap(0, root);

    let mut mr0 = r#type;
    let mut mr1 = size_bits;
    let mut mr2 = node_index;
    let mut mr3 = node_depth;
    set_mr(4, node_offset);
    set_mr(5, num_objects);

    let output_tag = call_with_mrs(service, tag, &mut mr0, &mut mr1, &mut mr2, &mut mr3);
    let result = wrap_err(output_tag.label());

    if result.is_err() {
        set_mr(0, mr0);
        set_mr(1, mr1);
        set_mr(2, mr2);
        set_mr(3, mr3);
    }

    result
}

pub fn call_with_mrs(
    dest: Word,
    msg_info: MessageInfo,
    mr0: &mut Word,
    mr1: &mut Word,
    mr2: &mut Word,
    mr3: &mut Word,
) -> MessageInfo {
    let (out_info, _out_dest) =
        x86::sys_send_recv(Syscall::Call as isize, dest, msg_info, mr0, mr1, mr2, mr3);

    out_info
}

#[derive(Clone, Copy)]
pub struct CapRights {
    pub data: Word,
}

impl CapRights {
    #[allow(clippy::identity_op)]
    pub fn new(
        cap_allow_grant_reply: bool,
        cap_allow_grant: bool,
        cap_allow_read: bool,
        cap_allow_write: bool,
    ) -> Self {
        let data = (0
            | (cap_allow_grant_reply as Word) << 3
            | (cap_allow_grant as Word) << 2
            | (cap_allow_read as Word) << 1
            | (cap_allow_write as Word) << 0) as Word;

        Self { data }
    }
}

#[repr(isize)]
#[non_exhaustive]
#[allow(unused)]
#[rustfmt::skip]
enum Syscall {
    Call               = sys::seL4_Syscall_ID_seL4_SysCall               as isize,
    ReplyRecv          = sys::seL4_Syscall_ID_seL4_SysReplyRecv          as isize,
    Send               = sys::seL4_Syscall_ID_seL4_SysSend               as isize,
    NBSend             = sys::seL4_Syscall_ID_seL4_SysNBSend             as isize,
    Recv               = sys::seL4_Syscall_ID_seL4_SysRecv               as isize,
    Reply              = sys::seL4_Syscall_ID_seL4_SysReply              as isize,
    Yield              = sys::seL4_Syscall_ID_seL4_SysYield              as isize,
    NBRecv             = sys::seL4_Syscall_ID_seL4_SysNBRecv             as isize,
    DebugPutChar       = sys::seL4_Syscall_ID_seL4_SysDebugPutChar       as isize,
    DebugDumpScheduler = sys::seL4_Syscall_ID_seL4_SysDebugDumpScheduler as isize,
    DebugHalt          = sys::seL4_Syscall_ID_seL4_SysDebugHalt          as isize,
    DebugCapIdentify   = sys::seL4_Syscall_ID_seL4_SysDebugCapIdentify   as isize,
    DebugSnapshot      = sys::seL4_Syscall_ID_seL4_SysDebugSnapshot      as isize,
    DebugNameThread    = sys::seL4_Syscall_ID_seL4_SysDebugNameThread    as isize,
}

#[repr(isize)]
#[non_exhaustive]
#[allow(unused)]
#[rustfmt::skip]
pub enum InvocationLabel {
    InvalidInvocation        = sys::invocation_label_InvalidInvocation                as isize,
    UntypedRetype            = sys::invocation_label_UntypedRetype                    as isize,
    TcbReadRegisters         = sys::invocation_label_TCBReadRegisters                 as isize,
    TcbWriteRegisters        = sys::invocation_label_TCBWriteRegisters                as isize,
    TcbCopyRegisters         = sys::invocation_label_TCBCopyRegisters                 as isize,
    TcbConfigure             = sys::invocation_label_TCBConfigure                     as isize,
    TcbSetPriority           = sys::invocation_label_TCBSetPriority                   as isize,
    TcbSetMCPriority         = sys::invocation_label_TCBSetMCPriority                 as isize,
    TcbSetSchedParams        = sys::invocation_label_TCBSetSchedParams                as isize,
    TcbSetIpcBuffer          = sys::invocation_label_TCBSetIPCBuffer                  as isize,
    TcbSetSpace              = sys::invocation_label_TCBSetSpace                      as isize,
    TcbSuspend               = sys::invocation_label_TCBSuspend                       as isize,
    TcbResume                = sys::invocation_label_TCBResume                        as isize,
    TcbBindNotification      = sys::invocation_label_TCBBindNotification              as isize,
    TcbUnbindNotification    = sys::invocation_label_TCBUnbindNotification            as isize,
    TcbSetTLSBase            = sys::invocation_label_TCBSetTLSBase                    as isize,
    CnodeRevoke              = sys::invocation_label_CNodeRevoke                      as isize,
    CnodeDelete              = sys::invocation_label_CNodeDelete                      as isize,
    CnodeCancelBadgedSends   = sys::invocation_label_CNodeCancelBadgedSends           as isize,
    CnodeCopy                = sys::invocation_label_CNodeCopy                        as isize,
    CnodeMint                = sys::invocation_label_CNodeMint                        as isize,
    CnodeMove                = sys::invocation_label_CNodeMove                        as isize,
    CnodeMutate              = sys::invocation_label_CNodeMutate                      as isize,
    CnodeRotate              = sys::invocation_label_CNodeRotate                      as isize,
    CnodeSaveCaller          = sys::invocation_label_CNodeSaveCaller                  as isize,
    IrqIssueIrqHandler       = sys::invocation_label_IRQIssueIRQHandler               as isize,
    IrqAckIrq                = sys::invocation_label_IRQAckIRQ                        as isize,
    IrqSetIrqHandler         = sys::invocation_label_IRQSetIRQHandler                 as isize,
    IrqClearIrqHandler       = sys::invocation_label_IRQClearIRQHandler               as isize,
    DomainSetSet             = sys::invocation_label_DomainSetSet                     as isize,
    // X86 specific
    PdptMap                  = sys::sel4_arch_invocation_label_X86PDPTMap             as isize,
    PDPTUnmap                = sys::sel4_arch_invocation_label_X86PDPTUnmap           as isize,
    PageDirectoryMap         = sys::arch_invocation_label_X86PageDirectoryMap         as isize,
    PageDirectoryUnmap       = sys::arch_invocation_label_X86PageDirectoryUnmap       as isize,
    PageTableMap             = sys::arch_invocation_label_X86PageTableMap             as isize,
    PageTableUnmap           = sys::arch_invocation_label_X86PageTableUnmap           as isize,
    IoPageTableMap           = sys::arch_invocation_label_X86IOPageTableMap           as isize,
    IoPageTableUnmap         = sys::arch_invocation_label_X86IOPageTableUnmap         as isize,
    PageMap                  = sys::arch_invocation_label_X86PageMap                  as isize,
    PageUnmap                = sys::arch_invocation_label_X86PageUnmap                as isize,
    PageGetAddress           = sys::arch_invocation_label_X86PageGetAddress           as isize,
    AsidControlMakePool      = sys::arch_invocation_label_X86ASIDControlMakePool      as isize,
    AsidPoolAssign           = sys::arch_invocation_label_X86ASIDPoolAssign           as isize,
    IoPortControlIssue       = sys::arch_invocation_label_X86IOPortControlIssue       as isize,
    IoPortIn8                = sys::arch_invocation_label_X86IOPortIn8                as isize,
    IoPortIn16               = sys::arch_invocation_label_X86IOPortIn16               as isize,
    IoPortIn32               = sys::arch_invocation_label_X86IOPortIn32               as isize,
    IoPortOut8               = sys::arch_invocation_label_X86IOPortOut8               as isize,
    IoPortOut16              = sys::arch_invocation_label_X86IOPortOut16              as isize,
    IoPortOut32              = sys::arch_invocation_label_X86IOPortOut32              as isize,
    IrqIssueIrqHandlerIOAPIC = sys::arch_invocation_label_X86IRQIssueIRQHandlerIOAPIC as isize,
    IrqIssueIrqHandlerMSI    = sys::arch_invocation_label_X86IRQIssueIRQHandlerMSI    as isize,
}

pub mod x86 {
    pub type Pml4 = CPtr;
    pub type Pdpt = CPtr;
    pub type PageDirectory = CPtr;
    pub type PageTable = CPtr;

    pub type VmAttributes = Word;
    pub type Page = CPtr;

    pub const X86_4K: Word = sys::_object_seL4_X86_4K as Word;

    pub const PDPT_OBJECT: Word = sys::_mode_object_seL4_X86_PDPTObject as Word;
    pub const PAGE_DIRECTORY_OBJECT: Word = sys::_object_seL4_X86_PageDirectoryObject as Word;
    pub const PAGE_TABLE_OBJECT: Word = sys::_object_seL4_X86_PageTableObject as Word;

    pub const PAGE_TABLE_SIZE: Word = PAGE_SIZE * 512;

    use core::arch::asm;

    use crate::{
        sel4::{set_cap, set_mr, MessageInfo, PAGE_SIZE},
        sys,
    };

    use super::{call_with_mrs, wrap_err, CPtr, CapRights, InvocationLabel, Sel4Error, Word};

    pub fn pdpt_map(
        service: Pdpt,
        pml4: Pml4,
        vaddr: Word,
        attr: VmAttributes,
    ) -> Result<(), Sel4Error> {
        let tag = MessageInfo::new(InvocationLabel::PdptMap as u64, 0, 1, 2);

        set_cap(0, pml4);

        let mut mr0 = vaddr;
        let mut mr1 = attr;
        let mut mr2 = 0;
        let mut mr3 = 0;

        let output_tag = call_with_mrs(service, tag, &mut mr0, &mut mr1, &mut mr2, &mut mr3);
        let result = wrap_err(output_tag.label());

        if result.is_err() {
            set_mr(0, mr0);
            set_mr(1, mr1);
            set_mr(2, mr2);
            set_mr(3, mr3);
        }

        result
    }

    pub fn page_directory_map(
        service: PageDirectory,
        vspace: CPtr,
        vaddr: Word,
        attr: VmAttributes,
    ) -> Result<(), Sel4Error> {
        let tag = MessageInfo::new(InvocationLabel::PageDirectoryMap as u64, 0, 1, 2);

        set_cap(0, vspace);

        let mut mr0 = vaddr;
        let mut mr1 = attr;
        let mut mr2 = 0;
        let mut mr3 = 0;

        let output_tag = call_with_mrs(service, tag, &mut mr0, &mut mr1, &mut mr2, &mut mr3);
        let result = wrap_err(output_tag.label());

        if result.is_err() {
            set_mr(0, mr0);
            set_mr(1, mr1);
            set_mr(2, mr2);
            set_mr(3, mr3);
        }

        result
    }

    pub fn page_table_map(
        service: PageTable,
        vspace: CPtr,
        vaddr: Word,
        attr: VmAttributes,
    ) -> Result<(), Sel4Error> {
        let tag = MessageInfo::new(InvocationLabel::PageTableMap as u64, 0, 1, 2);

        set_cap(0, vspace);

        let mut mr0 = vaddr;
        let mut mr1 = attr;
        let mut mr2 = 0;
        let mut mr3 = 0;

        let output_tag = call_with_mrs(service, tag, &mut mr0, &mut mr1, &mut mr2, &mut mr3);
        let result = wrap_err(output_tag.label());

        if result.is_err() {
            set_mr(0, mr0);
            set_mr(1, mr1);
            set_mr(2, mr2);
            set_mr(3, mr3);
        }

        result
    }

    pub fn sys_send_recv(
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

    pub fn page_map(
        service: Page,
        vspace: CPtr,
        vaddr: Word,
        rights: CapRights,
        attr: VmAttributes,
    ) -> Result<(), Sel4Error> {
        let tag = MessageInfo::new(InvocationLabel::PageMap as u64, 0, 1, 3);

        set_cap(0, vspace);

        let mut mr0 = vaddr;
        let mut mr1 = rights.data;
        let mut mr2 = attr;
        let mut mr3 = 0;

        let output_tag = call_with_mrs(service, tag, &mut mr0, &mut mr1, &mut mr2, &mut mr3);
        let result = wrap_err(output_tag.label());

        if result.is_err() {
            set_mr(0, mr0);
            set_mr(1, mr1);
            set_mr(2, mr2);
            set_mr(3, mr3);
        }

        result
    }
}
