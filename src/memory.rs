use crate::{
    sel4::{
        next_slot, next_slots, untyped_retype,
        x86::{
            self, page_directory_map, page_table_map, pdpt_map, PAGE_DIRECTORY_OBJECT,
            PAGE_TABLE_OBJECT, PAGE_TABLE_SIZE, PDPT_OBJECT, X86_4K,
        },
        CapRights, Empty, Sel4Error, SlotPos, UntypedDesc, Word, CNODE, PAGE_SIZE, UNTYPED_CAPS,
        VMATTR, VSPACE,
    },
    sys,
};

#[derive(Debug)]
pub struct Untyped {
    pub untyped_start: usize,
    pub untyped: [UntypedDesc; UNTYPED_CAPS],
    pub used_size: [usize; UNTYPED_CAPS],
}

impl Untyped {
    pub fn new(untyped_start: usize, untyped: &[sys::seL4_UntypedDesc; UNTYPED_CAPS]) -> Self {
        let mut untyped_arr = core::array::from_fn(|_| UntypedDesc::default());

        for (i, descr) in untyped.iter().enumerate() {
            untyped_arr[i] = UntypedDesc {
                paddr: descr.paddr as Word,
                size_bits: descr.sizeBits,
                is_device: descr.isDevice != 0,
                padding: descr.padding,
            }
        }

        Self {
            untyped_start,
            untyped: untyped_arr,
            used_size: [0; UNTYPED_CAPS],
        }
    }

    pub fn find_untyped(&mut self, needed_size: Word) -> Result<SlotPos, Sel4Error> {
        let needed_size = needed_size.next_multiple_of(PAGE_SIZE);

        for (cur_slot, cur_descr) in self.untyped.iter().enumerate() {
            if cur_descr.is_device {
                continue;
            }

            let cur_size: Word = 1 << cur_descr.size_bits;

            if cur_size - self.used_size[cur_slot] < needed_size {
                continue;
            }

            self.used_size[cur_slot] += needed_size;
            return Ok(cur_slot + self.untyped_start);
        }

        Err(Sel4Error::Other)
    }

    pub fn find_untyped_dev(
        &mut self,
        phys_addr: Word,
    ) -> Result<(SlotPos, UntypedDesc), Sel4Error> {
        for (cur_slot, cur_descr) in self.untyped.iter().enumerate() {
            if !cur_descr.is_device {
                continue;
            }

            let size: Word = 1 << cur_descr.size_bits;
            let addr_start: Word = cur_descr.paddr;
            let addr_end: Word = addr_start + size;

            if phys_addr >= addr_start && phys_addr < addr_end {
                self.used_size[cur_slot] += PAGE_SIZE;
                return Ok((cur_slot + self.untyped_start, *cur_descr));
            }
        }

        Err(Sel4Error::Other)
    }
}

pub struct MemoryManager {
    pub cur_vaddr: usize,
    pub max_vaddr: usize,
}

pub fn map_new_pt(untyped: &mut Untyped, slot: Word, virt_addr: usize) {
    let table_slot: SlotPos = untyped
        .find_untyped(PAGE_SIZE * 1024)
        .map_err(|e| ("Could not find untyped for pagetable map", e))
        .unwrap();

    untyped_retype(table_slot, x86::PAGE_TABLE_OBJECT, 0, CNODE, 0, 0, slot, 1)
        .map_err(|e| ("untyped_retype failed", e))
        .unwrap();

    x86::page_table_map(slot, VSPACE, virt_addr, VMATTR)
        .map_err(|e| ("Error mapping page table level 2", e))
        .unwrap();
}

pub fn map_pagetables(
    virt_addr: Word,
    empty: &mut Empty,
    untyped: &mut Untyped,
) -> Result<(), (&'static str, Sel4Error)> {
    let slots = next_slots::<3>(empty);

    let table_slot: SlotPos = untyped
        .find_untyped(PAGE_SIZE * 1024)
        .map_err(|e| ("Could not find untyped for pagetable map", e))?;

    /* Level 0 PML4 */
    // already mapped for us by seL4 during root task creation

    /* Level 1 PDPT */
    untyped_retype(table_slot, PDPT_OBJECT, 0, CNODE, 0, 0, slots[0], 1)
        .map_err(|e| ("untyped_retype failed", e))?;

    if let Err(e) = pdpt_map(slots[0], VSPACE, virt_addr, VMATTR) {
        return Err(("Error mapping page table level 0", e));
    }

    /* Level 2 PDT */
    untyped_retype(
        table_slot,
        PAGE_DIRECTORY_OBJECT,
        0,
        CNODE,
        0,
        0,
        slots[1],
        1,
    )
    .map_err(|e| ("untyped_retype failed", e))?;

    if let Err(e) = page_directory_map(slots[1], VSPACE, virt_addr, VMATTR) {
        return Err(("Error mapping page table level 1", e));
    }

    /* Level 3 PT */
    untyped_retype(table_slot, PAGE_TABLE_OBJECT, 0, CNODE, 0, 0, slots[2], 1)
        .map_err(|e| ("untyped_retype failed", e))?;

    if let Err(e) = page_table_map(slots[2], VSPACE, virt_addr, VMATTR) {
        return Err(("Error mapping page table level 2", e));
    }

    Ok(())
}

pub fn handle_pagetable_end(
    allocator: &mut MemoryManager,
    untyped: &mut Untyped,
    empty: &mut Empty,
) {
    if allocator.cur_vaddr >= allocator.max_vaddr {
        // We only ever increment allocator.cur_vaddr in 4k pages
        // so if we go beyond max_vaddr by some other distance thats a bug
        debug_assert!(allocator.cur_vaddr == allocator.max_vaddr);

        // Map the new page table which makes another 2Mib usable
        map_new_pt(untyped, next_slot(empty), allocator.cur_vaddr);
        allocator.max_vaddr += PAGE_TABLE_SIZE;
    }
}

pub fn map_dev_page(
    untyped_range: SlotPos,
    empty: &mut Empty,
    untyped: &mut Untyped,
    mem_manager: &mut MemoryManager,
) {
    let page_slot = next_slot(empty);

    // First convert untyped to "frame object"
    untyped_retype(untyped_range, X86_4K, 0, CNODE, 0, 0, page_slot, 1)
        .expect("Error retyping untyped memory");

    // Then map that "frame object" as a page
    let all_rights = CapRights::new(true, true, true, true);
    x86::page_map(page_slot, VSPACE, mem_manager.cur_vaddr, all_rights, VMATTR)
        .expect("Error mapping page");

    mem_manager.cur_vaddr += PAGE_SIZE;

    // One page table can keep up to 2MB in pages
    // If we try to allocate pages further than that we get a fault
    // So check whether thats the case and consecutively map another page table
    handle_pagetable_end(mem_manager, untyped, empty);
}

pub fn map_dev_range(
    phys_addr: Word,
    num_pages: Word,
    empty: &mut Empty,
    untyped: &mut Untyped,
    mem_manager: &mut MemoryManager,
) -> Result<usize, Sel4Error> {
    // Find untyed range that contains the physical address
    let (untyped_range, descr) = untyped
        .find_untyped_dev(phys_addr)
        .expect("Could not find untyped device memory");

    // Advance the range until we arrive at the address
    let mut start_paddr = descr.paddr;
    while start_paddr < phys_addr {
        untyped_retype(untyped_range, X86_4K, 0, CNODE, 0, 0, next_slot(empty), 1)
            .expect("Error advancing untyped range");

        start_paddr += 4096;
    }

    let start_vaddr = mem_manager.cur_vaddr;

    // Allocate the pages
    for _ in 0..num_pages {
        map_dev_page(untyped_range, empty, untyped, mem_manager);
    }

    Ok(start_vaddr)
}
