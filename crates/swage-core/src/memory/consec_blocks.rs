use std::{collections::VecDeque, ops::Range};

use crate::memory::{BytePointer, GetConsecPfns};

use crate::memory::{Memory, PhysAddr, VictimMemory};

/// Collection of consecutive physical memory blocks.
///
/// This struct manages multiple [`Memory`] blocks that may or may not be physically
/// contiguous. It provides a unified interface for accessing memory across multiple
/// allocations while tracking physical address ranges.
#[derive(Clone, Debug)]
pub struct ConsecBlocks {
    /// Vector of memory blocks managed by this collection
    pub blocks: Vec<Memory>,
}

impl ConsecBlocks {
    /// Creates a new collection of consecutive memory blocks.
    ///
    /// # Arguments
    ///
    /// * `blocks` - Vector of memory blocks to manage
    pub fn new(blocks: Vec<Memory>) -> Self {
        ConsecBlocks { blocks }
    }

    /// Deallocates all memory blocks in this collection.
    ///
    /// Consumes self and frees all underlying memory allocations.
    pub fn dealloc(self) {
        for block in self.blocks {
            block.dealloc();
        }
    }
}

impl VictimMemory for ConsecBlocks {}

impl BytePointer for ConsecBlocks {
    fn addr(&self, offset: usize) -> *mut u8 {
        assert!(offset < self.len(), "Offset {} >= {}", offset, self.len());
        let mut offset = offset;
        for block in &self.blocks {
            if offset < block.len {
                return block.addr(offset);
            }
            offset -= block.len;
        }
        unreachable!("block not found for offset 0x{:x}", offset);
    }

    fn ptr(&self) -> *mut u8 {
        self.blocks.first().unwrap().ptr()
    }

    fn len(&self) -> usize {
        self.blocks.iter().map(|block| block.len).sum()
    }
}

impl GetConsecPfns for ConsecBlocks {
    fn consec_pfns(&self) -> Result<Vec<Range<PhysAddr>>, crate::memory::memblock::Error> {
        let mut pfns = vec![];
        for block in &self.blocks {
            let mut block_pfns = VecDeque::from(block.consec_pfns()?);
            let is_cons = pfns
                .last()
                .is_some_and(|last: &Range<PhysAddr>| last.start == block_pfns[0].end);
            if is_cons {
                let prev = pfns.pop();
                let next = block_pfns.pop_front();
                pfns.push(prev.unwrap().start..next.unwrap().end);
            }
            pfns.extend(block_pfns);
        }
        Ok(pfns)
    }
}
