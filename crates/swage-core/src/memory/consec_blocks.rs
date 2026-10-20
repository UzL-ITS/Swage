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
            merge_pfns(&mut pfns, block.consec_pfns()?);
        }
        Ok(pfns)
    }
}

/// Appends `block_pfns` to `pfns`, merging the first range of `block_pfns` into the
/// last range of `pfns` if it continues it physically.
fn merge_pfns(pfns: &mut Vec<Range<PhysAddr>>, block_pfns: Vec<Range<PhysAddr>>) {
    let mut block_pfns = VecDeque::from(block_pfns);
    let is_cons = pfns
        .last()
        .zip(block_pfns.front())
        .is_some_and(|(last, next)| last.end == next.start);
    if is_cons {
        let prev = pfns.pop().unwrap();
        let next = block_pfns.pop_front().unwrap();
        pfns.push(prev.start..next.end);
    }
    pfns.extend(block_pfns);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB4: usize = 0x400000;

    fn r(start: usize) -> Range<PhysAddr> {
        PhysAddr::new(start)..PhysAddr::new(start + MB4)
    }

    #[test]
    fn merges_ascending_adjacent_blocks() {
        let mut pfns = vec![];
        merge_pfns(&mut pfns, vec![r(0x2fe800000)]);
        merge_pfns(&mut pfns, vec![r(0x2fec00000)]);
        assert_eq!(
            pfns,
            vec![PhysAddr::new(0x2fe800000)..PhysAddr::new(0x2ff000000)]
        );
    }

    #[test]
    fn keeps_descending_adjacent_blocks_separate() {
        // previously merged into the empty range 0x2fec00000..0x2fec00000
        let mut pfns = vec![];
        merge_pfns(&mut pfns, vec![r(0x2fec00000)]);
        merge_pfns(&mut pfns, vec![r(0x2fe800000)]);
        assert_eq!(pfns, vec![r(0x2fec00000), r(0x2fe800000)]);
    }
}
