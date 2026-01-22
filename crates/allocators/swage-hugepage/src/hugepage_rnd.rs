use crate::HugepageAllocator;
use log::info;
use rand::prelude::SliceRandom;
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{BytePointer, ConsecBlocks, Memory};
use swage_core::util::{Size, Size::MB, make_vec};

/// Allocator using randomized hugepage chunks.
///
/// Allocates from a pool of hugepages, selecting chunks randomly.
/// This allows to check whether a hammering pattern is chunk-movable in a memory range
pub struct HugepageRandomized {
    /// Pool of pre-allocated hugepages
    hugepages: Vec<ConsecBlocks>,
}

/// Number of hugepages to pre-allocate.
#[derive(Clone)]
pub struct NumHugePages(usize);

impl HugepageRandomized {
    /// Creates allocator with specified number of hugepages.
    ///
    /// # Arguments
    ///
    /// * `num_hugepages` - Number of 1GB hugepages to allocate
    pub fn new_with_count(num_hugepages: NumHugePages) -> Self {
        let hugepages = make_vec(num_hugepages.0, |_| {
            HugepageAllocator::default()
                .alloc_consec_blocks(MB(1024))
                .expect("hugepage alloc")
        });
        HugepageRandomized { hugepages }
    }
}

impl ConsecAllocator for HugepageRandomized {
    type Error = std::io::Error;
    fn block_size(&self) -> Size {
        MB(4)
    }

    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        let hp_size = MB(1024).bytes();
        let chunk_size = self.block_size().bytes();
        let num_chunks = hp_size / chunk_size;
        let total_chunks = self.hugepages.len() * num_chunks;
        let num_blocks = size.bytes() / chunk_size;

        let mut chunk_indices: Vec<usize> = (0..total_chunks).collect();
        let mut rng = rand::rng();
        chunk_indices.shuffle(&mut rng);
        let selected_indices = &chunk_indices[..num_blocks];
        //let free_indices = &chunk_indices[num_blocks..];

        let blocks = selected_indices
            .iter()
            .map(|index| {
                info!("Hugepage {}", index / num_chunks);
                self.hugepages[index / num_chunks].addr((index % num_chunks) * chunk_size)
            })
            .map(|ptr| Memory::new(ptr, chunk_size))
            .collect::<Vec<_>>();
        let consecs = ConsecBlocks::new(blocks);
        Ok(consecs)
    }
}

impl From<usize> for NumHugePages {
    fn from(value: usize) -> Self {
        NumHugePages(value)
    }
}
