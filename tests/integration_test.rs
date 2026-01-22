use rand::{Rng, rng};
use swage::allocator::ConsecAllocator;
use swage::util::PAGE_MASK;
use swage_blacksmith::BlacksmithConfig;
use swage_blacksmith::{FromBitDefs, FromBlacksmithConfig};
use swage_core::memory::{
    DRAMAddr, MemConfiguration, Memory, MemoryTupleTimer, PfnOffset, PfnOffsetResolver,
    PfnResolver, construct_memory_tuple_timer,
};
use swage_core::util::{ROW_SHIFT, ROW_SIZE, Size::MB};
use swage_hugepage::HugepageAllocator;

const CONFIG_FILE: &str = "../config/bs-config.json";

#[test]
fn test_pfn_offset_mock_timer() -> anyhow::Result<()> {
    struct TestTimer<'a> {
        callback: &'a dyn Fn((*const u8, *const u8)) -> u64,
    }

    impl MemoryTupleTimer for TestTimer<'_> {
        unsafe fn time_subsequent_access_from_ram(
            &self,
            a: *const u8,
            b: *const u8,
            _rounds: usize,
        ) -> u64 {
            (self.callback)((a, b))
        }
    }

    let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    const ADDR: *mut u8 = 0x200000000 as *mut u8;

    // it is not possible to determine the highest bank bit by only using one single memblock.
    let row_offsets = mem_config.bank_function_period() as usize / 2;
    for row_offset in 0..row_offsets {
        let base_addr = ADDR as usize + row_offset * ROW_SIZE;
        let timer = TestTimer {
            callback: &|(a, b)| {
                let a = a as usize - ADDR as usize;
                let a = base_addr + a;
                let b = b as usize - ADDR as usize;
                let b = base_addr + b;
                let a = DRAMAddr::from_virt(a as *mut u8, &mem_config);
                let b = DRAMAddr::from_virt(b as *mut u8, &mem_config);
                if a.bank == b.bank {
                    config.threshold + 100
                } else {
                    config.threshold - 100
                }
            },
        };

        let block = Memory::new(ADDR, MB(4).bytes());
        let offset = block.pfn_offset(&mem_config, config.threshold, &timer, None);

        assert!(offset.is_some());
        assert_eq!(offset.unwrap(), row_offset);
    }

    Ok(())
}

#[test]
fn test_pfn_offset_mmap() -> anyhow::Result<()> {
    let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let block = Memory::mmap(MB(4).bytes())?;
    let timer = construct_memory_tuple_timer()?;
    let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
    assert!(pfn_offset.is_none());
    block.dealloc();
    Ok(())
}

#[test]
#[ignore]
fn test_pfn_offset_hugepage() -> anyhow::Result<()> {
    env_logger::init();
    let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let mut allocator = HugepageAllocator {};
    let blocks = allocator.alloc_consec_blocks(swage::util::Size::GB(1))?;
    let block = blocks.blocks.first().expect("No blocks");
    let timer = construct_memory_tuple_timer()?;
    let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
    println!("VA: 0x{:02x}", block.ptr as usize);
    println!("PFN: 0x{:p}", block.pfn()?);
    assert_eq!(pfn_offset, Some(0));
    blocks.dealloc();
    Ok(())
}

#[test]
fn test_virt_offset() -> anyhow::Result<()> {
    let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let bank_bits_mask = (mem_config.bank_function_period() as usize * ROW_SIZE - 1) as isize;
    //let row_offsets = (1 << (mem_config.max_bank_bit + 1 - ROW_SHIFT as u64)) as u64;
    //let mut rng = thread_rng();
    const NUM_TESTCASES: usize = 1_000_000;
    let mut test_cases: Vec<(usize, usize)> = Vec::with_capacity(NUM_TESTCASES);
    test_cases.push((0x79acade00000, 0x419df9000));
    test_cases.push((0x77c537a00000, 0x19bd000));
    test_cases.push((0x7ffef6f36000, 0x4a1a0000));
    test_cases.push((0x7ffef6a00000, 0x4c111000));
    test_cases.push((0x7ffeca600000, 0x2033000));
    /*
    for _ in 0..NUM_TESTCASES {
        let v: usize = rng.gen();
        let p: usize = rng.gen();
        test_cases.push((v, p));
    } */
    for (v, p) in test_cases {
        println!("VA,PA");
        println!("0x{:02x},0x{:02x}", v, p);
        let byte_offset = (p as isize & bank_bits_mask) - (v as isize & bank_bits_mask);
        let byte_offset = byte_offset.rem_euclid(MB(4).bytes() as isize) as usize;
        println!("Byte offset 0x{:02x}", byte_offset);
        println!("Row offset: {}", byte_offset >> ROW_SHIFT);
        let dramv = unsafe {
            DRAMAddr::from_virt_offset(v as *const u8, byte_offset as isize, &mem_config)
        };
        let dramp = DRAMAddr::from_virt(p as *const u8, &mem_config);
        println!("{:?}", dramv);
        println!("{:?}", dramp);
        assert_eq!(dramv.bank, dramp.bank);
    }
    Ok(())
}

#[test]
#[allow(clippy::never_loop)]
fn test_virt_zero_gap() -> anyhow::Result<()> {
    let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
    let mem_config = MemConfiguration::from_blacksmith(&config);
    let mut rand = rng();
    for _ in 0..1000000 {
        let v = (rand.random::<i64>() as isize) << 12;
        let p = (rand.random::<i64>() as isize) << 12;
        println!("VA,PA: 0x{:x}, 0x{:x}", v, p);
        let vbase = v & PAGE_MASK as isize;
        let pbase = p & PAGE_MASK as isize;
        let offset = pbase as isize - vbase as isize;
        let offset = offset.rem_euclid(MB(4).bytes() as isize);
        //let offset = offset.rem_euclid(MB(2).bytes() as isize);
        let block = Memory::new_with_parts(
            v as *mut u8,
            MB(4).bytes(),
            PfnOffset::Fixed(offset as usize / ROW_SIZE),
        );
        let aligned: Memory = unimplemented!("&block.pfn_align()?[0]");
        let expected = if offset == 0 {
            v
        } else {
            v + MB(4).bytes() as isize - offset
        };
        assert_eq!(aligned.ptr as usize, expected as usize);

        let zero_gap = offset + vbase as isize;
        let pdram_zero = DRAMAddr::from_virt(
            (p + MB(4).bytes() as isize - zero_gap) as *mut u8,
            &mem_config,
        );
        assert_eq!(pdram_zero.bank, 0);
    }
    Ok(())
}
