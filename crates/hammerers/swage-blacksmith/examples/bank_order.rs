use clap::Parser;
use log::info;
use swage_blacksmith::BlacksmithConfig;
use swage_blacksmith::FromBitDefs;
use swage_core::memory::{DRAMAddr, MemConfiguration};
use swage_core::util::Size::KB;

#[derive(Parser, Debug)]
struct CliArgs {
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
}

fn main() -> Result<(), swage_blacksmith::Error> {
    env_logger::init();
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let addr = 0x2000000000 as *mut u8;
    let row_offsets = mem_config.bank_function_period() as usize;
    info!("Row offsets: {}", row_offsets);
    for row_offset in 0..row_offsets {
        let ptr = unsafe { addr.byte_add(row_offset * KB(8).bytes()) };
        let dram = DRAMAddr::from_virt(ptr, &mem_config);
        if row_offset != 0 && row_offset % 256 == 0 {
            println!();
        } else if row_offset != 0 {
            print!(",");
        }
        print!("{:02}", dram.bank);
    }
    println!();
    Ok(())
}
