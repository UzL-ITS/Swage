use std::{
    fs::File,
    io::{BufWriter, Write},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::Parser;
use indicatif::MultiProgress;
use log::{info, warn};
use serde::Serialize;
use swage_blacksmith::FromBlacksmithConfig;
use swage_blacksmith::blacksmith_config::BlacksmithConfig;
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{FormatPfns, GetConsecPfns, MemConfiguration};
use swage_core::util::MB;

/// CLI arguments for the `eval_alloc` binary.
///
/// This struct defines the command line arguments that can be passed to the `eval_alloc` binary
/// for evaluating allocator performance and behavior.
#[derive(Debug, Parser, Serialize, Clone)]
struct CliArgs {
    /// The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// The allocation strategy to use.
    #[clap(long = "alloc-strategy", default_value = "spoiler")]
    alloc_strategy: String,
    /// The number of allocation attempts to perform.
    #[clap(long = "attempts", default_value = "10")]
    attempts: u32,
    /// The size to allocate per attempt in MB.
    #[clap(long = "size", default_value = "4")]
    size_mb: usize,
    /// Repeat the allocation evaluation this many times.
    #[clap(long = "repeat", default_value = "1")]
    repeat: usize,
    /// The timeout in minutes for the entire evaluation process.
    #[clap(long = "timeout")]
    timeout: Option<u64>,
    /// Output file for results (JSON format).
    #[clap(long = "output")]
    output: Option<String>,
    /// Verbose output - print detailed allocation statistics.
    #[clap(long = "verbose", short = 'v')]
    verbose: bool,
    /// Deallocate memory after each allocation (for testing allocation/deallocation cycles).
    #[clap(long = "deallocate")]
    deallocate: bool,
}

#[derive(Debug, Serialize, Clone)]
struct AllocationResult {
    attempt: u32,
    success: bool,
    duration_ms: u64,
    pfn_count: Option<usize>,
    consec_pfns: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvaluationResults {
    args: CliArgs,
    total_attempts: u32,
    successful_attempts: u32,
    failed_attempts: u32,
    success_rate: f64,
    average_duration_ms: f64,
    total_duration_ms: u64,
    allocations: Vec<AllocationResult>,
}

impl EvaluationResults {
    fn new(args: CliArgs) -> Self {
        Self {
            args,
            total_attempts: 0,
            successful_attempts: 0,
            failed_attempts: 0,
            success_rate: 0.0,
            average_duration_ms: 0.0,
            total_duration_ms: 0,
            allocations: Vec::new(),
        }
    }

    fn add_allocation(&mut self, result: AllocationResult) {
        self.total_attempts += 1;
        if result.success {
            self.successful_attempts += 1;
        } else {
            self.failed_attempts += 1;
        }
        self.total_duration_ms += result.duration_ms;
        self.allocations.push(result);

        // Update calculated fields
        self.success_rate = self.successful_attempts as f64 / self.total_attempts as f64;
        self.average_duration_ms = self.total_duration_ms as f64 / self.total_attempts as f64;
    }

    fn save_to_file(&self, filename: &str) -> Result<()> {
        let file = File::create(filename)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, self)?;
        writer.flush()?;
        info!("Results saved to {}", filename);
        Ok(())
    }
}

fn evaluate_allocator(args: &CliArgs) -> Result<EvaluationResults> {
    let progress = MultiProgress::new();
    let bs_config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&bs_config);

    let mut allocator: Box<dyn ConsecAllocator> = match args.alloc_strategy.as_ref() {
        "pfn" => Box::new(swage_pfn::Pfn::new(mem_config, None.into())),
        "spoiler" => Box::new(swage_spoiler::Spoiler::new(
            mem_config,
            bs_config.threshold.into(),
            Some(progress),
        )),
        _ => panic!("Unknown allocator"),
    };

    let mut results = EvaluationResults::new(args.clone());
    let allocation_size = args.size_mb * MB;

    info!(
        "Starting allocation evaluation with {} attempts",
        args.attempts
    );
    info!("Allocation size: {} MB", args.size_mb);
    info!("Allocation strategy: {:?}", args.alloc_strategy);

    for attempt in 1..=args.attempts {
        info!("Attempt number {}", attempt);
        let start_time = Instant::now();

        let allocation_result = match allocator.alloc_consec_blocks(allocation_size) {
            Ok(memory) => {
                let duration = start_time.elapsed();
                let (pfn_count, pfns_str) = match memory.consec_pfns() {
                    Ok(pfns) => (Some(pfns.len()), Some(pfns.format_pfns())),
                    Err(e) => {
                        warn!("Failed to get PFNs: {:?}", e);
                        (None, Some(format!("Error getting PFNs: {:?}", e)))
                    }
                };

                if args.verbose {
                    info!(
                        "Attempt {}: Success in {}ms, {} PFN ranges",
                        attempt,
                        duration.as_millis(),
                        pfn_count.unwrap_or(0)
                    );
                    if let Some(ref pfns) = pfns_str {
                        info!("  PFNs:\n{}", pfns);
                    }
                }

                let result = AllocationResult {
                    attempt,
                    success: true,
                    duration_ms: duration.as_millis() as u64,
                    pfn_count,
                    consec_pfns: pfns_str,
                    error: None,
                };

                // Deallocate if requested
                if args.deallocate {
                    memory.dealloc();
                    if args.verbose {
                        info!("  Memory deallocated");
                    }
                }

                result
            }
            Err(e) => {
                let duration = start_time.elapsed();
                let error_msg = format!("{:?}", e);

                if args.verbose {
                    warn!(
                        "Attempt {}: Failed in {}ms - {}",
                        attempt,
                        duration.as_millis(),
                        error_msg
                    );
                }

                AllocationResult {
                    attempt,
                    success: false,
                    duration_ms: duration.as_millis() as u64,
                    pfn_count: None,
                    consec_pfns: None,
                    error: Some(error_msg),
                }
            }
        };

        results.add_allocation(allocation_result);
    }

    Ok(results)
}

fn main() -> Result<()> {
    env_logger::init();

    let args = CliArgs::parse();
    info!("CLI args: {:?}", args);

    let timeout = args.timeout.map(|t| Duration::from_secs(t * 60));
    let start_time = Instant::now();

    let mut all_results = Vec::new();

    for rep in 1..=args.repeat {
        if let Some(timeout_duration) = timeout {
            if start_time.elapsed() >= timeout_duration {
                warn!("Timeout reached after {} repetitions", rep - 1);
                break;
            }
        }

        info!("Starting repetition {}/{}", rep, args.repeat);

        match evaluate_allocator(&args) {
            Ok(results) => {
                info!("Repetition {} completed:", rep);
                info!("  Success rate: {:.2}%", results.success_rate * 100.0);
                info!("  Average duration: {:.2}ms", results.average_duration_ms);
                info!(
                    "  Successful attempts: {}/{}",
                    results.successful_attempts, results.total_attempts
                );

                all_results.push(results);
            }
            Err(e) => {
                warn!("Repetition {} failed: {:?}", rep, e);
            }
        }
    }

    // Save results if output file is specified
    if let Some(output_file) = &args.output {
        if all_results.len() == 1 {
            all_results[0].save_to_file(output_file)?;
        } else {
            // Save all repetition results
            let file = File::create(output_file)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &all_results)?;
            writer.flush()?;
            info!("All results saved to {}", output_file);
        }
    }

    // Print summary
    if !all_results.is_empty() {
        let total_success_rate: f64 =
            all_results.iter().map(|r| r.success_rate).sum::<f64>() / all_results.len() as f64;

        let total_avg_duration: f64 = all_results
            .iter()
            .map(|r| r.average_duration_ms)
            .sum::<f64>()
            / all_results.len() as f64;

        info!("=== EVALUATION SUMMARY ===");
        info!("Repetitions: {}", all_results.len());
        info!("Overall success rate: {:.2}%", total_success_rate * 100.0);
        info!("Overall average duration: {:.2}ms", total_avg_duration);
        info!(
            "Total evaluation time: {:.2}s",
            start_time.elapsed().as_secs_f64()
        );
    }

    Ok(())
}
