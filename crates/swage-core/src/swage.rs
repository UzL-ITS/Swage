use crate::MemCheck;
use crate::allocator::{ConsecAllocator, alloc_memory};
use crate::hammerer::Hammering;
use crate::memory::{BitFlip, BytePointer, ConsecBlocks, DataPattern, Initializable};
use crate::util::{NamedProgress, PAGE_MASK, Rng, Size};
use crate::victim::{HammerVictimError, VictimOrchestrator, VictimResult};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

pub type ProfileHammererFactory<H> = Box<dyn Fn(ConsecBlocks) -> H>;
pub type HammererFactory<H1, H2> = Box<dyn Fn(H1, ConsecBlocks, RoundProfile) -> H2>;
pub type VictimFactory<E> =
    Box<dyn Fn(ConsecBlocks, RoundProfile) -> Result<Box<dyn VictimOrchestrator>, E>>;

/// Main orchestrator for conducting end-to-end Rowhammer experiments.
///
/// The `Swage` struct combines an allocator, hammerer, and victim to execute
/// complete Rowhammer attack experiments with profiling, reproducibility checks,
/// and result collection. It manages the full lifecycle:
///
/// 1. Memory allocation using [`ConsecAllocator`]
/// 2. Profiling to identify vulnerable memory locations
/// 3. Reproducibility verification to filter transient bit flips
/// 4. Attack execution with hammering and victim checking
///
/// # Type Parameters
///
/// * `PH` - Profile hammerer type (implements [`Hammering`])
/// * `H` - Attack hammerer type (implements [`Hammering`])
/// * `AE` - Allocator error type
/// * `VE` - Victim error type
///
/// # Examples
///
/// Use [`Swage::builder()`] to construct a `Swage` instance with the required components.
pub struct Swage<PH: Hammering, H: Hammering, AE: std::error::Error, VE: std::error::Error> {
    allocator: Box<dyn ConsecAllocator<Error = AE>>,
    profile_hammerer_factory: ProfileHammererFactory<PH>,
    profile_data_pattern: DataPatternKind,
    hammerer_factory: HammererFactory<PH, H>,
    victim_factory: VictimFactory<VE>,
    pattern_size: usize,
    progress: Option<MultiProgress>,
    config: SwageConfig,
}

/// Profiling results from a series of hammering rounds.
///
/// Contains the bit flips that were consistently reproduced during profiling
/// and the data pattern used to induce them.
#[derive(Debug, Serialize, Clone)]
pub struct RoundProfile {
    /// Bit flips that met the reproducibility threshold
    pub bit_flips: Vec<BitFlip>,
    /// Data pattern used during profiling
    pub pattern: DataPattern,
}

/// Configuration parameters for Swage experiments.
///
/// Controls profiling behavior, reproducibility requirements, and execution timeouts.
pub struct SwageConfig {
    /// Number of profiling rounds to identify vulnerable bit flips
    pub profiling_rounds: u64,
    /// Minimum fraction of rounds a bit flip must appear during profiling to be considered reproducible (0.0-1.0)
    pub reproducibility_threshold: f64,

    /// Timeout for total hammering operation (None = unlimited)
    pub hammering_timeout: Option<Duration>,
    /// Number of times to repeat the attack (None = unlimited)
    pub repetitions: Option<u64>,
    /// Overall experiment timeout (None = no timeout)
    pub timeout: Option<Duration>,
}

impl Default for SwageConfig {
    fn default() -> Self {
        Self {
            profiling_rounds: 10,
            reproducibility_threshold: 0.8,
            hammering_timeout: None,
            repetitions: Some(1),
            timeout: None,
        }
    }
}

/// Results from a complete Rowhammer experiment.
///
/// Contains all attack results, profiling data, timestamp, and optional metadata.
///
/// # Type Parameters
///
/// * `T` - Success result type
/// * `E` - Error type
#[derive(Serialize)]
pub struct ExperimentData<T, E> {
    /// ISO 8601 timestamp of when the experiment ran
    date: String,
    /// Results from each attack repetition
    results: Vec<std::result::Result<T, E>>,
    /// Profiling data from the experiment
    profiling: RoundProfile,
    /// Additional JSON metadata (implementation-specific)
    data: Option<serde_json::Value>,
}

impl<T, E> ExperimentData<T, E> {
    fn new(
        results: Vec<std::result::Result<T, E>>,
        profiling: RoundProfile,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            date: chrono::Local::now().to_rfc3339(),
            results,
            profiling,
            data,
        }
    }
}

impl<H: Hammering, AE: std::error::Error, VE: std::error::Error> Swage<H, H, AE, VE> {
    /// Creates a new Swage builder.
    ///
    /// # Returns
    ///
    /// A builder for configuring and constructing a Swage instance
    pub fn builder() -> SwageBuilder<H, H, AE, VE> {
        SwageBuilder::default()
    }
}

#[derive(Debug, Error)]
pub enum HammerError<AE: std::error::Error, HE: std::error::Error, VE: std::error::Error> {
    #[error(transparent)]
    AllocationFailed(AE),
    #[error(transparent)]
    HammeringFailed(HE),
    #[error(transparent)]
    VictimFailed(VE),
    #[error("No vulnerable cells found during profiling")]
    NoVulnerableCells,
    #[error(transparent)]
    VictimError(#[from] HammerVictimError),
}

impl<AE: std::error::Error, HE: std::error::Error, VE: std::error::Error> Serialize
    for HammerError<AE, HE, VE>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<PH: Hammering, H: Hammering, AE: std::error::Error, VE: std::error::Error>
    Swage<PH, H, AE, VE>
{
    fn round(
        &mut self,
        start: Instant,
        hammering_time: &mut Duration,
    ) -> ExperimentData<VictimResult, HammerError<AE, H::Error, VE>> {
        info!("Starting bait allocation");
        //unsafe { shm_unlink(CString::new("HAMMER_SHM").unwrap().as_ptr()) };
        let memory = match alloc_memory(self.allocator.as_mut(), Size::B(self.pattern_size)) {
            Ok(memory) => memory,
            Err(e) => {
                warn!("Failed to allocate memory: {}", e);
                return ExperimentData::new(
                    vec![Err(HammerError::AllocationFailed(e))],
                    RoundProfile {
                        bit_flips: vec![],
                        pattern: DataPattern::Random(Box::new(Rng::from_seed(rand::random()))),
                    },
                    None,
                );
            }
        };
        info!("Allocated {} bytes of memory", memory.len());

        info!("Profiling memory for vulnerable addresses");

        let hammerer = (self.profile_hammerer_factory)(memory.clone());

        let profiling = hammer_profile(
            &hammerer,
            memory.clone(),
            self.profile_data_pattern,
            self.config.profiling_rounds,
            self.config.reproducibility_threshold,
            self.progress.clone(),
        );
        debug!("Profiling results: {:?}", profiling);
        if profiling.bit_flips.is_empty() {
            warn!("No vulnerable addresses found");
            memory.dealloc();
            return ExperimentData::new(
                vec![Err(HammerError::NoVulnerableCells)],
                profiling.clone(),
                None,
            );
        }

        let flips = profiling.bit_flips.clone();
        let dpattern = profiling.pattern.clone();

        let hammerer = (self.hammerer_factory)(hammerer, memory.clone(), profiling.clone());

        let mut victim = match (self.victim_factory)(memory.clone(), profiling.clone()) {
            Ok(v) => v,
            Err(e) => {
                return ExperimentData::new(
                    vec![Err(HammerError::VictimFailed(e))],
                    profiling,
                    None,
                );
            }
        };

        match victim.as_mut().start() {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to start victim: {:?}", e);
                victim.stop();
                memory.dealloc();
                return ExperimentData::new(
                    vec![Err(HammerError::VictimError(e))],
                    profiling.clone(),
                    victim.serialize(),
                );
            }
        }
        let flip_pages = flips
            .iter()
            .map(|f| (f.addr & !PAGE_MASK) as *const u8)
            .collect::<Vec<_>>();

        let hammer_progress = match (self.config.hammering_timeout, self.progress.as_mut()) {
            (Some(hammering_timeout), Some(p)) => {
                let p = p.add(ProgressBar::new(hammering_timeout.as_secs()));
                p.set_style(ProgressStyle::named_bar("Total hammering time"));
                p.set_position((hammering_timeout - *hammering_time).as_secs());
                Some(p)
            }
            _ => None,
        };

        let mut results: Vec<Result<VictimResult, HammerError<AE, H::Error, VE>>> = vec![];
        loop {
            if check_timeout(self.config.timeout, Instant::now() - start) {
                info!("Timeout reached. Stopping.");
                break;
            }
            if check_timeout(self.config.hammering_timeout, *hammering_time) {
                info!("Hammering timeout reached. Stopping.");
                break;
            }
            if let Some(hammer_progress) = &hammer_progress {
                hammer_progress.set_position(hammering_time.as_secs());
            }
            memory.initialize_excluding(dpattern.clone(), &flip_pages); // TODO maybe remove this?
            victim.init();
            let hammer_start = Instant::now();
            let result = hammerer.hammer();
            *hammering_time += Instant::now().duration_since(hammer_start);
            match result {
                Ok(_) => {}
                Err(err) => results.push(Err(HammerError::HammeringFailed(err))),
            };
            let result = victim.check();
            match result {
                Ok(result) => {
                    info!("Hammering successful: {:?}", result);
                    results.push(Ok(result));
                }
                Err(HammerVictimError::NoFlips) => {
                    warn!("No flips detected");
                    results.push(Err(HammerError::VictimError(HammerVictimError::NoFlips)));
                }
                Err(e) => {
                    warn!("Hammering failed: {:?}", e);
                    results.push(Err(HammerError::VictimError(e)));
                    break;
                }
            }
            if self.config.timeout.is_none() && self.config.hammering_timeout.is_none() {
                info!("No timeout set, stopping after one round");
                break;
            }
        }
        victim.stop();
        memory.dealloc();
        ExperimentData::new(results, profiling.clone(), victim.serialize())
    }

    /// Start the attack.
    ///
    /// Returns a vector of ExperimentData with VictimResults and possible Error observed.
    pub fn run(mut self) -> Vec<ExperimentData<VictimResult, HammerError<AE, H::Error, VE>>> {
        let mut experiments = vec![];

        let repetitions = self.config.repetitions;
        let timeout = self.config.timeout;
        let hammering_timeout = self.config.hammering_timeout;

        let start = Instant::now();
        let mut hammering_time = Duration::ZERO;
        let timeout_progress = match (timeout, self.progress.as_mut()) {
            (Some(timeout), Some(p)) => {
                let p = p.add(ProgressBar::new(timeout.as_secs()));
                p.set_style(ProgressStyle::named_bar("Global timeout"));
                p.set_position(0);
                p.tick();
                p.enable_steady_tick(Duration::from_secs(1));
                Some(p)
            }
            _ => None,
        };
        let rep_progress = match (repetitions, self.progress.as_mut()) {
            (Some(repetitions), Some(p)) => {
                let p = p.add(ProgressBar::new(repetitions));
                p.set_style(ProgressStyle::named_bar("Repetitions"));
                Some(p)
            }
            _ => None,
        };
        for rep in 0..repetitions.unwrap_or(u64::MAX) {
            if let Some(rep_progress) = &rep_progress {
                rep_progress.set_position(rep + 1);
            }
            if let Some(timeout_progress) = &timeout_progress {
                timeout_progress.set_position((Instant::now() - start).as_secs());
            }
            if rep > 0 && check_timeout(timeout, Instant::now() - start) {
                info!("Timeout reached. Stopping.");
                break;
            }
            if let Some(hammering_timeout) = hammering_timeout {
                if hammering_time >= hammering_timeout {
                    info!("Hammering timeout reached. Stopping.");
                    break;
                }
                info!(
                    "Hammering time left: {} minutes",
                    (hammering_timeout - hammering_time).as_secs() / 60,
                );
            }
            experiments.push(self.round(start, &mut hammering_time));
        }
        experiments
    }
}

fn check_timeout(timeout: Option<Duration>, duration: Duration) -> bool {
    timeout.is_some_and(|timeout| duration > timeout)
}

/// Hammer a given `memory` region `num_rounds` times to profile for vulnerable addresses.
fn hammer_profile<E: std::error::Error>(
    hammerer: &dyn Hammering<Error = E>,
    memory: ConsecBlocks,
    pattern: DataPatternKind,
    num_rounds: u64,
    reproducibility_threshold: f64,
    progress: Option<MultiProgress>,
) -> RoundProfile {
    let p = progress.as_ref().map(|p| {
        let p = p.add(ProgressBar::new(num_rounds));
        p.set_style(ProgressStyle::named_bar("Profiling round"));
        p.enable_steady_tick(Duration::from_secs(1));
        p
    });

    const _SHM_SEED: u64 = 9804201662804659191;
    let mut candidates = HashMap::new();
    let min_repro_count = (reproducibility_threshold * num_rounds as f64) as u64;
    let pattern = match pattern {
        DataPatternKind::Random => DataPattern::Random(Box::new(Rng::from_seed(rand::random()))),
        DataPatternKind::One => DataPattern::One,
        DataPatternKind::Zero => DataPattern::Zero,
    };
    for r in 1..=num_rounds {
        if let Some(p) = p.as_ref() {
            p.set_position(r);
        }
        if candidates.is_empty() && r > num_rounds - min_repro_count {
            warn!(
                "No candidates and only {} round(s) left. Stopping profiling, continuing with next pattern",
                num_rounds - r
            );
            break;
        }
        let mut victim = MemCheck::new(memory.clone(), pattern.clone(), vec![].into());
        victim.init();
        let result = hammerer.hammer();
        match result {
            Ok(_) => {
                let result = victim.check();
                let bit_flips = match result {
                    Ok(result) => {
                        info!("Profiling hammering round successful: {:?}", result);
                        result.bit_flips()
                    }
                    Err(e) => {
                        warn!("Profiling hammering round not successful: {:?}", e);
                        vec![]
                    }
                };
                for flip in bit_flips {
                    let entry = candidates.entry(flip).or_insert(0);
                    *entry += 1;
                }
            }
            Err(e) => {
                warn!("Profiling hammering round not successful: {:?}", e);
            }
        }
        let remaining_rounds = num_rounds - r;
        candidates.retain(|_, v| *v + remaining_rounds >= min_repro_count);
        info!("Profiling round {} candidates: {:?}", r, candidates);
    }
    RoundProfile {
        bit_flips: candidates.keys().cloned().collect(),
        pattern,
    }
}

/// Data pattern selection for configuration.
///
/// Used to specify which type of data pattern to use in the aggressors.
#[derive(Clone, Copy)]
pub enum DataPatternKind {
    /// Random data pattern
    Random,
    /// All zeros (0x00)
    Zero,
    /// All ones (0xFF)
    One,
}

pub struct SwageBuilder<PH: Hammering, H: Hammering, AE: std::error::Error, VE: std::error::Error> {
    allocator: Option<Box<dyn ConsecAllocator<Error = AE>>>,
    profile_hammerer_factory: Option<ProfileHammererFactory<PH>>,
    profile_data_pattern: DataPatternKind,
    hammerer_factory: HammererFactory<PH, H>,
    victim_factory: Option<VictimFactory<VE>>,
    pattern_size: Option<usize>,
    progress: Option<MultiProgress>,
    config: SwageConfig,
}

impl<H: Hammering, AE: std::error::Error, VE: std::error::Error> Default
    for SwageBuilder<H, H, AE, VE>
{
    fn default() -> Self {
        SwageBuilder {
            allocator: None,
            profile_hammerer_factory: None,
            profile_data_pattern: DataPatternKind::Random,
            hammerer_factory: Box::new(|h, _, _| h),
            victim_factory: None,
            pattern_size: None,
            progress: None,
            config: SwageConfig::default(),
        }
    }
}

impl<PH: Hammering, H: Hammering, AE: std::error::Error, VE: std::error::Error>
    SwageBuilder<PH, H, AE, VE>
{
    pub fn allocator<A: ConsecAllocator + 'static>(
        self,
        allocator: A,
    ) -> SwageBuilder<PH, H, A::Error, VE> {
        SwageBuilder {
            allocator: Some(Box::new(allocator)),
            profile_hammerer_factory: self.profile_hammerer_factory,
            profile_data_pattern: self.profile_data_pattern,
            hammerer_factory: self.hammerer_factory,
            victim_factory: self.victim_factory,
            pattern_size: self.pattern_size,
            progress: self.progress,
            config: self.config,
        }
    }

    pub fn profile_hammerer_factory(
        mut self,
        profile_hammerer_factory: impl Fn(ConsecBlocks) -> PH + 'static,
    ) -> Self {
        self.profile_hammerer_factory = Some(Box::new(profile_hammerer_factory));
        self
    }

    pub fn profile_data_pattern(mut self, profile_data_pattern: DataPatternKind) -> Self {
        self.profile_data_pattern = profile_data_pattern;
        self
    }

    pub fn hammerer_factory<H1: Hammering>(
        self,
        hammerer_factory: impl Fn(PH, ConsecBlocks, RoundProfile) -> H1 + 'static,
    ) -> SwageBuilder<PH, H1, AE, VE> {
        SwageBuilder {
            allocator: self.allocator,
            profile_hammerer_factory: self.profile_hammerer_factory,
            profile_data_pattern: self.profile_data_pattern,
            hammerer_factory: Box::new(hammerer_factory),
            victim_factory: self.victim_factory,
            pattern_size: self.pattern_size,
            progress: self.progress,
            config: self.config,
        }
    }

    pub fn victim_factory(
        mut self,
        victim_factory: impl Fn(ConsecBlocks, RoundProfile) -> Result<Box<dyn VictimOrchestrator>, VE>
        + 'static,
    ) -> Self {
        self.victim_factory = Some(Box::new(victim_factory));
        self
    }

    pub fn pattern_size(mut self, pattern_size: usize) -> Self {
        self.pattern_size = Some(pattern_size);
        self
    }

    pub fn progress(mut self, progress: MultiProgress) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn config(mut self, config: SwageConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build(self) -> Result<Swage<PH, H, AE, VE>, Error> {
        if !(self.config.timeout.is_some()
            || self.config.repetitions.is_some()
            || self.config.hammering_timeout.is_some())
        {
            return Err(Error::InvalidConfig(
                "At least one of timeout, repetitions or hammering_timeout must be set".into(),
            ));
        }
        Ok(Swage {
            allocator: self.allocator.ok_or(Error::Allocator)?,
            profile_hammerer_factory: self
                .profile_hammerer_factory
                .ok_or(Error::ProfileHammerer)?,
            profile_data_pattern: self.profile_data_pattern,
            hammerer_factory: self.hammerer_factory,
            victim_factory: self.victim_factory.ok_or(Error::Victim)?,
            progress: self.progress,
            pattern_size: self.pattern_size.ok_or(Error::PatternSize)?,
            config: self.config,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("No allocator specified")]
    Allocator,
    #[error("No profiling hammerer specified")]
    ProfileHammerer,
    #[error("No victim specified")]
    Victim,
    #[error("Pattern size not specified")]
    PatternSize,
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
}
