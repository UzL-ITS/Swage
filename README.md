## SWAGE: A Modular Rowhammer Attack Framework

SWAGE is a Rust-based framework for conducting end-to-end Rowhammer attacks in a modular
and composable way. The framework separates the attack pipeline into three core components:
**allocators**, **hammerers**, and **victims**, each defined by a trait that can be
independently implemented and combined.

### Overview

Rowhammer is a hardware vulnerability in DRAM where repeated accesses to memory rows can
cause bit flips in adjacent rows. SWAGE provides a structured approach to researching and
executing such attacks by breaking down the attack into modular components.

### Core Architecture

SWAGE is built around three main traits defined in [`swage_core`]:

- **[`allocator::ConsecAllocator`]** - Strategies for allocating consecutive physical memory blocks
- **[`hammerer::Hammering`]** - Implementations of memory hammering patterns and techniques
- **[`victim::VictimOrchestrator`]** - Management of target memory regions or applications

These components are orchestrated by the [`Swage`] struct, which coordinates the complete
attack pipeline from memory allocation through hammering to result verification.

### Building Your Own Attack Pipeline

Creating a custom Rowhammer attack pipeline with SWAGE involves three main steps:

#### Step 1: Choose or Implement an Allocator

Allocators provide consecutive physical memory blocks required for effective Rowhammer attacks.
SWAGE includes several built-in allocators:

- **`Spoiler`** - Uses SPOILER timing side-channel attack to infer physical addresses
- **`Pfn`** - Uses `/proc/self/pagemap` to obtain physical frame numbers (requires root)
- **`THP`** - Uses Transparent Huge Pages for 2MB blocks
- **`Hugepage`** - Uses 1GB hugepages (requires system configuration)

```rust
use swage::memory::MemConfiguration;
use swage::allocator::{ConsecAllocator, Spoiler, ConflictThreshold};
use swage::util::Size;

// Example: Create a Spoiler allocator
let mut allocator = Spoiler::new(MemConfiguration::default(), ConflictThreshold::from(190), None);
let memory = allocator.alloc_consec_blocks(Size::MB(256)).unwrap();
```

To create a custom allocator, implement the [`allocator::ConsecAllocator`] trait:

```rust
use swage::allocator::ConsecAllocator;
use swage::memory::ConsecBlocks;
use swage::util::Size;

struct MyAllocator;

impl ConsecAllocator for MyAllocator {
    type Error = std::io::Error;

    fn block_size(&self) -> Size {
        Size::MB(2) // 2MB blocks
    }

    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        // Your allocation logic here
        todo!()
    }
}
```

#### Step 2: Choose or Implement a Hammerer

Hammerers define the memory access patterns used to trigger bit flips. SWAGE provides:

- **`Blacksmith`** - Implements the Blacksmith fuzzing-based hammering technique
- **`DevMem`** - Direct memory access via `/dev/mem` (requires root)
- **`Dummy`** - A no-op hammerer for testing

The Blacksmith hammerer requires specific configuration including DRAM addressing
parameters and hammering patterns. See the `swage-blacksmith` crate documentation
for configuration details.

Note: Hammerers are typically created via factory functions in the builder pattern.
See Step 4 for usage examples.

To create a custom hammerer, implement the [`hammerer::Hammering`] trait:

```rust
use swage::hammerer::Hammering;

struct MyHammerer {
    // Your hammerer state
}

impl Hammering for MyHammerer {
    type Error = std::io::Error;

    fn hammer(&self) -> Result<(), Self::Error> {
        // Perform memory accesses to trigger Rowhammer
        todo!()
    }
}
```

#### Step 3: Choose or Implement a Victim

Victims define what is being targeted and how to check for successful attacks:

- **`MemCheck`** - Checks memory regions for bit flips
- Custom victim implementations for specific attack scenarios

Note: `MemCheck` is typically created by the victim factory in the builder pattern.
See Step 4 for usage examples.

To create a custom victim, implement the [`victim::VictimOrchestrator`] trait:

```rust
use swage::victim::{VictimOrchestrator, HammerVictimError, VictimResult};
use swage::memory::ConsecBlocks;

struct MyVictim;

impl VictimOrchestrator for MyVictim {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        // Initialize victim
        Ok(())
    }

    fn init(&mut self) {
        // Prepare victim state before hammering
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        // Check if attack succeeded
        Ok(VictimResult::Nothing)
    }

    fn stop(&mut self) {
        // Cleanup
    }
}
```

#### Step 4: Orchestrate the Attack with the Builder Pattern

SWAGE uses the builder pattern to construct and configure attack pipelines. The [`Swage::builder()`]
method provides a fluent interface for assembling the components:

```rust
use swage::{Swage, SwageConfig, MemCheck, DataPatternKind};
use swage::allocator::{Spoiler, ConflictThreshold};
use swage::memory::{MemConfiguration, DataPattern, ConsecBlocks};
use swage::util::Size;
use swage::victim::VictimOrchestrator;
use swage::blacksmith::Blacksmith;

// Configure the attack
let config = SwageConfig {
    profiling_rounds: 10,
    reproducibility_threshold: 0.8,
    repetitions: Some(1),
    ..Default::default()
};

let allocator = Spoiler::new(
    MemConfiguration::default(),
    300.into(),
    None
);
let pattern_size = Size::MB(256).bytes();

let swage = Swage::<Blacksmith, _, std::io::Error, std::io::Error>::builder()
    .allocator(allocator)
    .profile_hammerer_factory(|memory| {
        todo!("Build blacksmith hammerer");
    })
    .victim_factory(|memory, profiling| {
        todo!("Build your victim")
    })
    .pattern_size(todo!("pattern size"))
    .config(config)
    .build()
    .unwrap();
let experiments = swage.run();
```

### Adding New Modules to the Framework

SWAGE uses automatic module discovery. To add a new module:

1. Create a new crate in the appropriate directory:
   - `crates/allocators/swage-myallocator/` for allocators
   - `crates/hammerers/swage-myhammerer/` for hammerers
   - `crates/victims/swage-myvictim/` for victims

2. Implement the corresponding trait from `swage-core`

3. Run the module discovery script:
   ```bash
   ./update_modules.sh
   ```

The script will automatically register your module in the workspace.

### Platform Requirements

- **Architecture**: x86_64
- **OS**: Linux with access to `/proc/self/pagemap`
- **Privileges**: Some modules require root access or custom kernel modules

### Example: Complete Attack Pipeline


### Features

Enable specific non-core modules via Cargo features:

- `spoiler` - SPOILER allocator
- `pfn` - PFN allocator
- `hugepage` - Hugepage allocator
- `thp` - Transparent Huge Pages allocator
- `blacksmith` - Blacksmith hammerer
- `dev-mem` - /dev/mem hammerer

### Safety and Ethics

This framework is intended for security research and education. Users must:
- Only test on systems they own or have explicit permission to test
- Follow responsible disclosure practices for vulnerabilities
- Comply with all applicable laws and regulations

License: MIT
