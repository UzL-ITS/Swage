//! /dev/mem-based Rowhammer hammerer.
//!
//! This crate provides a hammerer that uses direct `/dev/mem` access to perform
//! precise memory operations at specific physical addresses. Requires root privileges.
//!
//! Implements the [`swage_core::hammerer::Hammering`] trait.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux
//! - Root privileges for `/dev/mem` access
//! - Kernel must allow `/dev/mem` access (not all distributions enable this)

#![warn(missing_docs)]

mod dev_mem;

pub use dev_mem::{Bit, DevMem};
