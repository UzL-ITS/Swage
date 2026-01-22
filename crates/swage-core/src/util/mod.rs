//! Utility functions and types used throughout the Swage framework.
//!
//! This module provides various helper types and traits including:
//! - [`Size`] - Memory size representation
//! - Constants for memory operations ([`PAGE_SIZE`], [`ROW_SIZE`], etc.)
//! - [`GroupBy`] trait for collection grouping operations
//! - [`ReadLine`] trait for reading lines from child process stdout
//! - Progress reporting utilities ([`NamedProgress`])
//! - Random number generation ([`Rng`])

mod alloc_util;
mod cancelable_thread;
mod constants;
mod named_progress;
mod rng;
mod size;

pub use self::alloc_util::*;
pub use self::cancelable_thread::*;
pub use self::constants::*;
pub use self::named_progress::NamedProgress;
pub use self::rng::Rng;
pub use self::size::Size;

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

/// Trait for grouping collection elements by a key function.
///
/// This trait extends collections with the ability to group elements based on
/// a key extraction function, similar to SQL's GROUP BY operation.
pub trait GroupBy<V> {
    /// Groups elements by the result of applying a function to each element.
    ///
    /// # Arguments
    ///
    /// * `f` - Function that extracts a grouping key from each element
    ///
    /// # Returns
    ///
    /// Returns a `HashMap` where keys are the grouping keys and values are
    /// vectors of elements that share that key.
    fn group_by<K: std::hash::Hash + std::cmp::Eq, F: Fn(&V) -> K>(
        self,
        f: F,
    ) -> HashMap<K, Vec<V>>;
}

impl<T> GroupBy<T> for Vec<T> {
    fn group_by<K: std::hash::Hash + std::cmp::Eq, F: Fn(&T) -> K>(
        self,
        f: F,
    ) -> HashMap<K, Vec<T>> {
        let mut out = HashMap::new();
        for elem in self {
            let k = f(&elem);
            out.entry(k).or_insert(vec![]).push(elem);
        }
        out
    }
}

/// Creates a vector by applying a function to each index.
///
/// # Arguments
///
/// * `n` - Number of elements to create
/// * `f` - Function that takes an index and returns a value
///
/// # Examples
///
/// ```
/// use swage_core::util::make_vec;
///
/// let squares = make_vec(5, |i| i * i);
/// assert_eq!(squares, vec![0, 1, 4, 9, 16]);
/// ```
pub fn make_vec<T>(n: usize, f: impl Fn(usize) -> T) -> Vec<T> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let val = f(i);
        v.push(val);
    }
    v
}

/// Macro for retrying operations until they succeed.
///
/// This macro continuously executes a closure until it returns `Ok`, logging errors
/// for each failed attempt. **Warning**: This creates an infinite loop if the operation
/// never succeeds.
#[macro_export]
macro_rules! retry {
    ($f:expr) => {{
        let f = $f;
        loop {
            match f() {
                Ok(x) => break x,
                Err(e) => {
                    log::error!("retry! block failed: {}", e);
                }
            }
        }
    }};
}

/// Trait for reading lines of strings from a stream with timeout support.
///
/// This trait provides a method to read a line from a stream, particularly useful
/// for reading from child process stdout with timeout handling.
pub trait ReadLine {
    /// Reads a line from the stream.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if:
    /// * The stream is closed
    /// * A timeout occurs ([`std::io::ErrorKind::WouldBlock`])
    fn read_line(&mut self) -> std::io::Result<Vec<u8>>;
}

impl ReadLine for std::process::ChildStdout {
    fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0; 1];
        let mut last_recv = None;
        const READ_TIMEOUT: Duration = Duration::from_millis(1);
        loop {
            let nbytes = self.read(&mut buf)?;
            if nbytes == 0 && last_recv.is_none() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 && last_recv.is_some_and(|t: Instant| t.elapsed() > READ_TIMEOUT) {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 {
                continue;
            }
            if buf[0] == b'\n' {
                break;
            }
            last_recv = Some(std::time::Instant::now());
            out.push(buf[0]);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::GroupBy;

    #[test]
    fn test_group_mod2() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = addrs.group_by(|x| x % 2);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&0], vec![0, 2, 4, 6, 8]);
        assert_eq!(groups[&1], vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn test_group_identity() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = addrs.group_by(|x| *x);
        for (i, group) in groups {
            assert_eq!(group.len(), 1);
            assert_eq!(group[0], i);
        }
    }

    #[test]
    fn test_group_prefix() {
        let addrs = vec!["apple", "banana", "apricot", "blueberry"];
        let groups = addrs.group_by(|x| &x[0..1]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups["a"], vec!["apple", "apricot"]);
        assert_eq!(groups["b"], vec!["banana", "blueberry"]);
    }
}
