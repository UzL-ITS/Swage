use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::Serialize;

/// Seedable random number generator.
///
/// Wraps StdRng to provide deterministic randomness from a seed value.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Rng {
    seed: u64,
    #[serde(skip_serializing)]
    rng: StdRng,
}

impl Rng {
    /// Creates a new RNG from a seed value.
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed value for deterministic random generation
    pub fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }
}

impl Clone for Rng {
    fn clone(&self) -> Self {
        Self::from_seed(self.seed)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::Rng;
    use rand::RngCore;

    #[test]
    fn test_rng_clone() {
        let mut rng = Rng::from_seed(0x42);
        let a = rng.next_u64();
        let mut cloned_rng = rng.clone();
        let b = cloned_rng.next_u64();
        assert_eq!(a, b, "Cloned Rng should start with the same seed");
    }
}
