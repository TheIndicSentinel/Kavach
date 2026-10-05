//! A small seeded generator (SplitMix64), so a seed gives the same run on
//! every machine and Rust version, without depending on a crate's stream.

#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// True with probability `p` (0 never, 1 always).
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        // 53 random bits as a fraction in [0, 1).
        #[allow(clippy::cast_precision_loss)]
        let fraction = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        fraction < p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_is_a_fixed_stream() {
        let (mut a, mut b) = (Rng::new(7), Rng::new(7));
        let first: Vec<u64> = (0..5).map(|_| a.next_u64()).collect();
        assert_eq!(first, (0..5).map(|_| b.next_u64()).collect::<Vec<_>>());
        let mut other = Rng::new(8);
        assert_ne!(first, (0..5).map(|_| other.next_u64()).collect::<Vec<_>>());
        // The SplitMix64 reference value for seed 0.
        assert_eq!(Rng::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
    }

    #[test]
    fn chances_are_bounded_and_roughly_fair() {
        let mut rng = Rng::new(1);
        assert!(!rng.chance(0.0));
        assert!(rng.chance(1.0));
        let hits = (0..10_000).filter(|_| rng.chance(0.25)).count();
        assert!((2_200..2_800).contains(&hits), "{hits}");
    }
}
