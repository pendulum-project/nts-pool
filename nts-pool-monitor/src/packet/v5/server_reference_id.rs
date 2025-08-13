use rand::distr::{Distribution, StandardUniform};
use rand::{Rng, rng};
use std::array::from_fn;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug)]
struct U12(u16);

impl U12 {
    pub const MAX: Self = Self(4095);

    /// For an array of bytes calculate the index at which a bit would live as well as a mask where the
    /// corresponding bit in that byte would be set
    const fn byte_and_mask(self) -> (usize, u8) {
        (self.0 as usize / 8, 1 << (self.0 % 8))
    }
}

impl Distribution<U12> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> U12 {
        U12(rng.gen_range(0..4096))
    }
}

impl From<U12> for u16 {
    fn from(value: U12) -> Self {
        value.0
    }
}

impl TryFrom<u16> for U12 {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value > Self::MAX.into() {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ServerId([U12; 10]);

impl ServerId {
    /// Generate a new random `ServerId`
    pub fn new(rng: &mut impl Rng) -> Self {
        // FIXME: sort IDs so we access the filters predictably
        // FIXME: check for double rolls to reduce false positive rate

        Self(from_fn(|_| rng.r#gen()))
    }
}

impl Default for ServerId {
    fn default() -> Self {
        Self::new(&mut rng())
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct BloomFilter([u8; Self::BYTES]);
impl BloomFilter {
    pub const BYTES: usize = 512;

    pub const fn new() -> Self {
        Self([0; Self::BYTES])
    }

    pub fn contains_id(&self, other: &ServerId) -> bool {
        other.0.iter().all(|idx| self.is_set(*idx))
    }

    pub fn add_id(&mut self, id: &ServerId) {
        for idx in id.0 {
            self.set_bit(idx);
        }
    }

    pub fn add(&mut self, other: &BloomFilter) {
        for (ours, theirs) in self.0.iter_mut().zip(other.0.iter()) {
            *ours |= theirs;
        }
    }

    pub fn union<'a>(others: impl Iterator<Item = &'a BloomFilter>) -> Self {
        let mut union = Self::new();

        for other in others {
            union.add(other);
        }

        union
    }

    pub fn count_ones(&self) -> u16 {
        self.0.iter().map(|b| b.count_ones() as u16).sum()
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }

    const fn set_bit(&mut self, idx: U12) {
        let (idx, mask) = idx.byte_and_mask();
        self.0[idx] |= mask;
    }

    const fn is_set(&self, idx: U12) -> bool {
        let (idx, mask) = idx.byte_and_mask();
        self.0[idx] & mask != 0
    }
}

impl<'a> FromIterator<&'a BloomFilter> for BloomFilter {
    fn from_iter<T: IntoIterator<Item = &'a BloomFilter>>(iter: T) -> Self {
        Self::union(iter.into_iter())
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for BloomFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: String = self
            .0
            .chunks_exact(32)
            .map(|chunk| chunk.iter().fold(0, |acc, b| acc | b))
            .map(|b| char::from_u32(0x2800 + b as u32).unwrap())
            .collect();

        f.debug_tuple("BloomFilter").field(&str).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_bits() {
        let mut rid = BloomFilter::new();
        assert!(rid.0.iter().all(|x| x == &0));
        assert!((0..4096).all(|idx| !rid.is_set(U12(idx))));
        assert_eq!(rid.count_ones(), 0);

        rid.set_bit(U12(0));
        assert_eq!(rid.count_ones(), 1);
        assert!(rid.is_set(U12(0)));
        assert_eq!(rid.0[0], 1);

        rid.set_bit(U12(4));
        assert_eq!(rid.count_ones(), 2);
        assert!(rid.is_set(U12(4)));
        assert_eq!(rid.0[0], 0b0001_0001);

        rid.set_bit(U12::MAX);
        assert_eq!(rid.count_ones(), 3);
        assert!(rid.is_set(U12::MAX));
        assert_eq!(rid.0[511], 0b1000_0000);
    }

    #[test]
    fn set_contains() {
        let mut filter = BloomFilter::new();

        let id = ServerId::default();
        assert!(!filter.contains_id(&id));

        filter.add_id(&id);
        assert!(filter.contains_id(&id));

        for _ in 0..128 {
            let rid = ServerId::default();

            filter.add_id(&rid);
            assert!(filter.contains_id(&rid));
        }
    }

    #[test]
    fn set_collect() {
        let mut ids = vec![];
        let mut filters = vec![];

        for _ in 0..10 {
            let id = ServerId::default();
            let mut filter = BloomFilter::new();
            filter.add_id(&id);

            ids.push(id);
            filters.push(filter);
        }

        let set: BloomFilter = filters.iter().collect();

        for rid in &ids {
            assert!(set.contains_id(rid));
        }
    }
}
