//! Optimized SHA256 for use in Ethereum.
//!
//! The initial purpose of this crate was to provide an abstraction over the hash function used in
//! the beacon chain. The hash function changed during the specification process, so defining it
//! once in this crate made it easy to replace.
//!
//! Now this crate serves primarily as a wrapper over two SHA256 crates: `sha2` and `ring` – which
//! it switches between at runtime based on the availability of SHA intrinsics.

pub use self::DynamicContext as Context;
use sha2::Digest;

#[cfg(feature = "zero_hash_cache")]
use lazy_static::lazy_static;

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// Returns the digest of `input` using the best available implementation.
pub fn hash(input: &[u8]) -> Vec<u8> {
    Sha2CrateImpl.hash(input)
}

/// Hash function returning a fixed-size array (to save on allocations).
///
/// Uses the best available implementation based on CPU features.
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    Sha2CrateImpl.hash_fixed(input)
}

/// Compute the hash of two slices concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let mut ctxt = DynamicContext::new();
    ctxt.update(h1);
    ctxt.update(h2);
    ctxt.finalize()
}

/// Context trait for abstracting over implementation contexts.
pub trait Sha256Context {
    fn new() -> Self;

    fn update(&mut self, bytes: &[u8]);

    fn finalize(self) -> [u8; HASH_LEN];
}

/// Top-level trait implemented by both `sha2` and `ring` implementations.
pub trait Sha256 {
    type Context: Sha256Context;

    fn hash(&self, input: &[u8]) -> Vec<u8>;

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN];
}

/// Implementation of SHA256 using the `sha2` crate (fastest on CPUs with SHA extensions).
struct Sha2CrateImpl;

impl Sha256Context for sha2::Sha256 {
    fn new() -> Self {
        sha2::Digest::new()
    }

    fn update(&mut self, bytes: &[u8]) {
        sha2::Digest::update(self, bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        sha2::Digest::finalize(self).into()
    }
}

/// Context encapsulating all implemenation contexts.
///
/// This enum ends up being 8 bytes larger than the largest inner context.
pub enum DynamicContext {
    Sha2(sha2::Sha256),
}

impl Sha256Context for DynamicContext {
    fn new() -> Self {
        Self::Sha2(Sha256Context::new())
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha2(ctxt) => Sha256Context::update(ctxt, bytes),
        }
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        match self {
            Self::Sha2(ctxt) => Sha256Context::finalize(ctxt),
        }
    }
}

impl Sha256 for Sha2CrateImpl {
    type Context = sha2::Sha256;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Self::Context::digest(input).into_iter().collect()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        Self::Context::digest(input).into()
    }
}

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
lazy_static! {
    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    pub static ref ZERO_HASHES: Vec<Vec<u8>> = {
        let mut hashes = vec![vec![0; 32]; ZERO_HASHES_MAX_INDEX + 1];

        for i in 0..ZERO_HASHES_MAX_INDEX {
            hashes[i + 1] = hash32_concat(&hashes[i], &hashes[i])[..].to_vec();
        }

        hashes
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[cfg(feature = "zero_hash_cache")]
    mod zero_hash {
        use super::*;

        #[test]
        fn zero_hash_zero() {
            assert_eq!(ZERO_HASHES[0], vec![0; 32]);
        }
    }
}
