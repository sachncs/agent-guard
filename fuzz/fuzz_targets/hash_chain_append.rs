#![no_main]

//! Fuzz target: HashChain::append + verify round-trip.
//!
//! Goal: ensure that for any byte string, the chain appends it,
//! computes a hash, and verify() on the same chain accepts the
//! returned (prev, hash) pair. The original was a no-op for several
//! critical months (commit history shows two prior bypasses); a
//! regression of the same kind would be caught here.

use agentguard_core::decision::chain::HashChain;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let chain = HashChain::new(b"fuzz-root-key");
    let (prev, hash) = chain.append(data);
    // Self-verify: the chain must accept the (prev, hash) it just produced.
    chain.verify(data, &prev, &hash).expect("chain must accept its own output");
});
