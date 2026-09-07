#![no_main]

//! Fuzz target: glob_match (resource pattern matching for delegation
//! tokens). The previous recursive implementation had a known
//! backtracking-blowup; the current iterative two-pointer walk should
//! terminate and return the right answer for any (pattern, value) pair.

use agentguard_core::delegation::glob_match;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split input at the first NUL byte (or after 256 bytes if no NUL).
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len().min(256));
    let pattern = &data[..split];
    let value = &data[split + 1..data.len().min(split + 257)];
    // Only consider printable ASCII patterns (avoid control chars in the
    // pattern; value can be anything).
    if !pattern.iter().all(|&b| b.is_ascii_graph() || b == b' ') {
        return;
    }
    let pat = match std::str::from_utf8(pattern) {
        Ok(s) => s,
        Err(_) => return,
    };
    let val = match std::str::from_utf8(value) {
        Ok(s) => s,
        Err(_) => return,
    };
    // We don't assert the result matches a reference implementation
    // (the spec is the test suite) but the function must not panic
    // and must terminate.
    let _ = glob_match(pat, val);
});
