#![no_main]

//! Fuzz target: canonical JSON serialization determinism + round-trip.
//!
//! Goal: confirm that `write_canonical_value` (streaming) and
//! `canonical_json` (allocating) produce byte-identical output for any
//! input, and that the streaming writer never panics on arbitrary JSON.

use agentguard_core::decision::canonical::{canonical_json, write_canonical_value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse the input as JSON; bail if it's not valid JSON.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    // Both functions must succeed on any valid JSON value.
    let Ok(allocating) = canonical_json(&value) else {
        panic!("canonical_json failed on input: {}", String::from_utf8_lossy(data));
    };
    let mut streaming = Vec::new();
    if write_canonical_value(&mut streaming, &value).is_err() {
        panic!("write_canonical_value failed on input: {}", String::from_utf8_lossy(data));
    }
    assert_eq!(
        allocating, streaming,
        "streaming output differs from allocating for: {}",
        String::from_utf8_lossy(data)
    );
});
