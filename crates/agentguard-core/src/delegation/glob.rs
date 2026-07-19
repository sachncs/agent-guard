//! Glob-pattern matching for delegation-token resource patterns.
//!
//! Supports `*` (matches any sequence of characters, including empty).
//! The match is greedy: it matches the longest possible prefix of the
//! value against the literal prefix, then advances.
//!
//! Implementation: a two-pointer walk that avoids both the recursion and
//! the Vec<&str> allocation of the previous version. The
//! `*`-delimited segments are matched left-to-right; on any partial
//! failure we back up the segment pointer to the previous `*` position
//! and try the next value position.

/// Glob match. Returns true if `value` matches `pattern` under the
/// `*` wildcard.
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let pat = pattern.as_bytes();
    let val = value.as_bytes();
    let pat_len = pat.len();
    let val_len = val.len();
    // Find split points: positions of each '*' in `pat`.
    let mut stars: Vec<usize> = Vec::new();
    for (i, &b) in pat.iter().enumerate() {
        if b == b'*' {
            stars.push(i);
        }
    }
    let n_stars = stars.len();
    // Walk the non-wildcard prefix P0.
    let p0_end = stars[0];
    if !slice_eq(pat, 0, p0_end, val, 0) {
        return false;
    }
    let mut vi = p0_end;
    // Match segments P1..Pn greedily from the start; on failure,
    // backtrack by incrementing the previous value position.
    let mut s: Vec<usize> = vec![vi];
    for i in 0..n_stars {
        let seg_start = stars[i] + 1;
        let seg_end = if i + 1 < n_stars {
            stars[i + 1]
        } else {
            pat_len
        };
        let seg_len = seg_end - seg_start;
        if i + 1 == n_stars {
            // Last segment: must be a suffix of value.
            if seg_len == 0 {
                return true;
            }
            return val_len >= vi + seg_len
                && slice_eq(pat, seg_start, seg_end, val, val_len - seg_len);
        }
        // Find pat[seg_start..seg_end] in val starting at or after vi.
        let mut pos = s[i];
        loop {
            if pos + seg_len > val_len {
                return false;
            }
            if slice_eq(pat, seg_start, seg_end, val, pos) {
                vi = pos + seg_len;
                s.push(vi);
                break;
            }
            pos += 1;
        }
    }
    false
}

#[inline]
fn slice_eq(a: &[u8], a_start: usize, a_end: usize, b: &[u8], b_start: usize) -> bool {
    let len = a_end - a_start;
    if b_start + len > b.len() {
        return false;
    }
    a[a_start..a_end] == b[b_start..b_start + len]
}

#[cfg(test)]
pub(crate) fn glob_match_test() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("Mailbox::*", "Mailbox::\"alice@x\""));
    assert!(glob_match("Mailbox::\"alice*\"", "Mailbox::\"alice@x\""));
    assert!(!glob_match("Mailbox::\"bob*\"", "Mailbox::\"alice@x\""));
    // Multiple wildcards.
    assert!(glob_match("a*b*c", "axbxc"));
    assert!(glob_match("a*b*c", "abxc"));
    assert!(glob_match("a*b*c", "axbxc"));
    // The previous "overly strict" bug: pattern "a*x*" should match "axxby"
    // (first * matches "xx", second * matches "y" after consuming "b").
    assert!(glob_match("a*x*", "axxby"));
}
