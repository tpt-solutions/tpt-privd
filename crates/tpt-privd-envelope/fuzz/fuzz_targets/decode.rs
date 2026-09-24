//! Fuzz target: envelope decoder must never panic on arbitrary bytes.
//!
//! Run with (requires nightly + cargo-fuzz, Linux/macOS):
//!
//! ```sh
//! cargo +nightly fuzz run decode
//! ```
//!
//! See `docs/ARCHITECTURE.md` § Testing for what this covers and what it
//! does not.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_privd_envelope::{decode, decode_result};

fuzz_target!(|data: &[u8]| {
    // Both decoders must return Result and never panic, abort, or
    // allocate unboundedly (framing already enforces size limits before
    // these see bytes in the daemon path; here we also probe direct calls).
    let _ = decode(data);
    let _ = decode_result(data);
});
