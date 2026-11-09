//! Our own S3 header parsers (s3s parses the rest): `x-tidemark-as-of`, `x-amz-tagging`,
//! `x-amz-copy-source-range`. Never panic; a parsed range is ordered.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tidemark_core::Ts;
use tidemark_s3::fuzzing::{as_of, copy_range, parse_tagging};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Ts::parse(s);
    if let Ok(v) = http::HeaderValue::from_str(s) {
        let mut h = http::HeaderMap::new();
        h.insert("x-tidemark-as-of", v);
        let _ = as_of(&h);
    }
    // Limits (10 tags, key ≤ 128, value ≤ 256) are the engine's job (`validate_tags`).
    let _ = parse_tagging(Some(s));
    if let Ok((first, last)) = copy_range(s) {
        assert!(first <= last, "{s:?} parsed to {first}-{last}");
    }
});
