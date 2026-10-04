#![no_main]
//! Application-layer parsers: DNS, TLS SNI, HTTP Host. Any name they return
//! must be safe to print.
use libfuzzer_sys::fuzz_target;
use netrain::{dns, inspect};

fuzz_target!(|data: &[u8]| {
    let _ = dns::question_name(data);
    let _ = dns::answers(data);
    for name in [inspect::tls_sni(data), inspect::http_host(data)].into_iter().flatten() {
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)));
    }
});
