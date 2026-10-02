#![no_main]
//! Link/IP/transport decoding and classification, for every link type.
use libfuzzer_sys::fuzz_target;
use netrain::decode::{decode, LinkType};

fuzz_target!(|data: &[u8]| {
    for link in [LinkType::Ethernet, LinkType::RawIp, LinkType::Null, LinkType::LinuxSll, LinkType::LinuxSll2] {
        if let Ok(decoded) = decode(link, data) {
            assert!(decoded.payload.len() <= data.len());
            let _ = netrain::classify::classify(&decoded);
            let _ = netrain::inspect::insight(&decoded);
        }
    }
    let _ = netrain::classify::classify_bytes(data);
});
