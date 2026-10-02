#![no_main]
//! A whole capture file through the reader, the analyser and the exporter.
use libfuzzer_sys::fuzz_target;
use netrain::replay::analyze_pcap;

fuzz_target!(|data: &[u8]| {
    if let Ok(summary) = analyze_pcap(data) {
        let _ = summary.to_string();
        let line = netrain::export::summary_json(&summary, 0);
        assert!(!line.contains('\n'));
    }
});
