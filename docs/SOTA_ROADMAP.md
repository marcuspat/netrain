# NetRain SOTA roadmap

Working branch: `claude/sota-loop` (draft PR, never merged by the loop).

## Rules every loop follows

1. Take the first unticked item below. One item per loop; finish it or leave a note under it.
2. Ship it with tests. `cargo test --no-fail-fast` must be green and `cargo clippy --all-targets`
   must not gain warnings before committing.
3. Conventional commit, push to `claude/sota-loop`, tick the item here with the commit hash and a
   one-line result.
4. No paid API calls, no `cargo publish`, no merge to `main`, no version tags.
5. Tests must not need root or a live interface: use the builders in `decode::testutil`, the
   pcap fixtures in `tests/fixtures/`, or offline replay.
6. If an item turns out to be wrong or already done, say so here and move on.

## Baseline (2026-10-01, `447676b`)

- 74 passing, 1 failing (`test_ddos_detection_syn_flood`), 4 ignored.
- 40 clippy warnings, 372 rustfmt diffs, no CI.
- Findings that shaped the list:
  - Threat detection could not fire on live traffic: SYN flags were read at a raw-IP offset from
    Ethernet frames, nothing fed the port-scan tracker, and no code ever adds a threat indicator,
    so the threat panel is always "Low".
  - `packet::parse_packet` hard-codes `length: 60`; `extract_dns_query` returns the literal
    `"example.com"`; `classify_protocol` and `validate_packet` panic on some inputs.
  - Capture picks `en0` first (macOS only), filters to `ip` (no IPv6), ignores the datalink type.
  - Six mutexes are taken per packet; the per-source connection table grows without bound.
  - "MEM" in the UI is a constant 1024 KB placeholder. Terminal is left in raw mode on error.
  - The resize branch calls `event::read()` a second time, swallowing an event.

## Backlog

- [x] **0. Layered zero-copy decoder** (`src/decode.rs`): Ethernet/VLAN/QinQ, raw IP, loopback,
      Linux cooked v1/v2; IPv4 with real IHL, IPv6 with extension headers, TCP/UDP/ICMP, fragments.
      Property-tested to never panic. Threat detector now uses it: SYN (not SYN-ACK) counting works
      on Ethernet frames and port scans are tracked from packets. 75 -> 91 tests, 0 failing.
- [x] **1. One parse path** (`9d45eca`). `pipeline::observe` decodes with the capture's real datalink type and
      classifies via `classify`; the capture thread uses it (no per-packet `Packet` copy), BPF is
      `ip or ip6`, IPv6 shows in the log and top talkers, byte stats use wire length. Stubs gone:
      `parse_packet` no longer hard-codes length 60, `classify_protocol*` and `validate_packet` no
      longer panic, `extract_dns_query` parses the real question (new `dns` module, terminal-safe).
      `optimized::{parse_packet_optimized, classify_protocol_optimized}` now delegate to the same
      code. 91 -> 103 tests. Not done here: `Packet` still carries `String` addresses for API
      compatibility (moved to item 12); `extract_dns_query` now returns `Option<String>`.
- [x] **2. Threat engine v2** (`8a7b2f2`). New `alerts::ThreatEngine`: per-source sliding windows for
      vertical port scans and horizontal host sweeps, NULL/FIN/Xmas stealth scans, SYN floods
      judged by unanswered SYNs per target (a busy server that answers is not a flood), traffic
      spikes. Alerts carry source, target and evidence, dedupe while the behaviour continues and
      expire 30s after it stops. Host tables, attempt history and alerts are all capped with
      least-recently-seen eviction. Time is injected, so tests are deterministic. `ThreatDetector`
      uses it: the threat level now comes from live packets and the panel lists up to three alerts.
      The legacy `add_connection` table is bounded and no longer swept on every packet.
      103 -> 117 tests. Known cost: eviction scans the host table when full (item 12).
- [ ] **3. Capture pipeline.** Bounded channel from capture thread to UI state instead of six
      per-packet mutexes; batch drain per frame; kernel/interface drop counters from pcap stats
      shown in the UI; default interface via `Device::lookup` rather than `en0`.
- [ ] **4. CLI and safe terminal handling.** `clap`: `--interface`, `--list-interfaces`,
      `--filter <bpf>`, `--read <file.pcap>`, `--demo`. Panic hook and RAII guard that always
      restore the terminal. Clear error (not a blank UI) when capture cannot open.
- [ ] **5. Offline replay and golden tests.** `--read` replays a pcap through the same pipeline;
      end-to-end tests over `tests/fixtures/*.pcap` asserting protocol counts and alerts.
- [ ] **6. Flow table.** 5-tuple flows with packets/bytes/first-last seen/TCP state, bounded with
      idle eviction; top talkers ranked by bytes; flows panel.
- [ ] **7. Application-layer insight.** Real DNS question parsing (compression-pointer loop
      safe), TLS ClientHello SNI, HTTP Host; hostnames in the packet log. QUIC long-header
      detection on UDP 443.
- [ ] **8. Protocol coverage.** ICMP/ICMPv6, ARP, QUIC, NTP, DHCP, mDNS, SSDP as first-class
      protocols; `#[non_exhaustive]` on public enums; port table instead of if-chains.
- [ ] **9. UI.** Resize handling (and the swallowed-event bug), pause (space), help overlay (`?`),
      protocol filter keys, real process memory (RSS) instead of the placeholder, threat
      colouring in the rain.
- [ ] **10. Machine-readable output.** `--json` NDJSON stream of packets/alerts, `--headless` for
      servers and pipes, summary on exit; schema documented and tested.
- [ ] **11. Least privilege.** Open capture then drop root; document `setcap cap_net_raw,
      cap_net_admin+eip`; smaller snaplen; immediate mode; promiscuous off unless requested.
- [ ] **12. Performance, measured.** Benchmarks on the real decode -> classify -> detect path,
      remove per-packet `String`/`Vec` allocations and the `unsafe get_unchecked`, record numbers
      in `docs/PERFORMANCE.md`; README claims must match them.
- [ ] **13. Fuzzing and hardening.** `cargo-fuzz` targets for decoder, DNS and TLS parsers with a
      seed corpus; `#![forbid(unsafe_code)]` in the library; remove remaining panics on input.
- [ ] **14. CI and supply chain.** GitHub Actions: fmt, clippy `-D warnings`, tests on Linux and
      macOS, MSRV, `cargo-deny`/`cargo-audit`; one `cargo fmt` commit; dependency upgrades
      (ratatui, crossterm, pcap); release workflow with checksummed binaries.
- [ ] **15. Truth pass and release notes.** README features checked against the code (rainbow
      mode, 3D depth, particle effects, memory metric), CHANGELOG, architecture note, PR rewritten
      as a release summary with what is and is not verified.
