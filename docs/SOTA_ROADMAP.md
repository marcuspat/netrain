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
- [x] **3. Capture pipeline** (`fb2129d`). `capture` module: the capture thread decodes and pushes a
      small owned record into a bounded channel (8192) with `try_send`; a full queue drops and
      counts instead of blocking. `state::AppState` owns all display state on the UI thread and
      drains up to 4096 records per frame, so there are no per-packet locks left (was six
      mutexes). Kernel and interface drops come from pcap stats once a second and show as `DROP`
      in the PERF panel. Default interface is chosen by `choose_device` (non-loopback, up,
      running, has an address) on any OS instead of `en0`. Capture errors after start are now
      reported instead of silently ending the thread. Fixed the double `event::read()` that
      swallowed an event. 117 -> 128 tests. Smoke-tested in a pty: `--demo` renders, and live
      capture as root in the dev container showed real HTTPS packets with real addresses.
- [x] **4. CLI and safe terminal handling** (`fbba6a1`). `clap` CLI: `-i/--interface`,
      `-l/--list-interfaces`, `-f/--filter <bpf>`, `-r/--read <file.pcap>` with `--speed`,
      `--demo`, `--no-splash`; unknown or conflicting flags now exit 2 (a typo such as `--dmeo`
      used to start a live capture). The source is opened and the filter compiled *before* the
      TUI starts, so a missing file, bad filter, unknown interface or missing privileges is a
      one-line `netrain: ...` error with exit code 1. `term::TerminalGuard` restores the terminal
      on every exit path and from a panic hook. Mouse capture is no longer enabled (it was unused
      and blocked text selection). `--read` replays through the live pipeline, paced by the
      recorded timestamps, without dropping. 128 -> 144 tests, including black-box tests of the
      binary. Smoke-tested in a pty: replaying a synthetic 40-port scan raised the port-scan alert.
      Finding: `tests/fixtures/*.pcap` are not valid pcap files (ASCII `PCAP` magic); item 5 must
      generate real ones.
- [x] **5. Offline replay and golden tests** (`b4ce58c`). `pcapfile`: pure-Rust classic pcap
      reader/writer (both endiannesses, micro/nano), property-tested. `replay::ReplayAnalyzer`
      runs the live pipeline on the capture's own timestamps, so a file always yields the same
      summary. `netrain --read FILE --summary` prints it without a terminal. The four fixtures
      are now real pcap files generated by reviewable builders in `tests/replay_golden.rs`
      (public `synth` module); a test fails if a file drifts from its builder. Golden tests assert
      protocol counts and alerts per fixture, and that the binary (via libpcap) agrees with the
      library. Bug found by them: the default BPF `ip or ip6` dropped every VLAN-tagged frame;
      it is now `ip or ip6 or (vlan and (ip or ip6))`. 144 -> 161 tests.
- [x] **6. Flow table** (`30842e5`). `flows::FlowTable`: bidirectional 5-tuple flows with
      per-direction packets/bytes, first/last seen, the most specific protocol seen, and a coarse
      TCP state (opening, open, closing, reset). Per-host totals give top talkers ranked by bytes
      (the old list ranked by packet count and replaced entries arbitrarily). Capped at 8192 flows
      and 4096 hosts with batch eviction of the least recently active, so a flood of new flows
      costs amortised O(1) per packet; idle flows expire after 60s, closed ones after 5s. The log
      panel shows top talkers and top flows; `--summary` reports flow count and top talkers.
      161 -> 169 tests.
- [x] **7. Application-layer insight** (`65da3c6`). `inspect` module: TLS ClientHello SNI, HTTP
      `Host` header and DNS question names, each validated to hostname characters only so a
      crafted packet cannot put terminal escape codes on screen. The packet log appends
      `sni=`/`host=`/`dns=`; flows carry their server name. DNS answers (A/AAAA, with compression
      pointers, loop-safe) fill a bounded address->name cache, so top talkers read
      `93.184.216.34 (example.com)` without netrain ever issuing a lookup itself. QUIC long-header
      packets on UDP 443 are classified as HTTPS (own label in item 8). `--summary` lists
      hostnames. Property tests on every parser. 169 -> 181 tests. Live smoke test in the dev
      container extracted a real SNI from real traffic.
- [x] **8. Protocol coverage** (`453e7d2`). New labels: ICMP (v4 and v6), QUIC, NTP, DHCP (v4 and v6),
      mDNS, SSDP. `Protocol` and `AlertKind` are `#[non_exhaustive]`; `Protocol::ALL`/`index()`
      replace hand-written per-protocol fields, so the activity tracker, the PROTOCOLS panel
      (busiest six seen) and the sparklines (busiest six) are data-driven instead of hard-coded
      to six names. UDP services use a port table. Not done: ARP, because it is not IP and the
      decoder and default filter are IP-only by design. Breaking for library users:
      `ProtocolSnapshot`'s public per-protocol fields became `get(protocol)`.
      Also this loop, from the review comment on PR #38: an IPv6 extension chain deeper than the
      decoder follows is now an error (it used to report an extension-header number as
      `ip_proto`); the default interface prefers a live loopback over a dead Ethernet port; and a
      regression test pins that an answering server is not flagged while the target table churns
      (the reported false positive did not reproduce). 181 -> 187 tests.
- [x] **9. UI** (`d7e2361`). Keys: space/p pause (the log and hex dump hold still; statistics, flows
      and threat detection keep running and the bar shows how many packets were skipped), f cycle
      a protocol filter over the log, a show all, ?/h help overlay, esc dismiss, q quit. The rain
      follows terminal resizes; below 80x24 a clear "too small" message replaces the layout.
      MEM shows the real resident set size from `/proc/self/status` (`n/a` where unavailable,
      e.g. macOS) instead of a constant 1.0MB. The loop is now paced by the input wait at ~60 FPS
      (it used to spin as fast as it could redraw), and FPS is measured between frames rather than
      from render time. Log lines carry their protocol, so colours no longer come from substring
      matching, and the log keeps 500 lines so a filter has material. Per-packet address
      formatting for the unused rain tracker is gone. 187 -> 197 tests. Driven in a pty: help,
      pause, filter, quit, shrink-below-minimum and grow all behaved. Not done: threat colouring
      inside the rain itself (the border already turns red).
- [x] **10. Machine-readable output** (`60ce0c9`). `--json` streams NDJSON (`packet`, `alert`
      raised/cleared, final `summary`) and `--headless` prints the same as greppable text; both
      run without a terminal on live capture or `--read`. `--alerts-only`, `--count N`, and
      `--summary --json` for a single summary object. Ctrl-C/SIGTERM still write the summary; a
      reader that goes away (`| head`) ends the run quietly with exit 0. For a file the output is
      byte-identical across runs. Schema in `docs/JSON_OUTPUT.md` (version 1), pinned by tests.
      197 -> 214 tests. Checked live in the dev container: `--json --alerts-only` under SIGINT
      printed the summary with real traffic. Adds `signal-hook` as a direct dependency (it was
      already in the tree via crossterm). `--demo` is not supported with these modes.
- [x] **11. Least privilege** (`331c359`). Root is dropped right after the capture is opened and the
      filter compiled: to the invoking user under `sudo`, otherwise to `nobody`; supplementary
      groups cleared, gid then uid set, and the drop verified irreversible (netrain exits if it
      is not). All packet parsing, the UI and JSON output therefore run unprivileged.
      `--keep-privileges` opts out. Promiscuous mode is now opt-in (`--promiscuous`; it was
      always on), snap length defaults to 1600 (`--snaplen`; was 5000), read timeout 100ms
      (was 1s, which batched the display). `docs/PRIVILEGES.md` covers the drop, `setcap`, macOS
      and the defaults. 214 -> 220 tests, including a root-only loopback test that asserts the
      drop and that packets still arrive afterwards (it ran here as root). Adds `libc` as a
      direct dependency. Not verified: the `sudo` path (SUDO_UID) and macOS, neither available
      in the dev container; the target-selection logic for them is unit-tested.
- [x] **12. Performance, measured** (`402e211`). `benches/pipeline.rs` measures the real path
      (decode, classify, hostname extraction, channel, state, threat engine, flows) on a traffic
      mix and under attack. The benchmarks found the threat engine collapsing under exactly what
      it detects: 28 K packets/s in a spoofed SYN flood and 49 K in a port scan. Fixed with
      incremental distinct-port/host counters (O(1) per packet), batch eviction, in-place alert
      refresh and revision-gated alert diffing: now 1.2 M and 1.8 M packets/s; headless analysis
      of a flood 26 K -> 544 K. Numbers and method in `docs/PERFORMANCE.md`; the README
      performance section now quotes them instead of the old "29ns" and "zero-allocation"
      claims. The last `unsafe` (`get_unchecked`) is gone. 220 -> 222 tests. Not done: the legacy
      `Packet` struct still carries `String` addresses; the live path does not use it.
- [x] **13. Fuzzing and hardening** (`67979ce`). `#![forbid(unsafe_code)]` on the library.
      `tests/fuzz_smoke.rs` is a deterministic mutation fuzzer that runs on stable with
      `cargo test`: it mutates valid packets and capture files and drives every parser, the legacy
      API, and the stateful pipeline (channel, UI state, analyser, JSON exporter) with hostile
      timestamps and lengths, checking that every output line is valid JSON. It found two panics,
      both fixed: adding an absurd capture timestamp to an `Instant`, and byte-counter overflow
      from a corrupt length (counters now saturate). Also removed: the panic in
      `calculate_rain_density` on a negative rate. Clean at 1.5 M iterations in a debug build
      (overflow checks on) and 3 M in release. `fuzz/` holds `cargo-fuzz` targets (decode,
      inspect, pcap_file) for coverage-guided runs; they are **not run** - no nightly toolchain
      was installable here. 222 -> 226 tests.
- [ ] **14. CI and supply chain.** GitHub Actions: fmt, clippy `-D warnings`, tests on Linux and
      macOS, MSRV, `cargo-deny`/`cargo-audit`; one `cargo fmt` commit; dependency upgrades
      (ratatui, crossterm, pcap); release workflow with checksummed binaries.
- [ ] **15. Truth pass and release notes.** README features checked against the code (rainbow
      mode, 3D depth, particle effects, memory metric), CHANGELOG, architecture note, PR rewritten
      as a release summary with what is and is not verified.
