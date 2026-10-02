# Architecture

netrain is a library (`src/lib.rs` and its modules) plus a thin binary (`src/main.rs`).
Everything that touches packet bytes is in the library and is tested without root, a network
or a terminal.

## Data flow

```
              capture thread                          UI thread
 libpcap --> decode --> classify --> PacketRecord ==> AppState --> ratatui
             (borrowed)  inspect      (owned,      |   stats, flows, names,
                                       ~150 bytes) |   ThreatDetector, log
                                 bounded channel --+
```

Headless modes (`--json`, `--headless`, `--summary`) skip the channel and the UI:

```
 libpcap --> ReplayAnalyzer (decode, classify, inspect, flows, ThreatEngine) --> Exporter --> stdout
```

## Modules

| module | role |
|---|---|
| `decode` | Link layer (Ethernet + VLAN, raw IP, loopback, Linux cooked), IPv4/IPv6 with extension headers, TCP/UDP/ICMP. Borrow-only; returns `DecodeError`, never panics. |
| `classify` | `Decoded` -> `Protocol`: payload signatures first, then well-known ports. |
| `inspect` | Hostnames from TLS SNI, HTTP `Host` and DNS questions; `NameCache` of address -> name from DNS answers. |
| `dns` | DNS question and A/AAAA answer parsing. |
| `pipeline` | `observe(link, bytes)` -> `PacketEvent`: the one decode-and-classify entry point. |
| `capture` | Bounded channel between capture and UI, drop counters, interface choice, replay pacing. |
| `state` | `AppState`: everything the UI shows, owned by the UI thread; user commands. |
| `alerts` | `ThreatEngine`: sliding-window detection with expiring, bounded alerts. Time is passed in. |
| `threat_detection` | `ThreatDetector`: the older public API, now a wrapper around `ThreatEngine`. |
| `flows` | Bidirectional 5-tuple flow table and per-host totals. |
| `replay` | `ReplayAnalyzer`: the pipeline driven by capture timestamps; `ReplaySummary`. |
| `export` | NDJSON and text output. |
| `pcapfile` | Pure-Rust classic pcap reader and writer. |
| `synth` | Builders for well-formed packets, used by tests, fixtures and benchmarks. |
| `sysinfo` | Resident memory of the process. |
| `simple_matrix` | The rain widget the binary uses. |
| `matrix_rain`, `optimized`, `packet` | Older code kept for API compatibility (see below). |

Binary-only: `cli` (clap definitions), `term` (terminal guard and panic hook), `privs`
(privilege drop).

## Design rules

1. **Packet bytes are hostile.** No `unsafe` in the library (`#![forbid(unsafe_code)]`), no
   indexing without a bounds check, no panics on input. Enforced by property tests and the
   mutation fuzzer in `tests/fuzz_smoke.rs`.
2. **Nothing grows without bound.** Each table has a cap and evicts the least recently used
   entries in batches, so a flood of spoofed addresses costs bounded memory and amortised
   constant time per packet.
3. **Time is an input.** The threat engine and the analyser take the current time as an
   argument. Live capture passes the wall clock; replay passes the capture's timestamps, which
   makes analysis of a file deterministic.
4. **The capture thread never waits for the UI.** It uses `try_send`; a full queue increments a
   counter. Replay uses a blocking send instead, because losing packets there would make the
   result wrong.
5. **Display only validated text.** Hostnames are restricted to hostname characters before
   they reach the terminal or the JSON stream.
6. **Privilege is for opening the capture, nothing else.** See `docs/PRIVILEGES.md`.

## Legacy code

- `matrix_rain::MatrixRain` (rainbow mode, particles, depth) is a more elaborate rain widget
  that the binary does not use; `simple_matrix::SimpleMatrixRain` is what runs. It remains
  exported and tested.
- `packet` and `optimized` expose the original `Packet`-based functions. They now delegate to
  `decode`/`classify`, and guess the framing of the buffer they are given. New code should use
  `pipeline::observe` with a real `LinkType`.
- `RainManager`, `RainColumn`, `calculate_fall_speed` and friends in `lib.rs` are helpers from
  the original test-first scaffold; nothing in the binary calls them.

## Testing layers

| layer | where | what it shows |
|---|---|---|
| unit + property | each module | parsers and state machines, including "never panics" |
| golden | `tests/replay_golden.rs` | real pcap fixtures give exact protocol counts and alerts |
| binary | `tests/cli_tests.rs`, `tests/headless_tests.rs` | flags, exit codes, JSON schema, privilege drop |
| fuzz smoke | `tests/fuzz_smoke.rs` | mutated packets and capture files through every parser and the stateful pipeline |
| benchmarks | `benches/pipeline.rs` | throughput on a traffic mix and under attack |
