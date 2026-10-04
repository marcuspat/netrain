# Performance

Measured with `cargo bench --bench pipeline` (criterion) on the development container:
2 vCPUs, Intel Xeon @ 2.10GHz, Linux, release build, single thread. Your numbers will differ;
the ratios and the "under attack" behaviour are the point. These are benchmarks of netrain's
own code on synthetic packets held in memory - they do not include libpcap, the kernel or
terminal rendering, and they are not a measured end-to-end capture rate.

## Per packet

| stage | throughput | per packet |
|---|---|---|
| decode (link, IP, transport) | 50 M packets/s | 20 ns |
| decode + classify | 17 M packets/s | 59 ns |
| everything the capture thread does (decode, classify, hostname extraction, build record) | 11 M packets/s | 89 ns |
| capture thread -> channel -> UI state (statistics, flows, threat engine, log line) | 1.05 M packets/s | 0.95 us |
| headless analysis (`--json` / `--summary` path, without output formatting) | 3.1 M packets/s | 0.33 us |

The traffic mix is mostly 1400-byte TLS data segments and bare ACKs, with handshakes, a
ClientHello and DNS queries.

## Under attack

A monitor must not fall over when the thing it is watching for happens. Each case feeds
20,000 SYN packets.

| case | before this work | now |
|---|---|---|
| threat engine, SYN flood from 20,000 spoofed sources | 28 K packets/s | 1.2 M packets/s |
| threat engine, one source scanning 20,000 ports | 49 K packets/s | 1.8 M packets/s |
| headless analysis of the spoofed flood | 26 K packets/s | 0.54 M packets/s |
| flow table, every packet a new flow | 1.4 M packets/s | 1.4 M packets/s |

What changed:

- Scan detection kept a per-source history and rebuilt two hash sets from it on every SYN.
  It now keeps running counts of distinct ports per host and hosts per port, updated as
  attempts enter and leave the window: O(1) per packet.
- When a host table was full, every new host triggered a scan of the whole table to find the
  oldest entry. Eviction now removes the oldest eighth in one pass.
- A continuing alert refreshed its evidence by allocating a new string per packet; it now
  rewrites the existing one.
- Headless analysis re-read and re-sorted the alert list on every packet; it now does so only
  when a new alert is raised or once per second of stream time.

## Memory

Every table is capped, so memory does not grow with traffic or with the number of spoofed
addresses: 4096 tracked sources and 4096 targets in the threat engine, 512 remembered
attempts per source, 8192 flows, 4096 hosts, 4096 cached names, 500 log lines, and a queue of
8192 packet records between capture and UI. The demo runs at about 10 MB resident.

## What is not measured

- Packets per second on a real interface. That depends on libpcap, the kernel buffer and the
  NIC; the `DROP` counter in the UI and `dropped` in the JSON summary report losses when they
  happen.
- Rendering cost. The UI is paced at about 60 frames per second and drains at most 4096
  records per frame, so display throughput is capped near 245 K packets/s; beyond that,
  records are dropped and counted rather than slowing capture.

## Reproducing

```sh
cargo bench --bench pipeline
cargo bench --bench pipeline -- under_attack     # one group
```
