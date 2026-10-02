# JSON output

`netrain --json` prints newline-delimited JSON on stdout: one object per line, no UI.
It works with live capture and with `--read FILE`, and never needs a terminal.

```sh
sudo netrain --json | jq -c 'select(.type == "alert")'
netrain --read trace.pcap --json --alerts-only
netrain --read trace.pcap --summary --json        # just the summary object
sudo netrain --json --count 1000 > sample.ndjson  # stop after 1000 packets
```

Every object has a `type`. Fields are only ever added; consumers should ignore fields they
do not know. Optional fields are omitted when they do not apply, never `null`.

## `packet`

| field | type | notes |
|---|---|---|
| `ts` | number | capture time, seconds since the Unix epoch |
| `ts_us` | integer | the same instant in microseconds (exact) |
| `src`, `dst` | string | IPv4 or IPv6 address |
| `src_port`, `dst_port` | integer | TCP and UDP only |
| `protocol` | string | `TCP`, `UDP`, `HTTP`, `HTTPS`, `DNS`, `SSH`, `ICMP`, `QUIC`, `NTP`, `DHCP`, `MDNS`, `SSDP` or `???` |
| `ip_proto` | integer | IP protocol number (6 TCP, 17 UDP, ...) |
| `length` | integer | bytes on the wire |
| `tcp_flags` | string | TCP only: letters from `S F R P A U`, e.g. `SA` |
| `host` | object | `{"source": "dns" \| "sni" \| "host", "name": "..."}` when the packet reveals a hostname |

## `alert`

Written once when an alert is raised and once when it clears.

| field | type | notes |
|---|---|---|
| `ts`, `ts_us` | number, integer | time of the packet that changed the alert's state |
| `state` | string | `raised` or `cleared` |
| `alert` | string | `Port scan`, `Host sweep`, `Stealth scan`, `SYN flood`, `Traffic spike` |
| `severity` | string | `medium` or `high` |
| `source` | string | the host responsible, when there is one |
| `target` | string | the host on the receiving end, when there is one |
| `detail` | string | the evidence, e.g. `20 ports in 60s` |

An alert only clears when a later packet arrives after it has expired, because time in the
stream advances with packets. Alerts still active at the end are listed in the summary.

## `summary`

Always the last line, also after Ctrl-C or SIGTERM.

| field | type | notes |
|---|---|---|
| `schema` | integer | version of this format, currently 1 |
| `packets` | integer | packets decoded and analysed |
| `undecodable` | integer | packets that were not IP or were malformed |
| `bytes` | integer | bytes on the wire |
| `duration_secs` | number | time between the first and last packet |
| `flows` | integer | distinct conversations seen |
| `peak_threat` | string | `low`, `medium`, `high` or `critical` |
| `protocols` | object | packet count per protocol label |
| `hostnames` | array | every hostname seen |
| `alerts` | array | every alert raised, without evidence counts |
| `top_talkers` | array | up to five of `{"address", "bytes", "packets"}` |
| `dropped` | integer | packets lost in the kernel or interface before analysis (live capture) |

## Plain text

`--headless` prints the same events as greppable text:

```
1700000000.200000 HTTPS 192.168.1.10:50001 -> 93.184.216.34:443 134B [PA] sni=example.com
1700000001.000000 ALERT Port scan 203.0.113.7 -> 10.0.0.1 (20 ports in 60s)
```

## Behaviour

- If the reader goes away (`netrain --json | head`), netrain stops quietly with exit code 0.
- Hostnames are validated before they are written, so the stream cannot be broken or spoofed
  by a crafted packet.
- For a capture file the output depends only on the file: the clock is the recorded timestamps.
