# Privileges

Capturing packets needs permission from the operating system. netrain asks for as little as
possible and gives it back early.

## What netrain does

1. Opens the capture and compiles the filter. This is the only step that needs privilege.
2. Drops root immediately afterwards:
   - under `sudo`, back to the user who ran it (`SUDO_UID` / `SUDO_GID`);
   - as plain root (a root shell, a container), to `nobody` (uid 65534);
   - it clears supplementary groups, sets the group, then the user, and then checks that root
     cannot be regained. If any step fails, netrain exits rather than continue as root.
3. Everything after that - decoding packets, the UI, JSON output - runs unprivileged.

Packet contents are attacker-controlled input. Parsing them without privilege means a parser
bug cannot be escalated to root.

`--headless` and `--json` print the result on stderr:

```
netrain: capturing on eth0, dropped root, running as uid 1000 gid 1000
```

`--keep-privileges` turns the drop off. There should be no reason to use it; it exists for
debugging.

## Running without sudo (Linux)

Grant the binary the capture capabilities once:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v netrain)"
netrain            # no sudo
```

`cap_net_raw` is what opening the capture needs; `cap_net_admin` is only needed for
`--promiscuous`. The capabilities are attached to that file: reinstalling or rebuilding
netrain removes them, and anyone who can run the binary can capture, so restrict who can
execute it if that matters:

```sh
sudo chgrp netdev "$(command -v netrain)" && sudo chmod 750 "$(command -v netrain)"
```

## macOS

Capture devices are `/dev/bpf*`. Either run `sudo netrain` (root is dropped as above), or
install Wireshark's "ChmodBPF" helper, which makes those devices readable by the
`access_bpf` group.

## No privileges needed

- `netrain --demo` - synthetic traffic.
- `netrain --read file.pcap` - replay or `--summary` of a capture taken elsewhere, for example
  with `sudo tcpdump -w file.pcap`.

## Capture defaults

- **Promiscuous mode is off.** netrain sees traffic to and from this host. Add `--promiscuous`
  to also see other hosts' traffic on a shared segment or a mirror port.
- **Snap length is 1600 bytes** (`--snaplen`): a whole standard Ethernet frame, enough to read
  hostnames from TLS and HTTP. Lower it (for example `--snaplen 128`) to capture headers only.
- **Default filter** is `ip or ip6 or (vlan and (ip or ip6))`; change it with `--filter`.
- netrain never transmits: it sends no packets and performs no DNS lookups of its own.
