# DNSWatch

A root Android app that shows you **exactly which domains a specific app talks to** —
its DNS lookups, the hostnames in its TLS handshakes (SNI), and every outbound
connection — and lets you **block** any of them per-app.

Built to answer questions like *"is this app really phoning home, and to where?"*
with on-device evidence instead of guesswork.

## What it does

- **Pick any installed app(s)** to watch — or flip on **Whole device** to monitor
  everything at once (NFLOG carries the per-packet uid, so events still attribute
  to the owning app).
- Mirrors traffic to **NFLOG** via `iptables` (per-app owner-match, or a global
  rule for whole-device) and runs `tcpdump` on the NFLOG interface.
- A pure-Kotlin parser decodes, live:
  - **DNS** queries/replies (with resolved IPs),
  - **TLS SNI** — the hostname inside each HTTPS ClientHello,
  - **QUIC / HTTP-3 SNI** — decrypts the QUIC-v1 Initial packet (HKDF + AES-GCM)
    to recover the hostname that would otherwise be invisible on UDP/443,
  - **all connection destination IPs**, annotated with their hostname via the
    DNS IP→host map.
- **Hosts tab** — a per-host rollup (host · hit count · classification · proto)
  with one-tap **"block all trackers."**
- **Tracker classification** with a switchable catalog: **Built-in** (offline) ·
  **Exodus Privacy** · **DuckDuckGo Tracker Radar** · **Hosts blocklist**
  (external lists fetched + cached, fail-safe back to built-in).
- **Per-app (or whole-device) domain blocking** — tap a host to DROP it; the
  block-list **persists**, re-applies on start, and follows **rotating IPs** as
  they resolve. A real per-app firewall.
- **Session recording** to a full log (beyond the on-screen cap), **Share**
  (text log or raw **.pcap** for Wireshark), and export to `/sdcard/Download`.

## Why root + NFLOG (and why SNI matters)

Android routes app DNS through the `netd` resolver, so raw `:53` packets aren't
tagged with the calling app's uid. DNSWatch therefore attributes per-app hostnames
from **TLS SNI** + the global DNS IP→host map, while still surfacing the resolver's
DNS feed for context. This is correct and encryption-proof (SNI is visible even
with DoH/DoT, barring ECH).

## Requirements

- **Root** (Magisk). The app calls `su` to install the iptables/NFLOG rules and
  run the bundled-or-system `tcpdump`.
- Kernel with `xt_owner` + `NFLOG` (standard on Magisk-rooted devices).

## Build

CI (GitHub Actions) builds a signed APK on every push and a release on `v*` tags.
Jetpack Compose + Material 3, gradle 8.10.2 / AGP 8.7.3 / Kotlin 2.1.0.

## Status

v1 — monitor (DNS + SNI + connection IPs) and per-app block. Verification tool;
not a general-purpose firewall.
