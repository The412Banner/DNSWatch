# DNSWatch

A root Android app that shows you **exactly which domains a specific app talks to** —
its DNS lookups, the hostnames in its TLS handshakes (SNI), and every outbound
connection — and lets you **block** any of them per-app.

Built to answer questions like *"is this app really phoning home, and to where?"*
with on-device evidence instead of guesswork.

## What it does

- **Pick any installed app(s)** to watch.
- Mirrors the selected app's outbound traffic to **NFLOG** via an `iptables`
  owner-match rule (uid-scoped) and runs `tcpdump` on the NFLOG interface.
- A pure-Kotlin parser decodes, live:
  - **DNS** queries/replies (with resolved IPs) — from the system resolver lane,
  - **TLS SNI** — the hostname inside each HTTPS ClientHello (works even when DNS
    is encrypted/cached; this is the reliable *per-app* hostname signal),
  - **all connection destination IPs**, annotated with their hostname via the
    DNS IP→host map.
- **Known trackers highlighted** (Google/Firebase/AdMob/analytics/CN-push, etc.).
- **Per-app domain blocking**: tap a host to DROP it (by resolved IP) for the
  selected app only — turn the monitor into a per-app firewall.
- **Export** the capture to a text log.

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
