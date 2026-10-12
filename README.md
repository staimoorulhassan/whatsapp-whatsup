# WhatsApp IP Hunter (whatsup-now)

A command-line tool that analyzes WhatsApp P2P call signaling and extracts the
remote caller/receiver public IP from the STUN traffic that crosses your
network interface during a call placed from the **WhatsApp Desktop app**.

> **Scope:** OSINT only. Results are ISP/city/region-level location of a public
> IP address — not a street address, subscriber identity, device details, or
> call content. This tool works only against traffic your own device sends and
> receives. Educational/defensive use only.

## How it works

1. You run `capture` (or `hunt`) from the terminal.
2. The tool auto-selects the active Wi-Fi/WLAN interface (or you pass `-i`).
3. It sniffs UDP traffic while **you** place a call to the target from the
   WhatsApp Desktop app and let it ring 2-3 seconds.
4. STUN packets are identified by the RFC 5389 magic cookie (`0x2112a442`) on
   **any** UDP port — no longer restricted to the classic 3478/5349 ports —
   which lets direct peer-to-peer ICE connectivity checks (ephemeral ports)
   reach the extractor.
5. The receiver's public IP is recovered from the **destination of the
   caller's outbound STUN Binding Request (0x0001)** during ringing, plus
   matching inbound Binding Responses — not from XOR-MAPPED-ADDRESS (that is
   only your own NAT mapping) and never from Meta TURN relays.
6. All candidates are classified (private / Meta infrastructure / corporate /
   public potential target) and only the public, non-infrastructure IP is
   geolocated via MaxMind (local DB or online) with a multi-provider fallback.
7. Results render as a table: IP, place (city, country), coordinates, and a
   Google Maps pin link.

## Features

- Desktop-app capture flow — no WhatsApp Web, no QR code, no Playwright on the
  live path
- Auto interface selection (`select_best_interface`)
- STUN magic-cookie detection on any port (P2P and TURN traffic)
- Outbound-binding-request directionality for receiver IP extraction
- Full capture diagnostics: packet/STUN counts, per-IP classification, STUN
  flow table (when no candidate is found)
- Geolocation: MaxMind GeoLite2 (local) -> ip-api.com -> ipinfo.io ->
  ipgeolocation.io -> geoplugin, LRU-cached (24h TTL)
- `hunt`, `capture`, `bulk-hunt`, `continuous-mode`, `interfaces` commands
- IPv4 and IPv6 support

## Installation

```
pip install -r requirements.txt
```

Npcap (WinPcap-compatible) is required for live capture on Windows.
Optional: place `GeoLite2-Country.mmdb` in the project root for offline
country lookup (otherwise online providers are used).

## Usage

### Capture (receiver IP)

```
python src/cli.py capture -t 15
```

Place the call from the WhatsApp Desktop app while the capture runs, let it
ring 2-3 seconds, then hang up.

### Hunt (with target number)

```
python src/cli.py hunt +1234567890 -t 15
```

### Bulk / continuous

```
python src/cli.py bulk-hunt +1111111111 +2222222222 -t 15
python src/cli.py continuous-mode numbers.txt -t 15
```

### Interfaces

```
python src/cli.py interfaces
```

## Config

`config/settings.py`:
- `CAPTURE_TIMEOUT` — default capture duration in seconds
- `GEOLITE_DB_PATH` — path to the local MaxMind database
- `BACKUP_GEO_SERVICE` — first online fallback provider
- `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` — read from environment; the
  MaxMind HTTP lookup is skipped entirely when these are unset

## Failure modes

- `STUN packets: 0` — the call used relay mode, or "Protect IP address in
  calls" is ON, or a VPN/proxy carried the traffic. Disable VPNs and make sure
  privacy protection is OFF on both ends.
- Only Meta infrastructure IPs in `stun_flows` — TURN relay path; the receiver
  public IP is not exposed to your device (CGNAT or protected calls).

## Tests

```
python -m pytest tests -q
```

## Disclaimer

Educational purposes only. Users are responsible for complying with all
applicable laws and privacy settings. Only use against numbers/devices you are
authorized to test.