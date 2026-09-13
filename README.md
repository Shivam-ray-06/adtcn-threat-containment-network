# ADTCN v2 — Java + C++ + JavaScript

A full rewrite of the ADTCN prototype in three languages instead of
Python: **Java** for the backend (correlation engine, policy engine,
evidence chain, REST + WebSocket API), **C++** for the endpoint agent,
network sensor, and attack simulator (real POSIX sockets, real Linux
inotify), and **JavaScript** for a redesigned dashboard with a clean
deterministic attack-flow diagram and a live alarm sound.

Same detection logic, same scoring weights, same policy rules as the
original design doc and the earlier Python version — this is a
language port, not a different system.

## Why no external libraries

This was built in a sandboxed environment that can't reach Maven
Central, vcpkg, or conan — only a handful of package registries
(npm, pip, crates.io) were reachable, and none of those help Java or
C++. So:

- **Java backend** uses only the JDK standard library: `com.sun.net.httpserver.HttpServer`
  for REST, and a ~100-line hand-rolled WebSocket server (RFC 6455
  handshake + text frames) for live updates. No Spring, no Jackson —
  there's a small hand-rolled `Json.java` instead. Storage is
  in-memory (`ConcurrentHashMap`/`CopyOnWriteArrayList`) rather than a
  database — swap-in point is called out in `Storage.java` if you want
  to add persistence later.
- **C++ programs** use raw POSIX sockets (`sys/socket.h`) for HTTP
  instead of libcurl, and `sys/inotify.h` directly for real file-access
  detection — no dependencies beyond a standard C++17 toolchain.

This is arguably a _better_ thing to show judges than a pile of
framework imports: it's ~2,000 lines of code where nearly every line
is actual project logic, not boilerplate from a library.

## What each service does

| Service          | Language   | Role                                                                                                            |
| ---------------- | ---------- | --------------------------------------------------------------------------------------------------------------- |
| `backend-java/`  | Java       | REST API (`:8000`) + WebSocket (`:8001`): correlation engine, policy engine, evidence hash chain, decoy manager |
| `agent-cpp/`     | C++        | Endpoint agent — real Linux inotify watch on the decoy file                                                     |
| `network-cpp/`   | C++        | Network sensor — tails a flow-record log, detects scanning/abnormal connections                                 |
| `simulator-cpp/` | C++        | Scripted attacker — plays the PC-47 scenario end-to-end                                                         |
| `dashboard/`     | JavaScript | Live SOC dashboard: threat scores, event feed, attack-flow diagram, incidents, alarm                            |

## Setup

You need: a JDK (11+), a C++17 compiler (g++ or clang++), and a
browser. No package managers needed.

## Quick start

From the repository root, run:

```bash
./run.sh
```

Then open **http://localhost:8000** and sign in with the local demo account
shown below. `run.sh` resolves its own location, builds the Java and C++
components, and starts the dashboard backend even when invoked from another
working directory.

```bash
cd adtcn-v2
./build.sh
```

This compiles the Java backend into `backend-java/out` and all three
C++ programs in place. Re-run it any time you edit source.

If `./build.sh` isn't executable: `chmod +x build.sh` first.

## Running the full demo (4 terminals)

**Terminal 1 — backend + dashboard**

```bash
cd backend-java
java -cp out adtcn.Main
```

Open **http://localhost:8000** for the dashboard. REST API is on
`:8000`, WebSocket live-updates on `:8001` (the dashboard connects to
both automatically).

**Terminal 2 — endpoint agent** (real inotify watch on the decoy file)

```bash
cd agent-cpp
./endpoint_agent PC-47 ../decoys/finance_admin_credentials.txt
```

**Terminal 3 — network sensor**

```bash
cd simulator-cpp && touch flow_log.jsonl && cd ../network-cpp
./network_sensor ../simulator-cpp/flow_log.jsonl
```

**Terminal 4 — run the attack scenario**

```bash
cd simulator-cpp
./attack_simulator PC-47 ../decoys/finance_admin_credentials.txt flow_log.jsonl
```

Watch the dashboard: threat score climbs step by step, the attack-flow
diagram builds itself left-to-right, an adaptive decoy gets deployed
once the attacker touches the finance zone, and once the honeytoken +
lateral-movement + score conditions are all met you'll hear the alarm
and see a CRITICAL/EMERGENCY incident with `ISOLATE_ENDPOINT` — same
scenario as the design doc's "Threat Score 96/100 → isolate PC-47."

The dashboard also explains seven attack types as the simulation runs:

1. Suspicious execution — unusual process and encoded command-line detection.
2. Internal discovery — distinct-destination counting in a sliding window.
3. Credential access — endpoint honeyfile and honeytoken correlation.
4. Privilege escalation — escalation signals correlated with host history.
5. Lateral movement — authenticated destination plus reconstructed graph path.
6. Command and control — first contact with a sensitive host.
7. Ransomware impact — rapid high-risk file activity correlated with the attack chain.

Each incoming event appears in the dashboard's **AI Detection Reasoning**
stream with its working model, detection evidence, tactic, and confidence.
The simulator emits all seven categories in order, including the privilege
escalation and ransomware stages added to this version.

The left-side **Attack Library** groups those seven types by tactic. The
adjacent **Attacker IP Map** shows the source IP, affected protected zone,
latest attack type, event count, and local attack time. Real sensors can send
`attacker_ip` at the event root or inside `metadata`; simulator events without
one receive a clearly labeled derived lab address from the host ID.

The dashboard opens behind a local demo login: `shivamray@SOC.in` with
password `Krishu!@#123`. Public IPs are resolved through `ipapi.co` into an
IP-geolocation city/region/country and plotted on each attack card's world map;
private, reserved, or derived lab IPs are explicitly shown as unavailable.

The command-center view includes a persistent attack-library rail and live
coverage for Phishing, Social engineering, DDoS, Brute force, SQL injection,
Man in the middle, and Ransomware. The attacker map uses Leaflet with dark
CARTO/OpenStreetMap tiles, pan/zoom controls, attribution, and marker popups.
Map tiles and public-IP geolocation require browser network access; the SOC
telemetry, scoring, evidence chain, and dashboard still work locally when those
external services are unavailable.

**Important:** run each program from _inside_ its own folder (as
shown above) — the decoy path and dashboard path are resolved
relative to the working directory the process starts in.

## The new dashboard — what changed

**Attack graph is no longer a physics simulation.** The old dashboard
used a force-directed graph library (vis-network) that let nodes drift
and edges cross/loop unpredictably — fine for a handful of nodes,
unreadable once an attack path had more than 4-5 hops. The new
dashboard computes a **deterministic layered layout**: every node's
horizontal position is fixed by how many hops it is from the start of
the attack path (`layer = 1 + max(layer of predecessors)`), so the
diagram always reads strictly left-to-right in the order the attacker
actually moved, with rendered arrows and no overlapping loops.

**Alarm sound.** Each live attack event plays a sustained alarm sequence
through the Web Audio API; ransomware uses a longer emergency sequence.
No audio file is needed because the tones are synthesized in JavaScript.
The login gesture unlocks browser audio, and the mute toggle in the
top-right disables the sequences when needed. Historical events stay silent
when the dashboard is reloaded.

**Cleaner layout overall**: score bars instead of bare numbers,
color-coded severity throughout, a live-connection indicator, and
clearer visual hierarchy between the event feed (raw telemetry),
threat scores (correlation output), and incidents (policy decisions).

## Testing components individually

**Backend only:**

```bash
cd backend-java && java -cp out adtcn.Main
curl http://localhost:8000/health
curl -X POST http://localhost:8000/events -H "Content-Type: application/json" \
  -d '{"entity_id":"PC-99","event_type":"decoy_credential_used","source":"test","metadata":{}}'
curl http://localhost:8000/state
curl http://localhost:8000/evidence/verify
```

**Trigger the endpoint agent manually** (with it running against a
live backend): just open the decoy file yourself —
`cat decoys/finance_admin_credentials.txt` — and watch the agent's
terminal report the access and the dashboard update live.

## Known limitations (be upfront about these with judges)

- Storage is in-memory — restarting the backend clears all state.
  Documented as a swap-in point for a real database.
- The C++ JSON helpers (`common-cpp/json_util.hpp`) are intentionally
  minimal — they build/read only the specific fields this project
  uses, not a general parser. Fine for this scope; would need a real
  JSON library for anything bigger.
- `inotify` (real-time file-access detection) is Linux-only — this is
  a genuine OS limitation, not a shortcut. `endpoint_agent.cpp`
  auto-detects the platform at compile time: real inotify on Linux,
  and a 1-second polling fallback on macOS/other platforms (same
  approach the earlier Python prototype used, for the same reason).
  You'll see `watching (polling fallback — non-Linux platform)` in the
  agent's terminal output on macOS — that's expected, not a bug.
