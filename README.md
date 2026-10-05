# DPI Engine: Multi-threaded Deep Packet Inspection in C++17

A from-scratch Deep Packet Inspection (DPI) engine that reads PCAP captures, identifies applications inside **encrypted HTTPS traffic** by extracting the TLS SNI, applies flow-based blocking rules, and writes a filtered PCAP plus a traffic report.

Built with **zero external libraries**: every protocol parser (PCAP, Ethernet, IPv4, TCP/UDP, TLS Client Hello, HTTP Host) is hand-written.

`C++17` · `Multithreading` · `TCP/IP` · `TLS` · `Producer-Consumer` · `Linux/macOS`

---

## Highlights

| Area | What it demonstrates |
|------|----------------------|
| **Protocol parsing** | Raw-byte parsing of PCAP, Ethernet, IPv4, TCP, UDP with correct network byte order handling |
| **Deep packet inspection** | Extracts the SNI hostname from TLS Client Hello and the `Host` header from HTTP |
| **Flow tracking** | Connections identified by 5-tuple (src IP, dst IP, src port, dst port, protocol) |
| **Concurrency** | Reader → Load Balancer → Fast Path → Writer pipeline using thread-safe queues |
| **Rule engine** | Block by source IP, application, or domain substring; decisions apply to the whole flow |
| **Reporting** | Per-application breakdown, detected domains, per-thread statistics |

---

## How It Works

```
User Traffic (PCAP) ──► [ DPI Engine ] ──► Filtered Traffic (PCAP)
                          │
                          ├─ Identify apps (YouTube, Facebook, Google, ...)
                          ├─ Block by IP / app / domain
                          └─ Generate report
```

Even though HTTPS is encrypted, the TLS Client Hello carries the destination hostname in plaintext (SNI). The engine reads it from the first data packet of each connection, classifies the flow, and applies rules to all remaining packets of that flow.

### Multi-threaded Architecture

```
                 ┌───────────────┐
                 │ Reader Thread │
                 └───────┬───────┘
            hash(5-tuple) % num_LBs
              ┌──────────┴──────────┐
              ▼                     ▼
        ┌──────────┐          ┌──────────┐
        │   LB 0   │          │   LB 1   │     Load Balancers
        └────┬─────┘          └────┬─────┘
       hash % num_FPs        hash % num_FPs
         ┌───┴───┐              ┌───┴───┐
         ▼       ▼              ▼       ▼
       FP0     FP1            FP2     FP3      Fast Paths (DPI + rules)
         └───────┴──────┬───────┴───────┘
                        ▼
                ┌───────────────┐
                │  Output Queue │
                └───────┬───────┘
                        ▼
                ┌───────────────┐
                │ Writer Thread │ ──► output.pcap
                └───────────────┘
```

**Key design decisions**

- **Consistent 5-tuple hashing.** Every packet of a connection lands on the same Fast Path, so each FP owns its flow table privately. No locks on flow state, and classification stays correct.
- **Producer-consumer queues.** Mutex + condition variables give efficient blocking with no busy-waiting.
- **Flow-level blocking.** The app is unknown until the Client Hello arrives. Once a flow is classified and matches a rule, it is marked blocked and all following packets are dropped.
- **Single-threaded baseline kept.** `main_working.cpp` is retained for correctness comparison and benchmarking against the multi-threaded version.

---

## Quick Start

### Prerequisites
- Linux or macOS
- `g++` or `clang++` with C++17 support
- Python 3 (only to generate test data)

### Build

```bash
# Single-threaded version
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# Multi-threaded version
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

### Generate test traffic

```bash
python3 generate_test_pcap.py     # creates test_dpi.pcap
```

### Run

```bash
# Inspect only
./dpi_engine test_dpi.pcap output.pcap

# With blocking rules
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# Tune the thread layout (4 LBs x 4 FPs)
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                    PROCESSING REPORT                         ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Forwarded:                    69                             ║
║ Dropped:                       8                             ║
╠══════════════════════════════════════════════════════════════╣
║                  APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6%  ##########                   ║
║ Unknown              16  20.8%  ####                         ║
║ YouTube               4   5.2%  #  (BLOCKED)                 ║
║ DNS                   4   5.2%  #                            ║
║ Facebook              3   3.9%                               ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com  -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com   -> Google
  - github.com       -> GitHub
```

---

## Benchmarks

> Replace the placeholders below with your own measured values before publishing.
> Method: `time ./dpi_engine big.pcap out.pcap --lbs 2 --fps N`, with Mpps = total packets / seconds.

**Environment:** `<CPU model, cores, RAM, OS, compiler, flags>`
**Input:** `<N> packets, <M> MB, <K> distinct flows`

| Configuration | Time (s) | Throughput (Mpps) | Speedup vs. single-thread |
|---------------|----------|-------------------|---------------------------|
| Single-threaded (`dpi_simple`) | `<x>` | `<x>` | 1.0x |
| MT: 1 LB × 1 FP | `<x>` | `<x>` | `<x>` |
| MT: 2 LB × 2 FP | `<x>` | `<x>` | `<x>` |
| MT: 2 LB × 4 FP | `<x>` | `<x>` | `<x>` |

---

## Project Structure

```
packet_analyzer/
├── include/                  # Headers
│   ├── pcap_reader.h         # PCAP file reading
│   ├── packet_parser.h       # Ethernet / IP / TCP / UDP parsing
│   ├── sni_extractor.h       # TLS SNI + HTTP Host extraction
│   ├── types.h               # FiveTuple, AppType, Flow
│   ├── rule_manager.h        # IP / app / domain blocking rules
│   ├── connection_tracker.h  # Flow tracking
│   ├── load_balancer.h       # LB thread
│   ├── fast_path.h           # FP thread (DPI + rules)
│   ├── thread_safe_queue.h   # Blocking queue
│   └── dpi_engine.h          # Orchestrator
├── src/
│   ├── main_working.cpp      # Single-threaded version
│   ├── dpi_mt.cpp            # Multi-threaded version
│   └── ...                   # Parser, reader, extractor implementations
├── generate_test_pcap.py     # Synthetic traffic generator
└── test_dpi.pcap             # Sample capture
```

---

## Known Limitations and Roadmap

Being upfront about scope, since these are the real engineering trade-offs:

- [ ] **TCP segmentation:** A Client Hello split across multiple TCP segments is not reassembled, so SNI extraction can miss it. *Next step: per-flow reassembly buffer.*
- [ ] **TLS 1.3 ECH / QUIC (HTTP/3):** Encrypted Client Hello hides the SNI, and QUIC carries it in encrypted UDP Initial packets. *Next step: QUIC Initial decryption.*
- [ ] **IPv4 only:** IPv6 and VLAN-tagged frames are not parsed yet.
- [ ] **Hash-based load distribution:** If the LB and FP stages reuse the same hash modulo, work can concentrate on fewer FPs (visible in the small sample, where FP1 and FP2 processed zero packets). *Next step: derive LB and FP indices from different hash bits or a second hash, then verify distribution on a large capture.*
- [ ] **Substring app matching:** `sni.find("youtube")` is simple but can false-positive. *Next step: suffix/domain-label matching.*
- [ ] **Offline only:** Works on PCAP files, not live capture. *Next step: libpcap or AF_PACKET input.*
- [ ] **Extras:** Bandwidth throttling instead of drop, live stats thread, persistent rules file.

---

## What I Learned

- Designing a pipeline where **hash-based sharding removes the need for shared mutable state**
- Parsing binary protocols safely: bounds checks, endianness, variable-length fields
- Why stateful inspection needs flow tracking, and where it breaks (fragmentation, encryption)
- Measuring concurrency honestly: queue contention, single-reader bottlenecks, load skew

---

## License

MIT (or your preferred license)
