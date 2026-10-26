# Zenoh + RaptorQ: Fountain-Coded Asset Distribution for Outdoor Robotics

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Zenoh](https://img.shields.io/badge/Zenoh-Peer--to--Peer-brightgreen)](https://zenoh.io/)

A zero-retransmission bulk asset distribution pipeline pairing **Eclipse Zenoh** with **RFC 6330 RaptorQ** fountain codes to stream maps, bounds, and binaries across Disconnected, Intermittent, and Low-Bandwidth (DDIL) outdoor robotic meshes.

---

## The Problem

In large-scale field deployments (autonomous turf machinery, agricultural rovers, sensor grids):

1. **RF Dead Zones:** Rolling topography and foliage cause sustained 15–30% packet loss.
2. **ACK/NACK Storms:** Standard ARQ and TCP pub/sub mechanisms fail during fleet-wide broadcasts. Weak links trigger retransmission floods that choke shared radio channels.
3. **Burst Loss & Buffer Saturation:** Driving behind obstacles or bursting data across narrow bridges (e.g., 900MHz serial meshes) causes buffer overflows and clustered packet loss.

---

## Architecture

* **Source Block Partitioning:** Payloads are compressed with `zlib` and partitioned across $Z$ independent RaptorQ source block encoders ($K_{target} \le 1,024$). This bounds edge memory usage and keeps solve times sub-millisecond.
* **Symbol Interleaving:** Droplets from all $Z$ blocks are interleaved round-robin during broadcast. Temporal RF fades distribute losses evenly across all blocks rather than destroying any single block.
* **Self-Describing 22-Byte OTI Prefix:** Every packet carries a 22-byte header (`comp_size`, `orig_size`, `symbol_size`, `num_blocks`, `sbn`). Receiving any single droplet immediately seeds the block layout.
* **Mutual Ed25519 Whitelisting & AEAD Encryption:** Transit data uses ChaCha20-Poly1305. Remote commands require Ed25519 signatures verified against an explicit pre-shared keyring, coupled with monotonic sequence tracking persisted to disk for nodes lacking RTC or NTP synchronization.
* **Asynchronous Edge Journaling:** Received fragments append to disk storage via a non-blocking queue and background thread with batched `fsync` boundaries to protect the Zenoh network reactor from I/O stalls and flash wear.
* **Best-Effort Pacing:** Employs Zenoh's `CongestionControl.DROP` and `Priority.DATA_LOW` alongside paced dispatch to prevent overflowing physical radio queues.

---

## Quickstart & Simulation

### 1. Install Dependencies

```bash
pip install eclipse-zenoh raptorq cryptography cbor2
```

### 2. Run the Demo

```bash
python demo.py
```

### Expected Output

```text
Original Size   : 158,500 bytes
Compressed Size : 36,042 bytes
CID (SHA-256)   : 7d4a2e...
RFC 6330 Blocks : 3 Source Blocks (Interleaved)
Total Droplets  : 111

Streaming interleaved droplets across Zenoh (simulating 25% radio drop)...

Ingested: 83, Dropped: 28
Broadcast Duration: 0.38s
Solved Blocks: 3 of 3
Assembly & Hash Time: 0.62 ms
Security: SUCCESS (Ed25519 whitelisted command verified)
Status: SUCCESS (Multi-block bit-exact match, 0 retransmissions)
```

---

## Repository Structure

```text
├── demo.py             # Two-node MeshOrchestrator simulation (BASE -> MOWER_1) with 25% loss
├── encode.py           # Multi-block partitioner & interleaver (zlib + RaptorQ + 22-byte OTI)
├── meshorchestrator.py # Standalone Zenoh peer node (pub/sub, queryables, journaling, auth)
└── README.md
```

---

## Community Discussion & Feedback

1. **Native Physical Broadcast vs. Peer Mesh:** In an RF broadcast environment, what is the recommended locator/transport configuration to ensure Zenoh leverages native L2/L3 broadcast rather than replicating packets across individual peer unicast sessions?
2. **Symbol Granularity vs. Batching:** For 512B–1KB droplets over low-baud links (e.g., 900MHz serial meshes or 802.11ah HaLow), is publishing individual droplets as discrete Zenoh samples idiomatic (relying on Zenoh's internal transport batching), or is explicit application-layer batching preferred to minimize L2/L3 framing overhead?
3. **Inter-Peer Repair (Queryables vs. Storages):** When an edge node is short by $N$ droplets to solve a specific block, is an on-demand Queryable targeting `sbn` dynamically generating fresh repair symbols preferred over native Zenoh Storages?

---

## License

This project is licensed under the [Apache 2.0 License](LICENSE).