# 5G Network Security — Attack Simulation & Rules-Based Monitoring

> **Academic cybersecurity project** — Université Euromed de Fès (EIDIA)  
> Supervised by Prof. ZINEDDINE Mhamed

A complete 5G core network security lab built on **Open5GS** and **UERANSIM**, featuring four attack simulations and a real-time AI-based monitoring dashboard.

---

## Table of Contents

- [Architecture](#architecture)
- [Attacks Implemented](#attacks-implemented)
- [Monitoring System](#monitoring-system)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Demo](#screenshots)

---

## Architecture

```
┌─────────────────────────────────────┐     ┌──────────────────────────┐
│         VM1 — Open5GS Core          │     │    VM2 — UERANSIM        │
│                                     │     │                          │
│  AMF · SMF · UPF · NRF · NSSF      │◄───►│  gNB + UE (eMBB / IoT)  │
│  UDM · UDR · AUSF · PCF · BSF      │     │  192.168.139.140         │
│  192.168.139.134                    │     └──────────────────────────┘
│                                     │
│  ┌─────────────────────────────┐   │
│  │   5G Slice Security Monitor │   │
│  │   Collector → Detector      │   │
│  │   FastAPI Dashboard :8080   │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘

Network Slices:
  Slice 1 (eMBB)  SST=1  →  10.45.0.0/16  ogstun
  Slice 2 (IoT)   SST=2  →  10.46.0.0/16  ogstun (shared)
```
<img width="515" height="168" alt="image" src="https://github.com/user-attachments/assets/8f2dbebe-077e-48c7-be12-9f5ae5958b61" />

---

## Attacks Implemented

### 1. PFCP Manipulation (Man-in-the-Middle on User Plane)

**Target:** PFCP protocol (port 8805) between SMF and UPF  
**Method:** Forge a `Session Modification Request` containing an `Outer Header Creation` IE (type 84) that redirects GTP-U traffic to an attacker-controlled IP.

```bash
sudo python3 attacks/pfcp_manipulation.py
# Traffic from the UE is redirected to ATTACKER_IP:2152
```

**Detection:** The collector parses every PFCP `Session Modification Request` for IE type 84. If found → `PFCP_INJECTION` alert is published to Redis.

---

### 2. Cross-Slice Attack (Slice Isolation Violation)

**Target:** Network slicing isolation between eMBB (SST=1) and IoT (SST=2)  
**Method:** Attempt to bypass logical network isolation by adding a route to the other slice.

```bash
# VM2
sudo ./build/nr-ue -c configs/ue-malicious.yaml
# AMF rejects with "No Allowed-NSSAI" → detected
```

**Detection:** AMF log pattern `No Allowed-NSSAI` triggers `SLICE_ISOLATION_VIOLATION` alert.

---

### 3. NSSAI Manipulation

**Target:** Modify UDM repository  
**Method:** Gain access to unauthorized network slices by tampering with UDM subscription data.

```bash
sudo ip route add 10.46.0.0/24 dev uesimtun0
 
ping -I uesimtun0 10.46.0.2 
```

---

### 4. DoS on NGAP Interface

**Target:** NGAP signalling between gNB and AMF (port 38412)  
**Method:** Flood the AMF with repeated `Registration Request` messages to exhaust signalling capacity.

```bash
# VM2
python3 attacks/dos_ngap.py
```

**Detection:** Registration request timestamps are counted per minute. Rate > 15 req/min triggers `NGAP_DOS` alert.

### 5. IP Spoofing (rp_filter Disabled)

**Target:** Open5GS UPF (ogstun interface) 
**Method:** User Plane — forged source IP packets — Disable rp_filter (Reverse Path Filtering)

```bash

python3 attacks/spoof.py

```
### 6. 5G-AKA AUTH

### 5G-AKA Authentication Attack

**Target:** Open5GS AMF / AUSF (5G-AKA Authentication)

**Method:** Authentication request using a legitimate IMSI (999700000000001) with a forged Ki (FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) to evaluate the robustness of the 5G-AKA authentication procedure.

---

## Monitoring System

### Components

| Component | File | Role |
|-----------|------|------|
| Collector | `5g-slice-monitor/collector/collector.py` | Tails Open5GS logs, sniffs PFCP/GTP-U |
| Detector  | `5g-slice-monitor/ai/detector.py` | Rule-based engine, reads Redis stats |
| Feeder    | `5g-slice-monitor/feeder.py` | tshark-based NSSAI/FAR IP extractor |
| API       | `5g-slice-monitor/dashboard/api.py` | FastAPI REST + WebSocket |
| Dashboard | `5g-slice-monitor/dashboard/index.html` | Real-time HTML/JS dashboard |

### Detection Rules

| Attack | Trigger | Severity |
|--------|---------|----------|
| PFCP Manipulation | IE type 84 (OHC) in Mod Request | CRITICAL |
| GTP Redirection | GTP-U to unexpected destination IP | CRITICAL |
| Cross-Slice | `No Allowed-NSSAI` in AMF logs | CRITICAL |
| DoS NGAP | NGAP registration rate > 15 req/min | CRITICAL |
| Cross-Slice GTP | Inter-slice packets on ogstun | HIGH |

### Dashboard Panels

- **Network Overview** — active slices, UE sessions, traffic BPS
- **Traffic Flow** — UE → gNB → UPF → Internet (turns red on attack)
- **Security Alerts** — real-time feed with severity badges
- **PFCP Monitor** — message types, injection count, event log
- **GTP-U Analysis** — per-slice packet counts, cross-slice detection
- **AI Detection** — ensemble label, anomaly score, model results

---

## Requirements

### VM1 — Open5GS Host

- Ubuntu 22.04
- Open5GS 2.7.x
- Python 3.10+
- Redis 7.x
- tshark / Wireshark CLI

### VM2 — UERANSIM Host

- Ubuntu 22.04
- UERANSIM 3.2.8
- Python 3.10+ (optional, for attack scripts)
- Scapy

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/DiawaraNana/5g-network-security.git
cd 5g-network-security
```

### 2. Install Open5GS (VM1)

Follow the [official Open5GS guide](https://open5gs.org/open5gs/docs/guide/01-quickstart/).

Copy the provided configs:

```bash
sudo cp configs/amf.yaml /etc/open5gs/amf.yaml
sudo cp configs/smf.yaml /etc/open5gs/smf.yaml
sudo cp configs/upf.yaml /etc/open5gs/upf.yaml
sudo systemctl restart open5gs-amfd open5gs-smfd open5gs-upfd
```

### 3. Install UERANSIM (VM2)

```bash
sudo apt install -y make gcc g++ libsctp-dev cmake
git clone https://github.com/aligungr/UERANSIM
cd UERANSIM && make
```

Copy configs from this repo:

```bash
cp configs/my-gnb.yaml ~/UERANSIM/config/
cp configs/my-ue.yaml  ~/UERANSIM/config/
cp configs/ue-iot.yaml ~/UERANSIM/config/
```

### 4. Install the monitoring system (VM1)

```bash
cd 5g-slice-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start all components
sudo bash scripts/start.sh
```

Dashboard available at: `http://VM1_IP:8080`

### 5. Add subscribers to MongoDB (VM1)

```bash
# eMBB subscriber (IMSI 001010000000001, SST=1)
# IoT subscriber  (IMSI 001010000000002, SST=2)
# Use Open5GS WebUI at http://localhost:9999 or mongosh scripts in docs/
```

---

## Usage

### Normal operation

```bash
# VM2 — Start gNB
sudo ./build/nr-gnb -c config/my-gnb.yaml &

# VM2 — Connect eMBB UE
sudo ./build/nr-ue -c config/my-ue.yaml &

# VM2 — Connect IoT UE
sudo ./build/nr-ue -c config/ue-iot.yaml &
```

### Running attacks

```bash
# Attack 1 — PFCP Manipulation (VM1)
sudo python3 attacks/pfcp_attack_ohc.py

# Attack 2 — Cross-Slice (VM2)
sudo ./build/nr-ue -c configs/ue-malicious.yaml

# Attack 3 — NSSAI Manipulation (VM2)
# (same as attack 2 but repeated rapidly)

# Attack 4 — DoS NGAP (VM2)
python3 attacks/ngap_dos.py
```

### Monitoring

```bash
# Watch Redis stats live
watch -n 1 'redis-cli hgetall pfcp:stats && redis-cli lrange events:alerts 0 3'

# View collector logs
tail -f 5g-slice-monitor/logs/collector.log

# Access dashboard
open http://192.168.139.134:8080
```

---

## Project Structure

```
5g-network-security/
├── attacks/
│   ├── pfcp_manipulation.py      # PFCP Session Modification injection
│   ├── pfcp_attack_ohc.py        # PFCP with Outer Header Creation IE
│   ├── ngap_dos.py               # DoS flood on NGAP interface
│   └── ue-malicious.yaml         # UERANSIM config — unauthorized slice
│
├── 5g-slice-monitor/
│   ├── collector/
│   │   └── collector.py          # Log tailer + PFCP/GTP sniffer
│   ├── ai/
│   │   ├── detector.py           # Rule-based detection engine
│   │   └── features.py           # Feature extraction from Redis
│   ├── dashboard/
│   │   ├── api.py                # FastAPI backend + WebSocket
│   │   └── index.html            # Real-time monitoring dashboard
│   ├── feeder.py                 # tshark-based NSSAI/FAR feeder
│   ├── requirements.txt
│   └── scripts/
│       ├── start.sh              # Start all components
│       └── stop.sh               # Stop all components
│
├── configs/
│   ├── amf.yaml                  # Open5GS AMF config
│   ├── smf.yaml                  # Open5GS SMF config
│   ├── upf.yaml                  # Open5GS UPF config
│   ├── my-gnb.yaml               # UERANSIM gNB config
│   ├── my-ue.yaml                # UERANSIM UE — eMBB (SST=1)
│   └── ue-iot.yaml               # UERANSIM UE — IoT (SST=2)
│
├── architecture.png
└── demo
│
├── .gitignore
└── README.md
```

---

## Demo

| 5G_NETWORK_PROJECT.mp4 in the files

---

## Technical Details

### PFCP Attack — How it works

The attack forges a valid PFCP `Session Modification Request` (msg type 52) with a spoofed SMF source IP (`127.0.0.4`). The payload contains a nested `Update FAR` (IE 10) → `Update Forwarding Parameters` (IE 11) → `Outer Header Creation` (IE 84) pointing to the attacker's IP and a fake TEID.

The UPF accepts this because PFCP has no authentication in the Open5GS implementation — it trusts any packet from `127.0.0.4:8805`.

### Detection — IE 84 parsing

```python
def find_ie(data, target_type, depth=0):
    """Recursively search for IE type in PFCP grouped IEs."""
    pos = 0
    while pos + 4 <= len(data):
        ie_t = struct.unpack_from(">H", data, pos)[0]
        ie_l = struct.unpack_from(">H", data, pos + 2)[0]
        ie_d = data[pos + 4: pos + 4 + ie_l]
        if ie_t == target_type:
            return ie_t, ie_d
        if ie_t in (3, 10, 11, 4):   # grouped IEs
            result = find_ie(ie_d, target_type, depth + 1)
            if result[0]: return result
        pos += 4 + ie_l
    return None, None
```

---

## References

- [3GPP TS 29.244](https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/) — PFCP Protocol Specification
- [Open5GS Documentation](https://open5gs.org/open5gs/docs/)
- [UERANSIM GitHub](https://github.com/aligungr/UERANSIM)
- [3GPP TS 23.501](https://www.3gpp.org/ftp/Specs/archive/23_series/23.501/) — 5G System Architecture

---

## Disclaimer

> This project is for **academic and research purposes only**, conducted in an isolated virtual lab environment. All attack simulations target a self-hosted Open5GS instance with no connection to real 5G infrastructure.
