# 🛡️ Detress — Lightweight Network Detection & Response (NDR)

<p align="center"> <img src="https://img.shields.io/badge/Status-Active-blue?style=for-the-badge"/> <img src="https://img.shields.io/badge/Detection-Network%20Telemetry-red?style=for-the-badge"/> </p>

Detress is a small but practical Network Detection & Response (NDR) platform designed for security labs, SOC training, and Blue Team experimentation.
It provides real-time packet metadata capture, a simple analysis pipeline, and a clean dashboard to visualize both network activity and generated alerts.

## 📐 Architecture Overview

```scss
                ┌──────────────────────────────────────────────┐
                │                    Detress                   │
                └──────────────────────────────────────────────┘
                                   ▲             ▲
                                   │             │ Web Dashboard
                                   │             │
                              Alert API      ┌─────────────┐
                                             │ Frontend UI │
                                             └─────────────┘
                                   │
                          ┌────────┴────────┐
                          │   Backend API   │ (FastAPI)
                          └────────┬────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Analysis Pipeline │
                         │  - Simple rules   │
                         │  - Behavior       │
                         └───────┬───────────┘
                                 │
                                 ▼
                    ┌───────────────────────────┐
                    │   Capture Agent (Scapy)   │
                    │ Extracts packet metadata  │
                    └───────────────────────────┘
```

The backend exposes REST endpoints for ingestion and alert retrieval, the capture module streams network metadata to the API, and the dashboard polls the backend every few seconds to display recent flows and alerts.

## ✨ Features

### Network Capture (Scapy)

- Live packet sniffing
- Metadata extraction (IP addresses, ports, protocol, packet size, timestamps)
- Lightweight JSON events sent to the backend


### Analysis Pipeline

A simple but realistic SOC-style rule engine:
- Port scan detection (burst analysis)
- Sensitive port access alerts
- Time-window based checks
- Basic behavioral rules (extensible)

Rules are cleanly separated and easy to extend.


### Alerting

- Severity levels (low / medium / high)
- Categories for quick triage
- Real-time generation
- Stored in memory for demonstration purposes


### Dashboard

A minimal web UI to visualize:

- The last 100 traffic events
- The last 50 alerts
- Backend health status
- Auto-refresh every 2 seconds

No frameworks.


## 🚀 Quick Start

### Requirements

- Docker Desktop
- Python 3.11+ (optional, for running the capture agent on the host)

### Running with Docker (Backend + Dashboard)
```bash
docker compose up --build
```

Once started, open:
```cpp
http://127.0.0.1:8000
```
You’ll see the dashboard updating in real time.


### Running the Capture Agent on the Host (Recommended on Windows)

Docker Desktop cannot sniff the host network.
For real traffic visibility, run the capture agent locally:

```bash
cd capture
python main.py
```

It will automatically send events to:

```arduino
http://127.0.0.1:8000/traffic
```


# 🧪 Basic Tests (No Capture)

### Send a test event
```bash
python tests/test_api.py
```

### Trigger a sensitive port alert
```bash
python tests/test_sensitive.py
```


# 📁 Project Structure

```bash
Detress/
│
├── backend/
│   ├── main.py           # FastAPI backend and rule engine
│   ├── static/index.html # Dashboard UI
│
├── capture/
│   ├── main.py           # Scapy capture agent
│
├── tests/
│   ├── test_api.py
│   ├── test_sensitive.py
│
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
└── README.md
```


# 🛠 Technology Stack

Component	Technology
Backend	FastAPI (Python)
Capture Agent	Scapy
Communication	REST / JSON
Dashboard	HTML + Vanilla JS
Deployment	Docker / Compose

| Component | Technology |
| --- | --- |
| `backend` | FastAPI (Python) |
| `capture` | Agent	Scapy |
| `Communication` | REST / JSON |
| `Dashboard` | HTML + Vanilla JS |
| `Deployment` | Docker / Compose |


# 🔮 Future Improvements

### Planned enhancements:

- PCAP import support
- YAML rule definitions (Suricata-style light rules)
- JA3/JA3S fingerprinting
- Threat intelligence enrichment (Abuse.ch, OTX, blocklists)
- More behavioral rules and correlation logic
- Optional TimescaleDB storage


# 📜 License

MIT License.
