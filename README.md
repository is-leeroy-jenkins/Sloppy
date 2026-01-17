





## 📌 Overview

**Sloppy** is a Python-based, interactive network packet analysis application built with **Streamlit**.
It combines **low-level protocol parsing**, **live or simulated packet capture**, and **real-time analytics** into a single, analyst-friendly interface.

The application is intentionally designed to *feel sophisticated and exploratory* while remaining lightweight, transparent, and easy to extend.



## ✨ Key Capabilities

* 🧪 **Demo / Replay Mode** — deterministic synthetic traffic for testing and demos
* 🛰️ **Live Packet Capture** — real-time sniffing via Scapy (privilege-aware)
* 🔍 **Manual Protocol Parsing** — Ethernet, IPv4, TCP, UDP, ICMP (no black boxes)
* 🧵 **Thread-Safe Ingestion** — background capture with queue-based buffering
* 🪟 **Rolling Session Window** — bounded memory, continuous updates
* 🎛️ **Interactive Filtering** — protocol, port range, packet window
* 📊 **Real-Time Analytics** — metrics, distributions, and time series
* 📋 **Live Packet Stream** — sortable, scrollable metadata table



## 🧱 Architecture at a Glance

```
┌────────────────────┐
│  🧪 Demo Generator  │
│  🛰️ Scapy Capture   │
└─────────┬──────────┘
          │ raw bytes
┌─────────▼──────────┐
│ 🔍 Protocol Parsers │
│ Ethernet / IPv4     │
│ TCP / UDP / ICMP    │
└─────────┬──────────┘
          │ normalized records
┌─────────▼──────────┐
│ 🧵 Session State    │
│ Queue + Windowing   │
└─────────┬──────────┘
          │ DataFrame
┌─────────▼──────────┐
│ 📊 Analytics & UI   │
│ Metrics • Charts    │
└────────────────────┘
```



## 📁 Project Structure

```
sloppy/
├── 🧠 __init__.py        # Core protocol parsing library
├── 🖥️ app.py            # Streamlit application orchestrator
├── ⚙️ config.py         # UI assets and configuration
├── 📦 requirements.txt  # Python dependencies
└── 📘 README.md         # Documentation
```



## 🧠 Core Parsing Engine (`__init__.py`)

Sloppy includes a **manual protocol decoding layer**, implemented directly against raw bytes.

### Supported Protocols

* 🧬 **Ethernet** — MAC addresses, EtherType
* 🌐 **IPv4** — TTL, protocol, source/destination IP
* 🔁 **TCP** — ports, flags, sequence data
* 📡 **UDP** — ports and payload
* 📣 **ICMP** — type and code
* 🌍 **HTTP** — best-effort UTF-8 payload decoding

### Why This Matters

* No reliance on Scapy for parsing logic
* Deterministic and testable behavior
* Reusable outside Streamlit
* Ideal for education, research, and controlled analysis



## 🖥️ Streamlit Application (`app.py`)

The Streamlit layer provides **orchestration, analytics, and visualization**, not parsing.

### Capture Modes

#### 🧪 Demo / Replay

* Generates realistic synthetic packets
* No admin privileges required
* Exercises the full analytics pipeline

#### 🛰️ Live (Scapy)

* Captures real network traffic
* Runs in a background daemon thread
* Gracefully disabled if Scapy or privileges are missing



## 🎛️ User Interface

### Sidebar Controls

* ▶️ Start / ■ Stop capture
* 🔄 Capture mode selection
* 🎚️ Protocol filters
* 🔢 Destination port range
* 🪟 Rolling packet window size

### Main Panel

* 📈 Executive metrics
* 📊 Protocol distribution
* ⏱️ Traffic over time (windowed)
* 📋 Live packet stream table



## 📊 Analytics & Visualizations

* **📈 Executive Metrics**

  * Total packets
  * Unique source IPs
  * Unique destination IPs
  * Average packet size
  * Protocol diversity

* **📊 Protocol Distribution**

  * Categorical breakdown of observed traffic

* **⏱️ Traffic Over Time**

  * Packets per second
  * Safely windowed to prevent memory blowups

* **📋 Live Packet Stream**

  * Timestamp-sorted metadata view
  * Scrollable and filter-aware



## 🧵 Concurrency & Safety

* Background capture runs in a **daemon thread**
* UI never blocks on network I/O
* Packet ingestion uses a bounded queue
* Rolling window enforces memory limits
* Streamlit rerun model respected at all times



## 📦 Installation

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install streamlit scapy
```



## ▶️ Running Sloppy

```bash
streamlit run app.py
```

> ⚠️ **Live capture requires administrator/root privileges.**
> Demo mode works without elevation.





## 🧭 Natural Extension Points

* 📂 PCAP import/export
* 🔗 Flow reconstruction (5-tuple)
* 🚨 Anomaly & threat scoring
* 💾 Persistent session storage
* 📡 Protocol-specific dashboards
* 📤 Report export (CSV / Markdown)



## 📜 License 

[MIT License](https://github.com/is-leeroy-jenkins/Sloppy/blob/main/LICENSE.txt)
© 2022–2025 Terry D. Eppler


