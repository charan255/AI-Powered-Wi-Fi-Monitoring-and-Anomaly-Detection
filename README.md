# AI-Powered Wi-Fi Network Monitoring, Traffic Logging and Anomaly Detection System

A defensive cybersecurity and network traffic intelligence platform built for local wireless networks. It passively observes network frames, parses Layer 2–4 metadata, logs traffic in MongoDB, detects intrusions and abnormal traffic flows using both unsupervised Machine Learning (**Isolation Forest**) and rule-based heuristics (**Port Scanning**, **Connection Spikes**, **Bandwidth Surges**, **Rogue MACs**), and provides a live web dashboard powered by **FastAPI**, **React**, and **Recharts**.

---

## 1. System Architecture

```
                    [ Wi-Fi / Ethernet Network Interface ]
                                      │
                     Scapy Packet Sniffer / Generator
                                      │
                                      ▼
                        Header & Metadata Parser
                 (L2 MAC, L3 IPv4, L4 TCP/UDP/ICMP/ARP)
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
       [ MongoDB Storage ]                         [ Analytics Engine ]
    - traffic_logs (L2-L4 logs)               - Rolling Feature Extractor
    - anomalies (ML records)                  - Isolation Forest (sklearn)
    - alerts (Heuristic alerts)               - Rule-Based Detectors:
    - devices (Subnet inventory)                 • SYN Port Scan Probes
                                                 • Connection / Packet Spikes
                                                 • Bandwidth Surges
                                                 • Unknown Device Alerts
                                                             │
                                                             ▼
                                                    [ FastAPI Backend ]
                                                 - REST Endpoints (/api/...)
                                                 - WebSocket (/ws/live)
                                                             │
                                                             ▼
                                                [ React + Vite Dashboard ]
                                                 - Real-Time Throughput Graph
                                                 - Protocol Breakdown (Recharts)
                                                 - Live Packet Inspector Modal
                                                 - Threats & Anomaly Center
                                                 - Wi-Fi Device Inventory
```

---

## 2. Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.13 | Core backend, packet processing, ML training |
| **Backend API** | FastAPI + Uvicorn | High-performance asynchronous REST & WebSocket server |
| **Packet Capture** | Scapy | Passive Layer 2–4 frame sniffing and packet dissection |
| **Database** | MongoDB + PyMongo | Document storage for telemetry, anomalies, and devices |
| **Machine Learning** | scikit-learn (`IsolationForest`) | Unsupervised statistical anomaly detection on feature vectors |
| **Frontend Framework** | React 18 + Vite | Modern reactive single-page dashboard |
| **Data Visualization** | Recharts | Live area charts, pie charts, and rate counters |
| **Styling & Icons** | Tailwind CSS + Lucide-React | Cybersecurity SOC-style dark theme interface |

---

## 3. Core Features & Detection Modules

### A. Passive Packet Ingestion & Parsing
- Extracts: Timestamp, Source IP, Destination IP, Source MAC, Destination MAC, Transport Protocol (TCP, UDP, ICMP, ARP), Source Port, Destination Port, Packet Length, TCP Flags (SYN, ACK, FIN, RST, PSH, URG), TTL, and Application Service Identification (HTTP, HTTPS, DNS, NTP, SSH).

### B. Machine Learning Anomaly Detection (Isolation Forest)
- Unsupervised anomaly detection that isolates outliers without requiring labeled intrusion datasets.
- Computes sliding-window behavioral vectors per IP:
  $$\mathbf{x} = \left[ r_{\text{packet}}, r_{\text{bytes}}, n_{\text{unique\_ports}}, n_{\text{unique\_ips}}, \rho_{\text{SYN}}, \rho_{\text{UDP}}, \bar{s}_{\text{packet}} \right]$$
- Normalizes features using `StandardScaler` and isolates statistically aberrant behavior ($s(x) < 0$).

### C. Rule-Based Heuristic Threat Detectors
1. **SYN Port Scan Detector**: Flags any host attempting connections to $\ge 15$ distinct ports within a 5-second window.
2. **Packet Flood / Connection Spike**: Detects abnormal packet velocities exceeding baseline capacity.
3. **Bandwidth Surge**: Alerts on abnormal bulk data transfers.
4. **Unknown / Rogue Device Discovery**: Alerts when an unregistered MAC address is first observed communicating on the subnet.

### D. Dual Operation Mode (Live NIC Sniffing & Simulator)
- **Live Mode**: Uses Scapy and Npcap to capture live packets from your local Wi-Fi or Ethernet adapter.
- **Simulation Mode**: Generates realistic synthetic traffic and includes one-click attack triggers (**Port Scan**, **Connection Spike**, **Bandwidth Burst**, **Rogue MAC**) for classroom demonstrations, project viva, and evaluation.

---

## 4. Setup and Installation

### Prerequisites
1. **Python 3.10+**
2. **Node.js 18+** & **npm**
3. **MongoDB** (Local instance or MongoDB Atlas free cloud cluster)
   *(Note: The system includes an automatic in-memory fallback buffer if MongoDB is temporarily offline).*
4. *(Optional for live capture on Windows)*: [Npcap](https://npcap.com/) installed with "WinPcap API-compatible Mode".

---

### Step 1: Backend Setup

1. Open a terminal and navigate to the backend folder:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. (Optional) Copy configuration file:
   ```bash
   copy .env.example .env
   ```

4. Launch the FastAPI server:
   ```bash
   python run.py
   ```
   *The backend will run on `http://localhost:8000` (API Docs at `http://localhost:8000/docs`).*

---

### Step 2: Frontend Setup

1. Open a second terminal and navigate to the frontend folder:
   ```bash
   cd frontend
   ```

2. Install npm dependencies:
   ```bash
   npm.cmd install
   ```

3. Launch the Vite development server:
   ```bash
   npm.cmd run dev
   ```
   *Open your browser and navigate to `http://localhost:3000`.*

---

## 5. Live Demonstration & Viva Guide

### How to Demonstrate in Project Viva:
1. **Open the Dashboard**: Point your browser to `http://localhost:3000`.
2. **Observe Real-Time Telemetry**:
   - The **Throughput Area Chart** shows live bytes/sec and packets/sec.
   - The **Protocol Distribution Pie Chart** updates in real-time.
   - The **Dissected Packet Table** streams live Layer 2–4 frames (click any row to inspect headers and TCP flags).
3. **Test Heuristic & ML Detections**:
   - In the top **Control Panel**, click **"Port Scan (SYN)"**.
     - Notice the alert appear in the **Security Alerts** panel: `[CRITICAL] PORT_SCAN: Probed 25 distinct ports`.
   - Click **"Unknown MAC"**.
     - Notice the new device appear in the **Discovered Wi-Fi Host Inventory** and trigger a rogue device alert.
   - Click **"Retrain Isolation Forest"** to demonstrate on-the-fly model adaptation.

---

## 6. Defensive Ethics & Legal Scope
This software is strictly defensive. It operates purely in **passive listening** and **analytical** mode:
- Zero transmission of de-authentication or disruption frames.
- No packet injection, ARP poisoning, or payload tampering.
- Only run on networks and devices you own or have explicit authorization to monitor.
