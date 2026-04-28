# IoT Network Intrusion Detection System

This project simulates a secure IoT environment using **TLS** and **DTLS** protocols. It includes an automated traffic simulator, a **Supervised Multi-Class Deep Learning** model to detect intrusions in real-time, a live dashboard, and an automated threat report generator.

## Deep Learning Model Architecture
The Intrusion Detection System (IDS) uses a **Multi-Layer Perceptron (MLP) Neural Network** built with `sklearn.neural_network.MLPClassifier`.

Instead of a simple "yes/no" anomaly detector, it is a **Multi-Class Classifier** designed to specifically identify different types of attacks.

**Model Specifications:**
- **Inputs:** 2 features (`payload_size`, `time_diff`)
- **Hidden Layers:** 3 dense layers `(128 nodes -> 64 nodes -> 32 nodes)`
- **Activation Function:** ReLU (Rectified Linear Unit)
- **Optimizer:** Adam
- **Outputs (Classes):**
  - `1`  : Normal/Benign Traffic
  - `-2` : DTLS Amplification Attack
  - `-3` : TLS Heartbleed Attack
  - `-4` : TLS POODLE Attack
  - `-5` : DTLS Replay Attack

## Project Structure
DS_Project/
├── iot_server.py          # TLS/DTLS server with real-time ML detection
├── iot_client.py          # Normal IoT traffic simulator
├── attacker_sim.py        # Attack traffic generator (4 attack types)
├── ml_anomaly_detector.py # Model training and evaluation
├── dl_autoencoder.py      # MLP model class definition
├── dashboard.py           # Real-time Flask dashboard
├── threat_report.py       # Automated threat report generator
├── certs/                 # TLS/DTLS certificates
└── traffic_log.csv        # Auto-generated traffic log

## Attack Types Simulated
| Attack | Protocol | Payload Size | Description |
|--------|----------|-------------|-------------|
| Heartbleed | TLS | ~490 bytes | Malformed heartbeat request exploiting OpenSSL |
| POODLE | TLS | ~352 bytes | SSL 3.0 fallback exploit using CBC padding |
| Amplification | DTLS | ~4000 bytes | Massive UDP payload to overwhelm server |
| Replay | DTLS | ~680 bytes | Captured handshake replayed to hijack sessions |

## Usage Instructions

### Prerequisites
```bash
pip install -r requirements.txt
```

### Step 1: Delete Old Data
Always start fresh before a new run:
```bash
del traffic_log.csv        # Windows
rm traffic_log.csv         # Linux/Mac
```
The server will auto-recreate it with proper headers on startup.

### Step 2: Start the IoT Server
In **Terminal 1** — keep this running throughout:
```bash
python iot_server.py
```

### Step 3: Start the Dashboard
In **Terminal 2** — open `http://localhost:5050` in your browser:
```bash
python dashboard.py
```

### Step 4: Generate Normal Traffic
In **Terminal 3**:
```bash
python iot_client.py
```
Let it run for a minute to build up normal traffic baseline, then Ctrl+C.

### Step 5: Simulate Attacks
In **Terminal 3**:
```bash
python attacker_sim.py --loop 30 --attack random
```
Watch the dashboard go live with attack detections. You can also target a specific attack:
```bash
python attacker_sim.py --loop 10 --attack tls_heartbleed
python attacker_sim.py --loop 10 --attack dtls_amp
python attacker_sim.py --loop 10 --attack tls_poodle
python attacker_sim.py --loop 10 --attack dtls_replay
```

### Step 6: Train the Model
Once enough data is collected:
```bash
python ml_anomaly_detector.py
```
This will load `traffic_log.csv`, label the data, train the MLP, print accuracy/precision/recall, and save `anomaly_model.pkl`.

### Step 7: Restart Server
Restart `iot_server.py` to load the freshly trained model, then run the attacker again — the server will now classify all 4 attack types in real-time.

### Step 8: Generate Threat Report
```bash
python threat_report.py
```
Generates `threat_summary.txt` (human-readable) and `threat_report.csv` (machine-readable) in the project folder.

## Dashboard Features
- Live packet count, anomaly count, and attack rate
- Donut chart — normal vs anomaly traffic ratio
- Line chart — packets over time
- Bar chart — breakdown by attack type
- Live packet table with last 20 entries (auto-refreshes every 3 seconds)