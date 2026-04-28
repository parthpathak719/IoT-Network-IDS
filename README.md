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

| File | Description |
|------|-------------|
| `iot_server.py` | TLS/DTLS server with real-time ML detection |
| `iot_client.py` | Normal IoT traffic simulator |
| `attacker_sim.py` | Attack traffic generator (4 attack types) |
| `ml_anomaly_detector.py` | Model training and evaluation |
| `dl_autoencoder.py` | MLP model class definition |
| `dashboard.py` | Real-time Flask dashboard |
| `threat_report.py` | Automated threat report generator |
| `certs/` | TLS/DTLS SSL certificates |
| `traffic_log.csv` | Auto-generated traffic log (created at runtime) |

## Attack Types Simulated
| Attack | Protocol | Payload Size | Description |
|--------|----------|-------------|-------------|
| Heartbleed | TLS | ~490 bytes | Malformed heartbeat request exploiting OpenSSL |
| POODLE | TLS | ~352 bytes | SSL 3.0 fallback exploit using CBC padding |
| Amplification | DTLS | ~4000 bytes | Massive UDP payload to overwhelm server |
| Replay | DTLS | ~680 bytes | Captured handshake replayed to hijack sessions |

## Dashboard Features
- Live packet count, anomaly count, and attack rate
- Donut chart — normal vs anomaly traffic ratio
- Line chart — packets over time
- Bar chart — breakdown by attack type
- Live packet table with last 20 entries (auto-refreshes every 3 seconds)

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

### Step 2: Start the IoT Server
**Terminal 1** — keep this running throughout:
```bash
python iot_server.py
```

### Step 3: Start the Dashboard
**Terminal 2** — open `http://localhost:5050` in your browser:
```bash
python dashboard.py
```

### Step 4: Generate Normal Traffic
**Terminal 3** — let it run for a minute to build up baseline:
```bash
python iot_client.py
```

### Step 5: Simulate Attacks
**Terminal 4** — watch the dashboard go live with detections:
```bash
python attacker_sim.py --loop 30 --attack random
```

### Step 6: Train the Model
**Terminal 3** — stop the client (Ctrl+C), then retrain:
```bash
python ml_anomaly_detector.py
```

### Step 7: Generate Threat Report
**Terminal 3**:
```bash
python threat_report.py
```
Generates `threat_summary.txt` and `threat_report.csv` in the project folder.