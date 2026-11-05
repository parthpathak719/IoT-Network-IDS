# IoT Network Intrusion Detection System

A local IoT traffic simulation with TLS, simulated DTLS traffic over plain UDP, a hybrid machine learning intrusion detector, a live Flask dashboard, and generated threat reports.

The attack generators send synthetic payloads with different sizes and timings. They do not exploit Heartbleed or POODLE, implement DTLS encryption, or demonstrate real amplification or session hijacking.

## Detection Model

The `DeepLearningIDS` class combines:

- An **Isolation Forest** trained on normal traffic to identify outliers.
- An **MLP classifier** with hidden layers `(128, 64, 32)` to classify known simulated attacks.
- Confidence thresholds that classify uncertain outliers as unknown anomalies.

The inputs are `payload_size` and `time_diff`. Training labels are derived from payload size rules, and the training script reports metrics on the training data. These metrics do not establish performance on unseen traffic or real attacks.

| Output | Meaning |
|--------|---------|
| `1` | Normal traffic |
| `-1` | Unknown anomaly |
| `-2` | Simulated DTLS amplification |
| `-3` | Simulated TLS Heartbleed |
| `-4` | Simulated TLS POODLE |
| `-5` | Simulated DTLS replay |

## Project Structure

| File | Description |
|------|-------------|
| `iot_server.py` | TLS and UDP simulation server with detection and CSV logging |
| `iot_client.py` | Normal IoT traffic simulator |
| `attacker_sim.py` | Four known attack simulations and three novel anomaly generators |
| `ml_anomaly_detector.py` | Model training and training-set evaluation |
| `dl_autoencoder.py` | Hybrid Isolation Forest and MLP model definition |
| `dashboard.py` | Live Flask dashboard |
| `threat_report.py` | Threat report generator |
| `setup.sh` | Ubuntu/Debian dependency installation and certificate generation |
| `PROJECT_REPORT.txt` | Project overview |

Certificates in `certs/`, `anomaly_model.pkl`, `traffic_log.csv`, and generated threat reports are local files excluded by `.gitignore`. Generate them after cloning.

## Setup

Use **Python 3.11** with the pinned dependencies in `requirements.txt`, plus OpenSSL for certificate generation. Run commands from the project directory.

### Ubuntu/Debian

With `python3` pointing to Python 3.11, run:

```bash
bash setup.sh
source .venv/bin/activate
```

The setup script installs dependencies and generates a local CA, server certificate, and client certificate. Running it again replaces the certificates, so stop the simulation first.

### Windows

Create and activate a virtual environment in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install OpenSSL and ensure `openssl` is available in PowerShell, then generate local certificates:

```powershell
New-Item -ItemType Directory -Force certs | Out-Null
openssl req -x509 -sha256 -days 365 -nodes -newkey rsa:2048 -subj "/CN=IoT_Root_CA" -keyout certs/ca.key -out certs/ca.crt
openssl req -nodes -newkey rsa:2048 -subj "/CN=iot_server" -keyout certs/server.key -out certs/server.csr
openssl x509 -req -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -in certs/server.csr -out certs/server.crt -days 365 -sha256
openssl req -nodes -newkey rsa:2048 -subj "/CN=iot_client" -keyout certs/client.key -out certs/client.csr
openssl x509 -req -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -in certs/client.csr -out certs/client.crt -days 365 -sha256
```

Generate fresh development keys after cloning. Keys included in earlier commits are exposed; stopping tracking them does not remove those copies from Git history. These self-signed certificates and the disabled client hostname check are intended for this local simulation.

## Run the Simulation

Activate the same virtual environment in each terminal before running Python commands.

1. Start the server in terminal 1:

   ```bash
   python iot_server.py
   ```

   On the first run, no model exists, so the server collects traffic with an anomaly score of `0` (unclassified).

2. Start the dashboard in terminal 2 and open `http://localhost:5050`:

   ```bash
   python dashboard.py
   ```

3. Generate normal traffic in terminal 3. Let it run for at least a minute:

   ```bash
   python iot_client.py
   ```

4. In terminal 4, collect each known attack class for training:

   ```bash
   python attacker_sim.py --loop 10 --attack dtls_amp
   python attacker_sim.py --loop 10 --attack tls_heartbleed
   python attacker_sim.py --loop 10 --attack tls_poodle
   python attacker_sim.py --loop 10 --attack dtls_replay
   ```

5. Stop the client and server with Ctrl+C after collection, then train:

   ```bash
   python ml_anomaly_detector.py
   ```

   This creates `anomaly_model.pkl`. The server loads the model only at startup, so restart `python iot_server.py` after every training run. Restart the normal client and run more attacks to observe detections.

6. To start a fresh detection session, stop the traffic generators and server and delete only `traffic_log.csv` before restarting them. Keep the trained model. You can also simulate novel payloads:

   ```bash
   python attacker_sim.py --loop 10 --attack exfiltration
   python attacker_sim.py --loop 10 --attack malformed_control
   python attacker_sim.py --loop 10 --attack random_payload
   ```

7. Generate a report from the collected traffic:

   ```bash
   python threat_report.py
   ```

   This creates `threat_summary.txt` and `threat_report.csv` locally.

The dashboard refreshes every three seconds and shows traffic counts, attack categories, a packet timeline, and the latest 20 records. The servers bind to all interfaces on TCP port 4443 and UDP port 4444; the bundled clients connect to `127.0.0.1`.
