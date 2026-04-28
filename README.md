# IoT Security & Deep Learning Anomaly Detection

This project simulates a secure IoT environment using **TLS** and **DTLS** protocols. It includes an automated traffic simulator and a **Supervised Multi-Class Deep Learning** model to monitor network payloads and detect intrusions in real-time.

## Deep Learning Model Architecture
The Intrusion Detection System (IDS) uses a **Multi-Layer Perceptron (MLP) Neural Network** built with `sklearn.neural_network.MLPClassifier`. 

Instead of a simple "yes/no" anomaly detector, it is a **Multi-Class Classifier** designed to specifically identify different types of attacks.

**Model Specifications:**
- **Inputs:** 2 features (`payload_size`, `processing_time_ms`)
- **Hidden Layers:** 3 dense layers `(128 nodes -> 64 nodes -> 32 nodes)`
- **Activation Function:** ReLU (Rectified Linear Unit)
- **Optimizer:** Adam
- **Outputs (Classes):**
  - `1` : Normal/Benign Traffic
  - `-2`: DTLS Amplification Attack
  - `-3`: TLS Heartbleed Attack

## Usage Instructions

### Step 1: Clean Up Old Data
To ensure your deep learning model is only trained on fresh simulation data, always delete or clear your old log file before starting a new test:
```bash
rm traffic_log.csv
```
*(Note: The system will automatically recreate it with the proper headers when the server starts).*

### Step 2: Start the IoT Server
In your first terminal window, activate your virtual environment and start the server:
```bash
./.venv/bin/python iot_server.py
```
*Leave this running. It will listen for incoming traffic and eventually use our trained model to classify attacks in real-time.*

### Step 3: Simulate Network Traffic & Attacks
Open a **second terminal window**, activate your virtual environment, and run the simulator. You can specify exactly how many attack loops to generate using the `--loop` flag:
```bash
./.venv/bin/python attacker_sim.py --loop 120
```
This script will fire a mix of normal traffic, DTLS Amplification, and TLS Heartbleed attacks at your server. All of this is logged into `traffic_log.csv`.

### Step 4: Train and Evaluate the Deep Learning Model
Once the simulator has finished running, use the collected data to train the MLP Neural Network:
```bash
./.venv/bin/python ml_anomaly_detector.py
```
This script will:
1. Load `traffic_log.csv`.
2. Automatically label the data (Normal, Heartbleed, DTLS Amp).
3. Train the neural network.
4. Output a detailed evaluation (Accuracy, Precision, Recall).
5. Save the trained model to `anomaly_model.pkl`.

### Step 5: Real-Time Active Defense
Now that `anomaly_model.pkl` exists, your running `iot_server.py` (from Step 2) is automatically using the Deep Learning model to scan all incoming packets. Run the `attacker_sim.py` script again, and you will see the server actively blocking and identifying specific attacks in real-time!
