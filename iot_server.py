import socket
import ssl
import threading
import time
import csv
import logging
import os

try:
    import joblib
    import numpy as np
    from dl_autoencoder import DeepLearningIDS
except ImportError:
    pass

# The python3-dtls library on PyPI is severely broken.
# Since this is an ML simulation, we will simulate the DTLS stream using a standard UDP socket.

# Configuration
TLS_PORT = 4443
DTLS_PORT = 4444
CERTFILE = 'certs/server.crt'
KEYFILE = 'certs/server.key'
LOG_FILE = 'traffic_log.csv'
MODEL_FILE = 'anomaly_model.pkl'

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

last_packet_time = 0.0

# Replay attack deduplication
_last_replay_time = 0
_REPLAY_DEDUP_WINDOW = 0.5  # seconds


def init_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'protocol', 'payload_size', 'processing_time_ms', 'anomaly_score'])

def load_model():
    if os.path.exists(MODEL_FILE):
        logging.info(f"Loading anomaly detection model from {MODEL_FILE}")
        model = joblib.load(MODEL_FILE)
        return model
    return None

ml_model = load_model()

def check_anomaly(payload_size, proc_time, time_diff):
    global _last_replay_time
    if ml_model is not None:
        try:
            import pandas as pd
            features = pd.DataFrame([[payload_size, time_diff]], columns=['payload_size', 'time_diff'])
            prediction = ml_model.predict(features)
            if prediction[0] == -2:
                logging.warning(f"!!! ANOMALY DETECTED !!! - DTLS Amplification Attack (Size: {payload_size} bytes)")
                return -2
            elif prediction[0] == -3:
                logging.warning(f"!!! ANOMALY DETECTED !!! - TLS Heartbleed Attack (Size: {payload_size} bytes)")
                return -3
            elif prediction[0] == -4:
                logging.warning(f"!!! ANOMALY DETECTED !!! - TLS POODLE Attack (Size: {payload_size} bytes)")
                return -4
            elif prediction[0] == -5:
                now = time.time()
                if now - _last_replay_time > _REPLAY_DEDUP_WINDOW:
                    _last_replay_time = now
                    logging.warning(f"!!! ANOMALY DETECTED !!! - DTLS Replay Attack (Size: {payload_size} bytes)")
                    return -5
                else:
                    return 1  # duplicate burst packet — ignore
            elif prediction[0] == -1:
                logging.warning(f"!!! UNKNOWN ANOMALY !!! - Traffic pattern deviates from normal memorized profile (Size: {payload_size} bytes)")
                return -1
            return 1
        except Exception as e:
            return 0
    return 0

def log_traffic(protocol, payload_size, proc_time_ms, anomaly_score):
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        # We write 7 columns to match the header:
        # timestamp, protocol, payload_size, entropy, proc_time, anomaly_score, label
        writer.writerow([time.time(), protocol, payload_size, 0.0, proc_time_ms, anomaly_score, anomaly_score])

# --- TLS SERVER (TCP) ---
def handle_tls_client(conn, addr):
    global last_packet_time
    logging.info(f"TLS connection from {addr}")
    start_time = time.time()
    try:
        data = conn.recv(1024)
        if data:
            now = time.time()
            payload_size = len(data)
            proc_time_ms = (now - start_time) * 1000
            time_diff = now - last_packet_time if last_packet_time > 0 else 1.0
            last_packet_time = now
            anomaly_score = check_anomaly(payload_size, proc_time_ms, time_diff)
            log_traffic('TLS', payload_size, proc_time_ms, anomaly_score)
            
            if anomaly_score == -1:
                conn.sendall(b"ALERT - Unknown Anomaly Detected")
            elif anomaly_score < -1:
                conn.sendall(b"ALERT - Known Attack Detected")
            else:
                conn.sendall(b"OK - TLS Data Received")
    except Exception as e:
        logging.error(f"TLS handler error from {addr}: {e}")
    finally:
        conn.close()

def start_tls_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind(('0.0.0.0', TLS_PORT))
    bindsocket.listen(5)
    with context.wrap_socket(bindsocket, server_side=True) as tls_socket:
        logging.info(f"Listening for TLS connections on TCP port {TLS_PORT}")
        while True:
            try:
                conn, addr = tls_socket.accept()
                threading.Thread(target=handle_tls_client, args=(conn, addr)).start()
            except Exception as e:
                logging.error(f"TLS Accept Error: {e}")

# --- DTLS SERVER (UDP Simulation) ---
def start_dtls_server():
    global last_packet_time
    try:
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bindsocket.bind(('0.0.0.0', DTLS_PORT))
        logging.info(f"Listening for DTLS (Simulated) connections on UDP port {DTLS_PORT}")
        while True:
            try:
                data, addr = bindsocket.recvfrom(4096)
                start_time = time.time()
                if data:
                    now = time.time()
                    payload_size = len(data)
                    proc_time_ms = (now - start_time) * 1000
                    time_diff = now - last_packet_time if last_packet_time > 0 else 1.0
                    last_packet_time = now
                    anomaly_score = check_anomaly(payload_size, proc_time_ms, time_diff)
                    log_traffic('DTLS', payload_size, proc_time_ms, anomaly_score)
                    
                    if anomaly_score == -1:
                        bindsocket.sendto(b"ALERT - Unknown Anomaly Detected", addr)
                    elif anomaly_score < -1:
                        bindsocket.sendto(b"ALERT - Known Attack Detected", addr)
                    else:
                        bindsocket.sendto(b"OK - DTLS Data Received", addr)
            except Exception as e:
                pass
    except Exception as e:
        logging.error(f"Could not start DTLS Server: {e}")

if __name__ == "__main__":
    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        print(f"Error: Certificates not found in 'certs/' directory. Please run setup.sh first.")
        exit(1)

    init_log_file()

    t1 = threading.Thread(target=start_tls_server, daemon=True)
    t2 = threading.Thread(target=start_dtls_server, daemon=True)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down server...")
