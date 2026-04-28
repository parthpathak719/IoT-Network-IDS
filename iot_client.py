import socket
import ssl
import time
import random
# Python DTLS PyPI packages are severely broken under modern Python 3.
# We will simulate DTLS by just using raw UDP sockets since the ML only cares about payload and timing.

SERVER_IP = '127.0.0.1'
TLS_PORT = 4443
DTLS_PORT = 4444
CA_CERT = 'certs/ca.crt'
CLIENT_CERT = 'certs/client.crt'
CLIENT_KEY = 'certs/client.key'

def send_tls_data():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False # For local testing

    try:
        with socket.create_connection((SERVER_IP, TLS_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname='iot_server') as tls_sock:
                # Normal behavior: payload size ~50 bytes
                payload = f"TEMP:{random.uniform(20.0, 25.0):.2f}|HUMID:{random.uniform(40.0, 50.0):.2f}".encode()
                tls_sock.sendall(payload)
                data = tls_sock.recv(1024)
                print(f"[TLS] Sent normal data. Server says: {data.decode()}")
    except Exception as e:
        print(f"[TLS] Connection error: {e}")

def send_dtls_data():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((SERVER_IP, DTLS_PORT))
        
        payload = f"STATUS:OK|BATTERY:{random.randint(80, 100)}".encode()
        sock.sendall(payload)
        data = sock.recv(1024)
        print(f"[DTLS] Sent normal data. Server says: {data.decode()}")
        sock.close()
    except Exception as e:
        print(f"[DTLS] Connection error: {e}")

if __name__ == "__main__":
    print("Simulating normal IoT device continuously... (Press Ctrl+C to stop)")
    try:
        while True:
            send_tls_data()
            time.sleep(1)
            send_dtls_data()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping normal IoT client.")
