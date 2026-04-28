import socket
import ssl
import time
import random
import argparse

# Python DTLS packages are completely broken in modern Python 3.
# We will simulate DTLS by just using raw UDP sockets since the ML only cares about payload and timing.

SERVER_IP = '127.0.0.1'
TLS_PORT = 4443
DTLS_PORT = 4444
CA_CERT = 'certs/ca.crt'
CLIENT_CERT = 'certs/client.crt'
CLIENT_KEY = 'certs/client.key'

def get_tls_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False
    return context

def attack_tls_heartbleed():
    print("[ATTACK] Running TLS Heartbleed Attack (Malformed Heartbeat Request)...")
    context = get_tls_context()
    try:
        with socket.create_connection((SERVER_IP, TLS_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname='iot_server') as tls_sock:
                # Attack behavior: Payload size exactly 500 bytes (anomaly)
                payload = b"HEARTBLEED_REQ" * 35 # roughly 500 bytes
                tls_sock.sendall(payload)
                tls_sock.recv(1024)
        time.sleep(0.05) 
    except Exception:
        pass

def attack_dtls_amplification():
    print("[ATTACK] Running DTLS Amplification Attack (Massive UDP Payload)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Blast a single massive 4000-byte payload to simulate an amplification reflection attack
        payload = b"A" * 4000
        sock.sendto(payload, (SERVER_IP, DTLS_PORT))
        time.sleep(0.05)
        sock.close()
    except Exception:
        pass

def attack_tls_poodle():
    print("[ATTACK] Running TLS POODLE Attack (SSL 3.0 Fallback Exploit)...")
    context = get_tls_context()
    try:
        with socket.create_connection((SERVER_IP, TLS_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname='iot_server') as tls_sock:
                # POODLE behavior: repeated small crafted CBC-padded blocks (~200 bytes)
                # Simulates forcing SSL3.0 fallback with padding oracle probe
                payload = b"POODLE_CBC_PAD\x10" * 22  # ~352 bytes
                tls_sock.sendall(payload)
                tls_sock.recv(1024)
        time.sleep(0.05)
    except Exception:
        pass

def attack_dtls_replay():
    print("[ATTACK] Running DTLS Replay Attack (Captured Handshake Replay)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Replay behavior: burst of identical captured handshake packets in rapid succession
        # Simulates replaying a valid DTLS ClientHello to hijack sequence numbers
        captured_handshake = b"DTLS_REPLAY_SEQ\x00\x01" * 40  # ~680 bytes, sent rapidly
        for _ in range(5):
            sock.sendto(captured_handshake, (SERVER_IP, DTLS_PORT))
            time.sleep(0.01)  # Rapid burst - key signature of replay
        sock.close()
    except Exception:
        pass


def generate_attack_data(iterations, min_delay, max_delay, specific_attack=None):
    attack_map = {
        'tls_heartbleed': attack_tls_heartbleed,
        'dtls_amp': attack_dtls_amplification,
        'tls_poodle': attack_tls_poodle,
        'dtls_replay': attack_dtls_replay
    }
    
    print(f"Starting automated attack data generation ({iterations} iterations)...")
    for i in range(iterations):
        print(f"\n--- Attack Sequence {i+1}/{iterations} ---")
        if specific_attack and specific_attack in attack_map:
            attack_type = attack_map[specific_attack]
        else:
            attack_type = random.choice(list(attack_map.values()))
            
        attack_type()
        
        if i < iterations - 1: # Don't sleep after the last sequence
            delay = random.uniform(min_delay, max_delay)
            print(f"Waiting for a random interval of {delay:.2f} seconds before the next sequence...")
            time.sleep(delay)
            
    print("\nData generation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate Attacks for ML Data Generation")
    parser.add_argument('--loop', type=int, default=1, help='Number of attack sequences to run')
    parser.add_argument('--attack', type=str, choices=['random', 'tls_heartbleed', 'dtls_amp', 'tls_poodle', 'dtls_replay'],
                        default='random', help='Run a specific attack, or random attacks')
    parser.add_argument('--min-interval', type=float, default=1.0, help='Minimum random delay between scripts (seconds)')
    parser.add_argument('--max-interval', type=float, default=8.0, help='Maximum random delay between scripts (seconds)')
    args = parser.parse_args()
    
    selected_attack = None if args.attack == 'random' else args.attack
    generate_attack_data(args.loop, args.min_interval, args.max_interval, selected_attack)
