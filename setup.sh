#!/bin/bash
set -e

echo "Starting setup for TLS/DTLS IoT Simulation Environment"

echo "1. Installing OS dependencies..."
# Update apt and install required tools.
sudo apt update
sudo apt install -y openssl libssl-dev python3-pip python3-venv build-essential python3-dev

echo "2. Setting up Python Virtual Environment..."
# Create a venv if it doesn't exist
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

# Activate the venv
source .venv/bin/activate

echo "3. Installing Python dependencies..."
pip install -r requirements.txt

echo "4. Generating SSL Certificates..."
mkdir -p certs
cd certs

# Generate a self-signed root CA
openssl req -x509 -sha256 -days 365 -nodes -newkey rsa:2048 -subj "/CN=IoT_Root_CA" -keyout ca.key -out ca.crt

# Generate Server key and CSR
openssl req -nodes -newkey rsa:2048 -subj "/CN=iot_server" -keyout server.key -out server.csr

# Sign Server Certificate
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -in server.csr -out server.crt -days 365 -sha256

# Generate Client key and CSR
openssl req -nodes -newkey rsa:2048 -subj "/CN=iot_client" -keyout client.key -out client.csr

# Sign Client Certificate
openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -in client.csr -out client.crt -days 365 -sha256

echo "Certificates generated successfully inside certs/"
cd ..

echo "---"
echo "Setup complete! To begin running the simulation:"
echo "1. Source the virtual environment: source .venv/bin/activate"
echo "2. Run the server: python3 iot_server.py"
