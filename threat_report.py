import pandas as pd
import os
import csv
from datetime import datetime

LOG_FILE = 'traffic_log.csv'
REPORT_TXT = 'threat_summary.txt'
REPORT_CSV = 'threat_report.csv'

ATTACK_LABELS = {
    -2: 'DTLS Amplification Attack',
    -3: 'TLS Heartbleed Attack',
    -4: 'TLS POODLE Attack',
    -5: 'DTLS Replay Attack'
}

RISK_THRESHOLDS = {
    'LOW':    5,
    'MEDIUM': 15,
    'HIGH':   9999
}

def get_risk(count):
    if count == 0:
        return 'NONE'
    elif count <= RISK_THRESHOLDS['LOW']:
        return 'LOW'
    elif count <= RISK_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    else:
        return 'HIGH'

def generate_report():
    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found. Run the server and clients first.")
        return

    df = pd.read_csv(LOG_FILE)
    if df.empty:
        print("Error: traffic_log.csv is empty.")
        return

    # --- DATA SANITATION ---
    # Ensure anomaly_score is numeric, replace NaN (malformed rows) with 1 (Normal)
    df['anomaly_score'] = pd.to_numeric(df['anomaly_score'], errors='coerce').fillna(1)
    df['payload_size'] = pd.to_numeric(df['payload_size'], errors='coerce').fillna(0)
    # -----------------------

    df = df.sort_values('timestamp')
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')

    total = len(df)
    normal_count = len(df[df['anomaly_score'] >= 0])
    anomaly_df = df[df['anomaly_score'] < 0]
    anomaly_count = len(anomaly_df)

    # Duration
    duration_secs = df['timestamp'].max() - df['timestamp'].min()
    hours = int(duration_secs // 3600)
    minutes = int((duration_secs % 3600) // 60)
    seconds = int(duration_secs % 60)
    duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # Attack breakdown
    attack_counts = {}
    for label, name in ATTACK_LABELS.items():
        attack_counts[name] = len(df[df['anomaly_score'] == label])

    # Peak attack window (1-minute rolling window)
    peak_window_start = None
    peak_window_end = None
    peak_count = 0
    if not anomaly_df.empty:
        for ts in anomaly_df['timestamp']:
            window = anomaly_df[(anomaly_df['timestamp'] >= ts) & (anomaly_df['timestamp'] < ts + 60)]
            if len(window) > peak_count:
                peak_count = len(window)
                peak_window_start = datetime.fromtimestamp(window['timestamp'].min()).strftime('%H:%M:%S')
                peak_window_end = datetime.fromtimestamp(window['timestamp'].max()).strftime('%H:%M:%S')

    # Protocol risk
    tls_attacks = len(df[(df['anomaly_score'] < 0) & (df['protocol'] == 'TLS')])
    dtls_attacks = len(df[(df['anomaly_score'] < 0) & (df['protocol'] == 'DTLS')])

    # --- Write TXT ---
    with open(REPORT_TXT, 'w', encoding='utf-8') as f:
        f.write("================================================================\n")
        f.write("              IoT NETWORK THREAT REPORT\n")
        f.write(f"              Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("================================================================\n\n")

        f.write("OVERVIEW\n")
        f.write("-" * 64 + "\n")
        f.write(f"Total Packets Analyzed  : {total}\n")
        f.write(f"Normal Traffic          : {normal_count}  ({normal_count/total*100:.1f}%)\n")
        f.write(f"Total Anomalies         : {anomaly_count}   ({anomaly_count/total*100:.1f}%)\n")
        f.write(f"Monitoring Duration     : {duration_str}  (hh:mm:ss)\n\n")

        f.write("ATTACK BREAKDOWN\n")
        f.write("-" * 64 + "\n")
        for name, count in attack_counts.items():
            protocol = "TLS " if name.startswith("TLS") else "DTLS"
            pct = f"{count/anomaly_count*100:.1f}%" if anomaly_count > 0 else "0.0%"
            label = name[4:] if name.startswith("TLS") else name[5:]
            f.write(f"{protocol} | {label:<28}: {count} packets  ({pct} of attacks)\n")

        f.write("\nPEAK ATTACK WINDOW\n")
        f.write("-" * 64 + "\n")
        if peak_window_start:
            f.write(f"Highest Activity  : {peak_window_start} -> {peak_window_end}\n")
            f.write(f"Attack Frequency  : {peak_count} packets / min\n")
        else:
            f.write("No major attack peaks detected.\n")

        f.write("\nSECURITY RISK ASSESSMENT\n")
        f.write("-" * 64 + "\n")
        f.write(f"TLS Vulnerabilities  : {tls_attacks} events\n")
        f.write(f"DTLS Vulnerabilities : {dtls_attacks} events\n")
        
        status = "THREATS DETECTED — REVIEW RECOMMENDED" if anomaly_count > 0 else "ALL CLEAR — NO THREATS DETECTED"
        f.write(f"STATUS: {status}\n")
        f.write("-" * 64 + "\n")

    # ── Write CSV ──────────────────────────────────────────────────────────────
    with open(REPORT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'datetime', 'protocol', 'payload_size', 'processing_time_ms', 'anomaly_score', 'attack_type'])
        for _, row in df.iterrows():
            attack_type = ATTACK_LABELS.get(int(row['anomaly_score']), 'Normal')
            writer.writerow([
                row['timestamp'],
                row['datetime'],
                row['protocol'],
                row['payload_size'],
                row['processing_time_ms'],
                int(row['anomaly_score']),
                attack_type
            ])

    print(f"\nThreat report generated successfully.")
    print(f"  -> {REPORT_TXT}")
    print(f"  -> {REPORT_CSV}")

    print("\n" + "="*30 + " REPORT SUMMARY " + "="*30)
    with open(REPORT_TXT, 'r', encoding='utf-8', errors='replace') as f:
        print(f.read())

if __name__ == "__main__":
    generate_report()
