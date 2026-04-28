import pandas as pd
import time
LOG_FILE = 'traffic_log.csv'
df = pd.read_csv(LOG_FILE)
df['anomaly_score'] = pd.to_numeric(df['anomaly_score'], errors='coerce')
df['processing_time_ms'] = pd.to_numeric(df['processing_time_ms'], errors='coerce').fillna(0)
mask = df['anomaly_score'].isna() & df['processing_time_ms'].isin([-1, -2, -3, -4, -5])
df.loc[mask, 'anomaly_score'] = df.loc[mask, 'processing_time_ms']
df['anomaly_score'] = df['anomaly_score'].fillna(1)
print(f"Unknown anomalies found: {len(df[df['anomaly_score'] == -1])}")
