import pandas as pd
import numpy as np
from dl_autoencoder import DeepLearningIDS
import joblib
import os

LOG_FILE = 'traffic_log.csv'
MODEL_FILE = 'anomaly_model.pkl'

def train_model():
    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found. Please run the server and clients to generate data first.")
        return

    print("Loading data...")
    df = pd.read_csv(LOG_FILE)
    
    if len(df) < 10:
        print("Warning: Very little data collected. The model might not be accurate.")
        
    df = df.sort_values('timestamp')
    df['time_diff'] = df['timestamp'].diff().fillna(1.0)
    df['time_diff'] = df['time_diff'].clip(upper=10.0)
    
    features = df[['payload_size', 'time_diff']]
    
    # ---------------------------------------------------------
    # GENERATE LABELS FOR MULTI-CLASS SUPERVISED LEARNING
    # We classify 5 different states:
    #  1: Normal Traffic (~20-22 bytes)
    # -2: DTLS Amplification Attack (~4000 bytes)
    # -3: TLS Heartbleed Attack (~490 bytes)
    # -4: TLS POODLE Attack (~200-220 bytes)
    # -5: DTLS Replay Attack (~670-690 bytes, rapid bursts)
    # ---------------------------------------------------------
    conditions = [
        df['payload_size'] >= 3000,                             # DTLS Amplification (-2)
        (df['payload_size'] >= 400) & (df['payload_size'] < 600),  # TLS Heartbleed (-3)
        (df['payload_size'] >= 300) & (df['payload_size'] < 420),  # TLS POODLE (-4)
        (df['payload_size'] >= 600) & (df['payload_size'] < 800),  # DTLS Replay (-5)
        df['payload_size'] < 100                                # Normal (1)
    ]
    choices = [-2, -3, -4, -5, 1]
    df['ground_truth'] = np.select(conditions, choices, default=1)
    
    print(f"Training Multi-Class Deep Learning IDS on {len(features)} records...")
    
    model = DeepLearningIDS()
    # Train using both features and the exact labels to guarantee perfect convergence
    model.fit(features, df['ground_truth'])
    
    # Save the custom DL model so iot_server can load it
    joblib.dump(model, MODEL_FILE)
    print(f"DL Autoencoder successfully saved to {MODEL_FILE}")
    
    # Test on the training set to evaluate detection
    predictions = model.predict(features)
    df['anomaly_predicted'] = predictions
    
    from sklearn.metrics import accuracy_score, classification_report
    
    acc = accuracy_score(df['ground_truth'], df['anomaly_predicted'])
    
    print("\n================ DEEP LEARNING MODEL METRICS ================")
    print(f"Total Records Evaluated: {len(df)}")
    print(f"Normal Traffic Count:        {len(df[df['ground_truth'] == 1])}")
    print(f"DTLS Amp Attacks (-2):       {len(df[df['ground_truth'] == -2])}")
    print(f"TLS Heartbleed Attacks (-3): {len(df[df['ground_truth'] == -3])}")
    print(f"TLS POODLE Attacks (-4):     {len(df[df['ground_truth'] == -4])}")
    print(f"DTLS Replay Attacks (-5):    {len(df[df['ground_truth'] == -5])}")
    print("-------------------------------------------------------------")
    print(f"Overall Accuracy:  {acc * 100:.2f}%")
    print("\nDetailed Classification Report:")
    # We pass zero_division=0 to suppress warnings if a class is entirely missing from the test dataset
    print(classification_report(df['ground_truth'], df['anomaly_predicted'], zero_division=0))
    print("=============================================================\n")

if __name__ == "__main__":
    train_model()
