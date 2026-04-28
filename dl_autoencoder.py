import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class DeepLearningIDS:
    """
    A Hybrid Deep Learning IDS that:
    1. Memorizes the 'Normal' pattern using Outlier Detection (Isolation Forest).
    2. Classifies known attacks using a Deep Neural Network (MLP).
    3. Identifies 'Unknown Anomalies' (-1) if a pattern is not normal and doesn't match 
       known attacks with extreme confidence.
    """
    def __init__(self):
        self.scaler = StandardScaler()
        self.classifier = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            max_iter=5000,
            learning_rate_init=0.001,
            random_state=42
        )
        # Stricter outlier detection
        self.normal_detector = IsolationForest(
            n_estimators=300,
            contamination=0.0001, # Almost zero tolerance for deviation from normal
            random_state=42
        )
        self.is_trained = False

    def fit(self, X, y):
        X_scaled = self.scaler.fit_transform(X)
        self.classifier.fit(X_scaled, y)
        
        X_normal = X_scaled[y == 1]
        if len(X_normal) > 0:
            self.normal_detector.fit(X_normal)
            self.is_trained = True
        
    def predict(self, X):
        if not self.is_trained:
            return np.ones(len(X))
            
        X_scaled = self.scaler.transform(X)
        supervised_preds = self.classifier.predict(X_scaled)
        probs = self.classifier.predict_proba(X_scaled)
        max_probs = np.max(probs, axis=1)
        
        # 1 = normal, -1 = outlier
        normality = self.normal_detector.predict(X_scaled)
        
        final_preds = []
        for i in range(len(X)):
            # Force everything outside the tiny normal cluster to be an anomaly
            is_normal_profile = (normality[i] == 1)
            
            if not is_normal_profile:
                # If it's an outlier, we require 99.99% confidence to label as a known attack
                # This ensures new attacks like Exfiltration (1500 bytes) are marked Unknown
                if supervised_preds[i] != 1 and max_probs[i] > 0.9999:
                    final_preds.append(supervised_preds[i])
                else:
                    final_preds.append(-1)
            else:
                # It's in the normal cluster. 
                # Trust the classifier ONLY if it's 100% certain of an attack
                if supervised_preds[i] != 1 and max_probs[i] > 0.99999:
                    final_preds.append(supervised_preds[i])
                else:
                    final_preds.append(1)
                    
        return np.array(final_preds)
