"""
K-Nearest Neighbors classifier for network traffic.
Alternative to LSTM — faster inference, runs on CPU, more interpretable.
"""

import joblib
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from pathlib import Path


class TrafficClassifierKNN:
    def __init__(self, n_neighbors: int = 5):
        self.model = KNeighborsClassifier(
            n_neighbors=n_neighbors,
            weights='distance',
            algorithm='ball_tree',
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, X: np.ndarray, y: np.ndarray):
        """Train on feature matrix X and binary labels y."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True
    
    def predict(self, features: list) -> dict:
        """
        Predict single sample.
        Returns dict matching the LSTM API format for frontend compatibility.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # get prediction and probability
        prediction = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]
        
        # probability of attack (class 1)
        attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        
        # match LSTM API response format exactly
        status = "ATTACK" if prediction == 1 else "NORMAL"
        confidence = attack_prob if prediction == 1 else (1 - attack_prob)
        
        if attack_prob > 0.8:
            threat_level = "HIGH"
        elif attack_prob > 0.5:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        return {
            "status": status,
            "confidence": round(confidence, 4),
            "threat_level": threat_level
        }
    
    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Batch prediction for evaluation — much faster than per-sample.
        Returns raw predictions (0/1 array).
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def predict_proba_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Batch probability prediction.
        Returns probability array for both classes.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def get_neighbors_info(self, features: list) -> dict:
        """
        Get explainability info: the k nearest neighbors and their distances.
        This is what makes KNN interpretable — we can show WHY a decision was made.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        distances, indices = self.model.kneighbors(X_scaled)
        
        # Get the labels of neighbors
        neighbor_labels = self.model._y[indices[0]]
        
        return {
            "distances": distances[0].tolist(),
            "neighbor_labels": neighbor_labels.tolist(),
            "attack_neighbors": int(sum(neighbor_labels)),
            "normal_neighbors": int(len(neighbor_labels) - sum(neighbor_labels)),
            "avg_distance": float(np.mean(distances[0]))
        }
    
    def save(self, path: str = "models/knn_model.joblib"):
        """Save model and scaler together."""
        Path(path).parent.mkdir(exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, path)
        print(f"Model saved to {path}")
    
    @classmethod
    def load(cls, path: str = "models/knn_model.joblib") -> "TrafficClassifierKNN":
        """Load pre-trained model."""
        data = joblib.load(path)
        instance = cls()
        instance.model = data['model']
        instance.scaler = data['scaler']
        instance.is_trained = data.get('is_trained', True)
        return instance
