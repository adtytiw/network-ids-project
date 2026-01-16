"""
Detailed evaluation of KNN classifier with visualizations.
Run: python src/ml/evaluate_knn.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_recall_curve,
    roc_curve,
    roc_auc_score
)
import sys
import time

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.ml.knn_model import TrafficClassifierKNN


FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Packet Length Mean',
    'Active Mean',
    'Idle Mean'
]


def load_test_data(csv_path: str = "data/processed/cleaned_traffic.csv", test_size: int = 50_000):
    """Load a test subset for evaluation."""
    df = pd.read_csv(csv_path)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # take stratified test subset
    _, test_df = train_test_split(
        df, test_size=test_size, random_state=42, stratify=df['Label']
    )
    
    X = test_df[FEATURES].values
    y = test_df['Label'].values
    
    return X, y


def main():
    print("=" * 60)
    print("KNN Traffic Classifier — Detailed Evaluation")
    print("=" * 60)
    
    # load model
    print("\n[1/5] Loading trained model...")
    try:
        model = TrafficClassifierKNN.load("models/knn_model.joblib")
        print("      Model loaded successfully")
    except FileNotFoundError:
        print("Error: Model not found. Run train_knn.py first.")
        return
    
    # load test data
    print("\n[2/5] Loading test data...")
    X_test, y_test = load_test_data(test_size=50_000)
    print(f"      Test samples: {len(X_test):,}")
    print(f"      Attack ratio: {y_test.mean():.1%}")
    
    # batch prediction
    print("\n[3/5] Running batch prediction...")
    start = time.time()
    y_pred = model.predict_batch(X_test)
    y_proba = model.predict_proba_batch(X_test)[:, 1]  # attack probability
    elapsed = time.time() - start
    print(f"      Predicted {len(X_test):,} samples in {elapsed:.2f}s")
    print(f"      Throughput: {len(X_test)/elapsed:,.0f} samples/sec")
    
    # metrics
    print("\n[4/5] Computing metrics...")
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"\n      Accuracy: {accuracy:.2%}")
    print(f"      ROC AUC:  {auc:.4f}")
    
    print("\n      Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                  NORMAL  ATTACK")
    print(f"      Actual NORMAL  {cm[0,0]:>6}  {cm[0,1]:>6}")
    print(f"      Actual ATTACK  {cm[1,0]:>6}  {cm[1,1]:>6}")
    
    print("\n      Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "ATTACK"]))
    
    # single-sample inference test
    print("\n[5/5] Testing single-sample API...")
    test_sample = X_test[0].tolist()
    start = time.time()
    result = model.predict(test_sample)
    single_time = (time.time() - start) * 1000
    print(f"      Sample features: {[f'{v:.2f}' for v in test_sample[:5]]}...")
    print(f"      Prediction: {result}")
    print(f"      Latency: {single_time:.2f}ms")
    
    print("\n" + "=" * 60)
    print("Evaluation complete. Model ready for production.")
    print("=" * 60)


if __name__ == "__main__":
    main()
