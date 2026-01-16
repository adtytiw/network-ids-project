"""
Training script for KNN classifier.
Run: python src/ml/train_knn.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import sys

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


def load_data(csv_path: str = "data/processed/cleaned_traffic.csv", max_samples: int = 250_000):
    """
    Load processed dataset with optional subsetting.
    KNN doesn't scale well to millions of samples, so we take a stratified subset.
    """
    df = pd.read_csv(csv_path)
    
    # clean data
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # subsample if dataset is too large (stratified to keep class balance)
    if len(df) > max_samples:
        from sklearn.model_selection import train_test_split
        df, _ = train_test_split(
            df, train_size=max_samples, random_state=42, stratify=df['Label']
        )
        print(f"      Subsampled to {max_samples:,} for KNN efficiency")
    
    X = df[FEATURES].values
    y = df['Label'].values  # already 0/1 from preprocessing
    
    return X, y


def main():
    print("=" * 50)
    print("KNN Traffic Classifier Training")
    print("=" * 50)
    
    # load data
    print("\n[1/4] Loading data...")
    try:
        X, y = load_data()
    except FileNotFoundError:
        print("Error: data/processed/cleaned_traffic.csv not found")
        print("Run preprocessing first: python src/ml/preprocess.py")
        return
    
    print(f"      Dataset size: {len(X):,} samples")
    print(f"      Attack ratio: {y.mean():.1%}")
    
    # split
    print("\n[2/4] Splitting data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train):,} | Test: {len(X_test):,}")
    
    # train
    print("\n[3/4] Training KNN (k=5)...")
    model = TrafficClassifierKNN(n_neighbors=5)
    model.train(X_train, y_train)
    print("      Done.")
    
    # evaluate using batch prediction (much faster than per-sample)
    print("\n[4/4] Evaluating (batch mode)...")
    y_pred = model.predict_batch(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n      Accuracy: {accuracy:.2%}")
    print("\n      Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "ATTACK"]))
    
    # save
    model.save("models/knn_model.joblib")
    
    print("=" * 50)
    print("Training complete. Model ready for inference.")
    print("=" * 50)


if __name__ == "__main__":
    main()
