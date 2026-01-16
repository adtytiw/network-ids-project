import torch
import torch.nn as nn
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

# 1. Define the exact same Model Class used during training
class TrafficLSTM(nn.Module):
    def __init__(self, input_size):
        super(TrafficLSTM, self).__init__()
        # Changed num_layers to 2 to match your saved state_dict
        self.lstm = nn.LSTM(input_size, 64, num_layers=2, batch_first=True)
        self.fc = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # We only care about the last hidden state of the last layer
        _, (hn, _) = self.lstm(x)
        out = self.fc(hn[-1])
        return self.sigmoid(out)

def evaluate():
    print("⏳ Loading Model and Scaler on Arch CPU...")
    device = torch.device('cpu') # Explicitly force CPU
    
    # Load the scaler used for normalization
    scaler = joblib.load("models/scaler.joblib")
    
    # Load data for evaluation
    df = pd.read_csv("data/processed/cleaned_traffic.csv")
    X = df.drop('Label', axis=1).values
    y = df['Label'].values
    
    # Scale and prepare tensors
    X_scaled = scaler.transform(X)
    X_tensor = torch.FloatTensor(X_scaled).unsqueeze(1)
    
    # Initialize model architecture and load saved weights
    input_dim = X.shape[1]
    model = TrafficLSTM(input_dim)
    model.load_state_dict(torch.load("models/lstm_model.pth", map_location=device))
    model.eval()

    print("📊 Running Inference on Intel i5...")
    with torch.no_grad():
        outputs = model(X_tensor)
        predictions = (outputs > 0.5).float().numpy()

    # Print Final Metrics
    print("\n✅ EVALUATION COMPLETE")
    print("=" * 40)
    print(classification_report(y, predictions, target_names=['Normal', 'Attack']))
    print("=" * 40)
    
    cm = confusion_matrix(y, predictions)
    print(f"Confusion Matrix:\n{cm}")

if __name__ == "__main__":
    evaluate()