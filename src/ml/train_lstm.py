import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

class TrafficLSTM(nn.Module):
    """2-layer LSTM for binary traffic classification."""
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super(TrafficLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :]) # Take only the last time step
        return self.sigmoid(out)

def train_model():
    """Main training loop. Outputs model to models/lstm_model.pth"""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load data
    df = pd.read_csv("data/processed/cleaned_traffic.csv")
    X_raw = df.drop('Label', axis=1).values
    y_raw = df['Label'].values

    # normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    joblib.dump(scaler, "models/scaler.joblib")

    # sliding window for sequence input
    window = 5
    X_seq, y_seq = [], []
    for i in range(len(X_scaled) - window):
        X_seq.append(X_scaled[i:i+window])
        y_seq.append(y_raw[i+window])
    
    X_train = torch.FloatTensor(np.array(X_seq))
    y_train = torch.FloatTensor(np.array(y_seq)).view(-1, 1)

    # DataLoader
    loader = DataLoader(TensorDataset(X_train, y_train), batch_size=128, shuffle=True)

    # Initialize Model
    model = TrafficLSTM(input_size=X_raw.shape[1]).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    print("Starting training...")
    model.train()
    for epoch in range(10):
        total_loss = 0
        for batch_X, batch_y in loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        print(f"Epoch {epoch+1}/10 | Loss: {total_loss/len(loader):.4f}")

    torch.save(model.state_dict(), "models/lstm_model.pth")
    print("✅ Model saved to models/lstm_model.pth")

if __name__ == "__main__":
    train_model()