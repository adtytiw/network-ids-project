from fastapi import FastAPI, HTTPException
import torch
import torch.nn as nn
import joblib
import numpy as np
from pydantic import BaseModel

app = FastAPI(title="Guardian AI - Network IDS")


class TrafficLSTM(nn.Module):
    """LSTM classifier for network traffic. Architecture must match training config."""
    def __init__(self, input_size):
        super(TrafficLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, 64, num_layers=2, batch_first=True)
        self.fc = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        _, (hn, _) = self.lstm(x)
        out = self.fc(hn[-1])
        return self.sigmoid(out)

# globals
device = torch.device('cpu')
model = None
scaler = None


@app.on_event("startup")
def load_assets():
    """Load model weights and scaler on server start."""
    global model, scaler
    print("Loading model...")
    try:
        scaler = joblib.load("models/scaler.joblib")
        
        # Auto-detect input size from the scaler
        input_dim = scaler.n_features_in_
        
        model = TrafficLSTM(input_size=input_dim)
        model.load_state_dict(torch.load("models/lstm_model.pth", map_location=device))
        model.eval()
        print(f"✅ System Ready. Input features detected: {input_dim}")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")

class PacketData(BaseModel):
    features: list[float]

@app.post("/predict")
async def predict_traffic(data: PacketData):
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Scale and Reshape for LSTM [batch, seq_len, features]
        feat_array = np.array(data.features).reshape(1, -1)
        scaled_feat = scaler.transform(feat_array)
        input_tensor = torch.FloatTensor(scaled_feat).unsqueeze(1)
        
        with torch.no_grad():
            output = model(input_tensor)
            probability = output.item()
            prediction = 1 if probability > 0.5 else 0
            
        return {
            "status": "ATTACK" if prediction == 1 else "NORMAL",
            "confidence": round(float(probability if prediction == 1 else 1-probability), 4),
            "threat_level": "HIGH" if probability > 0.8 else "MEDIUM" if probability > 0.5 else "LOW"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/health")
def health():
    return {"status": "AI System Online", "device": str(device)}