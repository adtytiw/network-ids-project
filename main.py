from fastapi import FastAPI, HTTPException
import numpy as np
from pydantic import BaseModel
import sys
from pathlib import Path

# ensure src is importable
sys.path.insert(0, str(Path(__file__).parent))
from src.ml.knn_model import TrafficClassifierKNN

app = FastAPI(title="Guardian AI - Network IDS (KNN)")

# globals
knn_model = None


@app.on_event("startup")
def load_assets():
    """Load KNN model on server start."""
    global knn_model
    
    print("Loading KNN model...")
    try:
        knn_model = TrafficClassifierKNN.load("models/knn_model.joblib")
        print("✅ KNN Ready.")
    except Exception as e:
        print(f"❌ Failed to load KNN model: {e}")


class PacketData(BaseModel):
    features: list[float]


@app.post("/predict")
async def predict_traffic(data: PacketData):
    """Predict using KNN model."""
    if knn_model is None:
        raise HTTPException(status_code=503, detail="KNN model not loaded")
    
    try:
        result = knn_model.predict(data.features)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/explain")
async def explain_prediction(data: PacketData):
    """
    Get explainability info for a prediction.
    Shows the k nearest neighbors that influenced the decision.
    This is a key advantage of KNN over black-box models.
    """
    if knn_model is None:
        raise HTTPException(status_code=503, detail="KNN model not loaded")
    
    try:
        prediction = knn_model.predict(data.features)
        neighbors = knn_model.get_neighbors_info(data.features)
        
        return {
            **prediction,
            "explanation": {
                "attack_neighbors": neighbors["attack_neighbors"],
                "normal_neighbors": neighbors["normal_neighbors"],
                "avg_distance": round(neighbors["avg_distance"], 4),
                "reasoning": f"Based on {neighbors['attack_neighbors']}/5 similar attack patterns"
                    if prediction["status"] == "ATTACK" 
                    else f"Matches {neighbors['normal_neighbors']}/5 normal traffic patterns"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
def health():
    return {
        "status": "AI System Online",
        "model": "KNN (k=5)",
        "loaded": knn_model is not None
    }