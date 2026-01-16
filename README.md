# Guardian AI

A real-time Network Intrusion Detection System (NIDS) powered by an LSTM neural network. Monitors live network traffic, classifies packets, and visualizes threat data through a web dashboard.

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Packet Sniffer │────▶│   FastAPI       │────▶│   Streamlit     │
│  (Scapy)        │      │   Inference API │      │   Dashboard     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
     live_sniffer.py         main.py                  dashboard.py
```

- **Inference API** (`main.py`): FastAPI server hosting the trained PyTorch LSTM model
- **Packet Sniffer** (`src/web/live_sniffer.py`): Captures packets via Scapy, extracts flow features, queries the API
- **Dashboard** (`src/web/dashboard.py`): Streamlit frontend for real-time visualization

## Quick Start

### Prerequisites
- Python 3.12+
- Linux (for raw packet capture)
- Root/sudo access (sniffer requires it)

### Installation
```bash
# Clone and setup
git clone <repo-url>
cd network-ids-project

# Install dependencies 
uv sync
```

### Running
```bash
./run.sh
```
This starts all three components. Dashboard available at `http://localhost:8501`.

### Attack Simulation
To test detection capabilities:
```bash
sudo .venv/bin/python simulate_attack.py
```

## Project Structure

```
├── main.py                 # FastAPI inference server
├── run.sh                  # Orchestration script
├── simulate_attack.py      # Traffic generator for testing
├── models/
│   ├── lstm_model.pth      # Trained model weights
│   └── scaler.joblib       # Feature scaler
├── src/
│   ├── ml/
│   │   ├── preprocess.py   # Dataset preprocessing
│   │   ├── train_lstm.py   # Model training script
│   │   └── evaluate_lstm.py
│   └── web/
│       ├── dashboard.py    # Streamlit UI
│       └── live_sniffer.py # Packet capture
└── data/
    ├── raw/                # CICIDS2017 CSV files
    └── processed/          # Cleaned training data
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| ML Framework | PyTorch (LSTM) |
| API | FastAPI + Uvicorn |
| Frontend | Streamlit + Plotly |
| Packet Capture | Scapy |
| Dataset | CICIDS2017 |

## Deployment Notes

For containerization:
- The sniffer requires `NET_ADMIN` and `NET_RAW` capabilities
- Consider `--network=host` for Docker to access the host NIC
- API and Dashboard can run as standard containers

## License

MIT
