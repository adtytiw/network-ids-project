# Guardian AI

A real-time Network Intrusion Detection System (NIDS) powered by a K-Nearest Neighbors (KNN) classifier. Monitors live network traffic, classifies packets, and visualizes threat data through a consumer-friendly web dashboard.

## Features

- **Real-time packet analysis** — Captures and classifies network traffic in milliseconds
- **98.8% accuracy** — KNN model trained on 250,000+ labeled traffic samples
- **Consumer-friendly dashboard** — Easy-to-understand health scores, attack breakdowns, and threat sources
- **Demo mode** — Simulate attacks to see the system in action
- **Export logs** — Download CSV reports for further analysis

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Packet Sniffer │────▶│   FastAPI       │────▶│   Streamlit     │
│  (Scapy)        │      │   Inference API │      │   Dashboard     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
     live_sniffer.py         main.py                  dashboard.py
```

- **Inference API** (`main.py`): FastAPI server hosting the trained KNN classifier
- **Packet Sniffer** (`src/web/live_sniffer.py`): Captures packets via Scapy, extracts flow features, queries the API
- **Dashboard** (`src/web/dashboard.py`): Streamlit frontend with real-time visualization and health monitoring

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

## Dashboard Features

| Feature | Description |
|---------|-------------|
| **Health Score** | 0-100 score based on threat rate, attack velocity, and recent incidents |
| **Attack Type Breakdown** | Identifies SSH brute force, RDP attacks, HTTP scans, etc. |
| **Top Threat Sources** | Leaderboard of malicious IPs with severity badges |
| **Simulate Attack** | Demo mode to test detection without real attacks |
| **Export Logs** | Download packet analysis as CSV |

## Project Structure

```
├── main.py                 # FastAPI inference server
├── run.sh                  # Orchestration script
├── models/
│   └── knn_model.joblib    # Trained KNN classifier
├── src/
│   ├── ml/
│   │   ├── knn_model.py    # KNN classifier class
│   │   ├── train_knn.py    # Model training script
│   │   ├── evaluate_knn.py # Model evaluation
│   │   └── preprocess.py   # Dataset preprocessing
│   └── web/
│       ├── dashboard.py    # Streamlit UI
│       └── live_sniffer.py # Packet capture
└── data/
    ├── raw/                # CICIDS2017 CSV files
    └── processed/          # Cleaned training data
```

## Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 98.81% |
| AUC-ROC | 0.9955 |
| Precision | 98.8% |
| Recall | 98.8% |
| Response Time | ~25ms |

## Tech Stack

| Component | Technology |
|-----------|------------|
| ML Model | scikit-learn KNN (k=5, distance-weighted) |
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
