#!/bin/bash

# Define paths to virtual environment executables
# Assumes we are running from the project root
VENV_DIR="$(pwd)/.venv"
PYTHON="$VENV_DIR/bin/python"
UVICORN="$VENV_DIR/bin/uvicorn"
STREAMLIT="$VENV_DIR/bin/streamlit"

# Check if venv exists
if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Virtual environment not found at $VENV_DIR"
    echo "Please run 'uv sync' or install dependencies first."
    exit 1
fi

# Check if KNN model exists, train if not
if [ ! -f "models/knn_model.joblib" ]; then
    echo "⚠️ KNN model not found. Training..."
    "$PYTHON" src/ml/train_knn.py
fi

# Kill previous instances
pkill -f "uvicorn main:app"
pkill -f "streamlit run"
sudo pkill -f "src/web/live_sniffer.py"

echo "Starting Guardian AI (KNN Edition)..."

# API server
echo "[1/3] Starting inference API..."
"$UVICORN" main:app --host 0.0.0.0 --port 8000 &
API_PID=$!
sleep 3 # Wait for model to load

# Dashboard
echo "[2/3] Starting dashboard..."
"$STREAMLIT" run src/web/dashboard.py &
DASH_PID=$!

# Packet sniffer (foreground, needs root)
echo "[3/3] Starting packet sniffer (requires sudo)..."
echo "Press Ctrl+C to stop all services."
# Crucial: Use the VENV python with sudo to access scapy
sudo "$PYTHON" src/web/live_sniffer.py

# cleanup on exit
echo "Shutting down..."
kill $API_PID 2>/dev/null
kill $DASH_PID 2>/dev/null
