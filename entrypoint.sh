#!/bin/sh
set -e

echo "=== Detress: starting backend API ==="
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait backend start
sleep 3

echo "=== Detress: starting capture agent ==="
python capture/main.py &

CAPTURE_PID=$!

echo "=== Detress: services started ==="
echo "Dashboard  : http://localhost:8000/"

# Wait both processes
wait $BACKEND_PID
wait $CAPTURE_PID
