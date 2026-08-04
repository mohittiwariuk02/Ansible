#!/usr/bin/env bash

# SSH Key Manager Startup Script
echo "================================================="
echo "   Starting Centralized SSH Key Manager Web UI"
echo "================================================="

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Ensure venv exists
if [ -d "$SCRIPT_DIR/venv" ]; then
    echo "[*] Using Python virtual environment at ./venv ..."
    PYTHON_BIN="$SCRIPT_DIR/venv/bin/python"
else
    PYTHON_BIN="python3"
fi

export ANSIBLE_LOCAL_TEMP="$SCRIPT_DIR/.ansible_tmp/local"
export ANSIBLE_REMOTE_TEMP="~/.ansible/tmp"
# Use Port 5050 to avoid macOS AirPlay Receiver port 5000 conflict
export PORT=${PORT:-5050}

echo "[*] Launching Web Service on http://0.0.0.0:${PORT} ..."
"$PYTHON_BIN" backend/app.py
