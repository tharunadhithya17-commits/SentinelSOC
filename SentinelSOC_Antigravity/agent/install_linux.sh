#!/bin/bash
# SentinelSOC Agent — Linux/macOS Installer

set -e

echo "============================================================"
echo "  SentinelSOC Security Agent — Linux/macOS Installer"
echo "============================================================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install it first: sudo apt install python3 python3-pip"
    exit 1
fi

echo "[OK] Python3 found: $(python3 --version)"

# Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install psutil requests --quiet
echo "[OK] Dependencies installed."

# Ask for server
echo ""
read -p "Enter SOC Server URL [http://localhost:4000]: " SOC_URL
SOC_URL=${SOC_URL:-http://localhost:4000}

echo ""
echo "[*] Starting SentinelSOC Agent..."
echo "    Server: $SOC_URL"
echo "    Press Ctrl+C to stop."
echo ""

export SOC_SERVER="$SOC_URL"
python3 "$(dirname "$0")/sentinel_agent.py"
