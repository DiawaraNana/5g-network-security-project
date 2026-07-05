#!/bin/bash
# stop.sh — Arrête tous les composants
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$BASE_DIR/logs"

echo "[*] Stopping 5G Slice Security Monitor..."

for comp in collector detector api; do
    PID_FILE="$LOG_DIR/$comp.pid"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        kill "$PID" 2>/dev/null && echo "[-] $comp (PID $PID) stopped"
        rm -f "$PID_FILE"
    fi
done

echo "[+] All components stopped."
