#!/bin/bash
# =============================================================
# start.sh — Lance tous les composants du système de monitoring
# =============================================================
# Usage : sudo bash start.sh

set -e
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "${BLUE}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   5G Slice Security Monitor — Startup   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Vérifications ────────────────────────────────────
log "Checking prerequisites..."
command -v redis-server >/dev/null || err "Redis not found. Install: sudo apt install redis-server"
command -v python3      >/dev/null || err "Python3 not found."
[ -f "$BASE_DIR/requirements.txt" ] || err "requirements.txt not found."

# ── 2. Redis ────────────────────────────────────────────
log "Starting Redis..."
if ! redis-cli ping &>/dev/null; then
    sudo systemctl start redis-server 2>/dev/null || \
    redis-server --daemonize yes --logfile "$LOG_DIR/redis.log"
    sleep 1
fi
redis-cli ping | grep -q PONG && log "Redis OK" || err "Redis failed to start"

# ── 3. Python venv ──────────────────────────────────────
if [ ! -d "$BASE_DIR/venv" ]; then
    log "Creating Python venv..."
    python3 -m venv "$BASE_DIR/venv"
fi
source "$BASE_DIR/venv/bin/activate"

log "Installing Python dependencies..."
pip install -q -r "$BASE_DIR/requirements.txt"

# ── 4. Collector ────────────────────────────────────────
log "Starting Data Collector..."
sudo "$BASE_DIR/venv/bin/python3" "$BASE_DIR/collector/collector.py" \
    > "$LOG_DIR/collector.log" 2>&1 &
echo $! > "$LOG_DIR/collector.pid"
log "Collector PID: $(cat $LOG_DIR/collector.pid)"

# ── 5. AI Detector ──────────────────────────────────────
log "Starting AI Detection Engine..."
"$BASE_DIR/venv/bin/python3" "$BASE_DIR/ai/detector.py" \
    > "$LOG_DIR/detector.log" 2>&1 &
echo $! > "$LOG_DIR/detector.pid"
log "Detector PID: $(cat $LOG_DIR/detector.pid)"

# ── 6. API / Dashboard ──────────────────────────────────
log "Starting Dashboard API (port 8080)..."
cd "$BASE_DIR/dashboard"
"$BASE_DIR/venv/bin/python3" api.py \
    > "$LOG_DIR/api.log" 2>&1 &
echo $! > "$LOG_DIR/api.pid"
log "API PID: $(cat $LOG_DIR/api.pid)"

sleep 2

# ── 7. Status ───────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  System Started Successfully!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  📊 Dashboard   : ${BLUE}http://localhost:8080${NC}"
echo -e "  📡 API Docs    : ${BLUE}http://localhost:8080/docs${NC}"
echo -e "  📋 Logs        : ${YELLOW}$LOG_DIR/${NC}"
echo ""
echo -e "  Processes:"
echo -e "  Collector → PID $(cat $LOG_DIR/collector.pid)"
echo -e "  Detector  → PID $(cat $LOG_DIR/detector.pid)"
echo -e "  API       → PID $(cat $LOG_DIR/api.pid)"
echo ""
echo -e "  Stop with: ${RED}sudo bash stop.sh${NC}"
