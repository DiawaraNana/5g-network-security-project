#!/bin/bash
# reset_5g_monitor.sh - Nettoyage complet & redémarrage 5G Core + Monitor
# ⚠️ À exécuter avec : sudo bash reset_5g_monitor.sh

set +e  # Continue même si une commande échoue (services inactifs, redis vide, etc.)

echo "================================================="
echo "  🧹 5G SLICE MONITOR & OPEN5GS - RESET COMPLET"
echo "================================================="

# 1. Tuer les processus Python du monitor (même zombies)
echo "[1/6] 🛑 Killing monitor processes..."
pkill -9 -f "collector.py" 2>/dev/null || true
pkill -9 -f "detector.py"  2>/dev/null || true
pkill -9 -f "dashboard.py" 2>/dev/null || true
sleep 2

# 2. Arrêter Open5GS proprement
echo "[2/6] 🛑 Stopping Open5GS services..."
systemctl stop open5gs-amfd open5gs-smfd open5gs-upfd \
              open5gs-ausfd open5gs-udmd open5gs-udrd \
              open5gs-pcrfd open5gs-bsfd open5gs-nrfd \
              open5gs-mmed open5gs-sgwud open5gs-pgwd open5gs-hssd 2>/dev/null || true
sleep 3

# 3. Nettoyage ciblé Redis (ne touche pas aux autres bases si Redis est partagé)
echo "[3/6] 🗑️ Purging Redis monitor data..."
redis-cli DEL events:alerts events:logs pfcp:stats ngap:stats gtp:stats \
  sessions:eMBB sessions:IoT sessions:total sessions:json \
  ai:latest ai:history current:traffic metrics:traffic 2>/dev/null || \
  echo "⚠️ Redis non dispo ou déjà vide. On continue..."

# 4. Redémarrer Open5GS
echo "[4/6] 🚀 Restarting Open5GS services..."
systemctl start open5gs-amfd open5gs-smfd open5gs-upfd \
              open5gs-ausfd open5gs-udmd open5gs-udrd \
              open5gs-pcrfd open5gs-bsfd open5gs-nrfd \
              open5gs-mmed open5gs-sgwud open5gs-pgwd open5gs-hssd 2>/dev/null || true

echo "⏳ Attente 8s pour l'initialisation du core..."
sleep 8

# 5. Vérification état des services critiques
echo "[5/6] 📊 Status Check:"
for svc in amf smf upf; do
  status=$(systemctl is-active "open5gs-${svc}d" 2>/dev/null || echo "unknown")
  echo "   open5gs-${svc}d: $status"
done

# 6. Lancement du collector en background
echo "[6/6] 🐍 Starting Collector in background..."
PROJECT_DIR="$HOME/5g-slice-monitor"
cd "$PROJECT_DIR" || { echo "❌ Dossier $PROJECT_DIR introuvable ! Modifie la variable PROJECT_DIR."; exit 1; }

# Vérifie que le venv existe
#if [[ ! -f "venv/bin/python3" ]]; then
 # echo "❌ venv/bin/python3 introuvable. Vérifie ton environnement."
  #exit 1
#fi

#nohup venv/bin/python3 collector/collector.py > /tmp/collector.log 2>&1 &
#COLLECTOR_PID=$!
#sleep 2

echo "================================================="
echo "✅ RESET TERMINÉ AVEC SUCCÈS"
echo "📌 Collector PID: $COLLECTOR_PID"
echo "📜 Logs collector : tail -f /tmp/collector.log"
echo "🔍 Vérif Redis    : redis-cli LLEN events:alerts"
echo "================================================="
echo "💡 Tu peux maintenant lancer le détecteur :"
echo "   venv/bin/python3 ai/detector.py"
echo "================================================="
