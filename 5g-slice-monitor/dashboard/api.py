"""
api.py — VERSION CORRIGÉE & ASYNCHRONE
=======================================
- Lecture Redis robuste (fallback list/set/hash/json)
- WebSocket non-bloquant (asyncio.to_thread)
- Endpoint /api/debug/redis pour diagnostic immédiat
- Fallback casse (eMBB/embb)
"""

import json
import asyncio
import logging
import redis
import os
import numpy as np
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn
# ── Global: WebSocket connections pool ───────────────────
#connections: List[WebSocket] = []

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = FastAPI(title="5G Slice Security Monitor", version="2.1")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# ── Helpers Robustes ─────────────────────────────────────
def safe_redis_int(key: str, default: int = 0) -> int:
    """Lit un entier depuis Redis en gérant string, JSON, list, set ou hash."""
    val = r.get(key)
    if val is None:
        for check in [r.llen, r.scard, r.hlen]:
            try:
                count = check(key)
                if count > 0: return count
            except: pass
        return default
    try:
        return int(val)
    except ValueError:
        try:
            data = json.loads(val)
            if isinstance(data, (list, dict)):
                return len(data) if isinstance(data, list) else data.get("count", default)
        except: pass
        return default


def rlist(key, n=50):
    items = r.lrange(key, 0, n - 1)
    out = []
    for item in items:
        try: out.append(json.loads(item))
        except Exception: pass
    return out

def rjson(key):
    val = r.get(key)
    if val:
        try: return json.loads(val)
        except Exception: pass
    return None

# ── Endpoints ────────────────────────────────────────────
@app.get("/api/status")
def get_status():
    hb = r.get("collector:heartbeat")
    ai = rjson("ai:latest")
    return {
        "system": "5G Slice Security Monitor v2",
        "timestamp": datetime.utcnow().isoformat(),
        "collector": {"alive": hb is not None, "last_beat": hb},
        "ai": {"alive": ai is not None, "ensemble": ai.get("ensemble") if ai else "No data"},
    }

@app.get("/api/slices")
def get_slices():
    embb_sessions = safe_redis_int("sessions:eMBB") or safe_redis_int("sessions:embb")
    iot_sessions  = safe_redis_int("sessions:IoT")  or safe_redis_int("sessions:iot")

    traffic = r.hgetall("current:traffic")
    embb_t  = json.loads(traffic.get("eMBB", "{}"))
    pfcp, gtp = r.hgetall("pfcp:stats"), r.hgetall("gtp:stats")

    return {
        "eMBB": {
            "subnet":"10.45.0.0/16", "sst":1, "interface":"ogstun",
            "ue_sessions":embb_sessions, "bps_in":embb_t.get("bps_in",0), "bps_out":embb_t.get("bps_out",0),
            "pps_in":embb_t.get("pps_in",0), "pps_out":embb_t.get("pps_out",0),
            "status":"active" if embb_sessions > 0 else "idle",
            "gtp_pkts": int(gtp.get("embb", 0))
        },
        "IoT": {
            "subnet":"10.46.0.0/16", "sst":2, "sd":"000002", "interface":"ogstun",
            "ue_sessions":iot_sessions, "bps_in":0, "bps_out":0, "pps_in":0, "pps_out":0,
            "status":"active" if iot_sessions > 0 else "idle",
            "gtp_pkts": int(gtp.get("iot", 0))
        },
        "interface": {
            "name":"ogstun", "subnets":["10.45.0.0/16", "10.46.0.0/16"],
            "bps_in":embb_t.get("bps_in",0), "bps_out":embb_t.get("bps_out",0)
        }
    }

@app.get("/api/sessions")
def get_sessions():
    embb = safe_redis_int("sessions:eMBB") or safe_redis_int("sessions:embb")
    iot  = safe_redis_int("sessions:IoT")  or safe_redis_int("sessions:iot")
    sessions_json = r.get("sessions:json") or r.get("sessions:data")
    sessions = {}
    if sessions_json:
        try: sessions = json.loads(sessions_json)
        except Exception: pass
    return {"total": embb + iot, "eMBB": embb, "IoT": iot, "sessions": sessions}

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    alerts = rlist("events:alerts", limit)
    return {
        "count": len(alerts), "alerts": alerts,
        "critical": len([a for a in alerts if a.get("severity") == "CRITICAL"]),
        "high":     len([a for a in alerts if a.get("severity") == "HIGH"]),
    }

@app.get("/api/ai")
def get_ai():
    latest = rjson("ai:latest")
    if not latest: return {"status": "no_data", "ensemble": "Normal", "anomaly_score": 0}
    return latest

@app.get("/api/ai/history")
def get_ai_history(limit: int = 120):
    history = rlist("ai:history", limit)
    simplified = [{
        "timestamp": h.get("timestamp"), "ensemble": h.get("ensemble"),
        "anomaly_score": h.get("anomaly_score", 0),
        "if_score": (h.get("models") or [{}])[0].get("score", 0),
        "ae_score": (h.get("models") or [{},{}])[1].get("score", 0) if len(h.get("models") or []) > 1 else 0
    } for h in history]
    return {"history": simplified}

@app.get("/api/pfcp/events")
def get_pfcp_events(limit: int = 50):
    events = rlist("events:pfcp", limit)
    stats  = r.hgetall("pfcp:stats")
    return {"count": int(stats.get("total",0)), "mod_req": int(stats.get("mod_req",0)),
            "injections": int(stats.get("injections",0)), "events": events}

@app.get("/api/gtp/events")
def get_gtp_events(limit: int = 50):
    events = rlist("events:gtp", limit)
    stats  = r.hgetall("gtp:stats")
    return {"total": int(stats.get("total",0)), "embb_pkts": int(stats.get("embb",0)),
            "iot_pkts": int(stats.get("iot",0)), "cross_slice": int(stats.get("cross",0)), "events": events[:limit]}

@app.get("/api/logs")
def get_logs(limit: int = 100):
    return {"logs": rlist("events:logs", limit)}

@app.get("/api/debug/redis")
def debug_redis():
    """Diagnostique les clés Redis en respectant leur type natif."""
    keys = [
        "sessions:eMBB", "sessions:embb", "sessions:IoT", "sessions:iot",
        "sessions:total", "sessions:json", "sessions:data",
        "current:traffic", "pfcp:stats", "gtp:stats", "ai:latest"
    ]
    result = {}
    
    for k in keys:
        try:
            key_type = r.type(k)  # Returns: "string", "hash", "list", "none", etc.
            
            if key_type == "none":
                result[k] = {"type": "none", "value": None, "safe_count": 0}
            elif key_type == "string":
                val = r.get(k)
                result[k] = {"type": "string", "value": val, "safe_count": safe_redis_int(k)}
            elif key_type == "hash":
                val = r.hgetall(k)
                result[k] = {"type": "hash", "value": val, "safe_count": len(val)}
            elif key_type == "list":
                val = r.lrange(k, 0, -1)
                result[k] = {"type": "list", "value": val, "safe_count": len(val)}
            elif key_type == "set":
                val = list(r.smembers(k))
                result[k] = {"type": "set", "value": val, "safe_count": len(val)}
            elif key_type == "zset":
                val = r.zrange(k, 0, -1, withscores=True)
                result[k] = {"type": "zset", "value": val, "safe_count": len(val)}
            else:
                result[k] = {"type": key_type, "value": f"<{key_type} not fully supported>", "safe_count": 0}
                
        except Exception as e:
            result[k] = {"type": "error", "value": str(e), "safe_count": 0}
    
    return result
# ── WebSocket (Async Safe) ───────────────────────────────
# ── WebSocket (Robuste + Sanitization JSON) ──────────────
connections: List[WebSocket] = []  # ✅ Déclaration sécurisée ici aussi

def sanitize(obj):
    """Convertit types numpy/sets/dates en natifs Python pour JSON."""
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize(i) for i in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    return obj

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connections.append(ws)
    logging.info(f"[WS] New connection ({len(connections)} active)")
    
    try:
        while True:
            try:
                # Récupération non-bloquante des données
                slices   = await asyncio.to_thread(get_slices)
                alerts   = await asyncio.to_thread(get_alerts, 10)
                ai       = await asyncio.to_thread(get_ai)
                pfcp     = await asyncio.to_thread(get_pfcp_events, 10)
                sessions = await asyncio.to_thread(get_sessions)

                payload = sanitize({
                    "type":      "update",
                    "timestamp": datetime.utcnow().isoformat(),
                    "slices":    slices,
                    "alerts":    alerts,
                    "ai":        ai,
                    "pfcp":      pfcp,
                    "sessions":  sessions,
                })

                await ws.send_json(payload)
                
            # ✅ Capture TOUS les types de déconnexion
            except (WebSocketDisconnect, 
                    Exception) as e:
                
                # Vérifie si c'est une vraie déconnexion client
                err_name = type(e).__name__
                if err_name in ("WebSocketDisconnect", "ClientDisconnected", "ConnectionClosed"):
                    logging.info(f"[WS] Client disconnected ({err_name})")
                    break  # Sort proprement de la boucle
                
                # Pour les autres erreurs, log et continue
                logging.warning(f"[WS] Send error: {err_name} - {e}")
                await asyncio.sleep(0.5)
            
            await asyncio.sleep(1)
            
    finally:
        # ✅ Nettoyage GARANTI même en cas de crash
        if ws in connections:
            connections.remove(ws)
            logging.info(f"[WS] Connection cleaned ({len(connections)} active)")

# ── Serveur ──────────────────────────────────────────────
DASH_DIR = os.path.dirname(__file__)

@app.get("/")
def root():
    idx = os.path.join(DASH_DIR, "index.html")
    if os.path.exists(idx): return FileResponse(idx)
    return {"message": "API OK", "docs": "/docs"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=False)
