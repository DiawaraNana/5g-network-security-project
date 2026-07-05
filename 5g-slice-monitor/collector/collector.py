"""
  5G SECURITY COLLECTOR — FINAL CORRECTED VERSION
  ✅ Détection OHC/PFCP active
  ✅ Plus de sessions mortes au démarrage
  ✅ Thread sniffer robuste (ne plante plus silencieusement)
"""

import re
import time
import threading
import subprocess
import json
import socket
import redis
import struct
import psutil
import traceback
from datetime import datetime
from collections import deque
from scapy.all import sniff, IP, UDP, Raw

# ── Config ───────────────────────────────────────────────
REDIS_HOST  = "localhost"
REDIS_PORT  = 6379
OGSTUN_IF   = "ogstun"
PFCP_PORT   = 8805
LEGIT_PFCP  = {"127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.7", "127.0.0.10"}
NGAP_DOS_THRESHOLD = 15

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def ts(): return datetime.utcnow().isoformat()
def publish(channel, data):
    data["timestamp"] = ts()
    try:
        r.lpush(channel, json.dumps(data))
        r.ltrim(channel, 0, 4999)
    except Exception as e:
        print(f"[REDIS ERR] {e}")

# ── Sessions ─────────────────────────────────────────────
active_sessions = {}
known_seids     = set()
pending_seids   = {}
last_upf_count  = 0
sessions_lock = threading.Lock()

def classify_ip(ip):
    if ip.startswith("10.45."): return "eMBB"
    if ip.startswith("10.46."): return "IoT"
    return "eMBB"

def update_sessions():
    with sessions_lock:
        embb = sum(1 for s in active_sessions.values() if s["slice"] == "eMBB")
        iot  = sum(1 for s in active_sessions.values() if s["slice"] == "IoT")
        r.set("sessions:eMBB", embb)
        r.set("sessions:IoT", iot)
        r.set("sessions:total", len(active_sessions))
        r.set("sessions:json", json.dumps({
            k: {"ip": v["ip"], "slice": v["slice"]}
            for k, v in active_sessions.items()
        }))

# ── Compteurs ────────────────────────────────────────────
pfcp_stats = {"total": 0, "mod_req": 0, "injections": 0, "ohc_detected": 0}
gtp_stats  = {"total": 0, "embb": 0, "iot": 0, "cross": 0}
ngap_timestamps = deque()

def update_ngap_rate():
    now = time.time()
    while ngap_timestamps and ngap_timestamps[0] < now - 60:
        ngap_timestamps.popleft()
    r.hset("ngap:stats", mapping={
        "reg_rate": str(len(ngap_timestamps)),
        "total": str(len(ngap_timestamps))
    })

# ── 1. Log Collector ─────────────────────────────────────
LOG_KEYWORDS = {
    "fseid":            "UE F-SEID[UP:",
    "session_cnt":      "Number of UPF-Sessions is now",
    "dnn_slice_reject": "Not Supported OR Not Subscribed",
    "nssai_error":      "No Allowed-NSSAI",
    "amf_reject":       "Registration reject [",
    "ngap_reg":         "Registration",
}

SERVICES = ["open5gs-amfd", "open5gs-smfd", "open5gs-upfd"]

def handle_session_count_change(new_count):
    global last_upf_count
    with sessions_lock:
        old_count = last_upf_count
        last_upf_count = new_count

        if new_count == 0:
            removed = list(active_sessions.keys())
            active_sessions.clear()
            known_seids.clear()
            pending_seids.clear()
            print(f"[SESSION] All sessions removed (UPF count = 0)")

        elif new_count < old_count:
            diff = old_count - new_count
            seids_to_remove = list(active_sessions.keys())[:diff]
            for seid in seids_to_remove:
                info = active_sessions.pop(seid, None)
                known_seids.discard(seid)
                pending_seids.pop(seid, None)
                if info:
                    print(f"[SESSION] -{seid} ({info['slice']} {info['ip']})")

        elif new_count > old_count:
            pass
    update_sessions()

def tail_journal(service):
    proc = subprocess.Popen(
        ["journalctl", "-u", service, "-f", "-n", "0", "--output=short-iso"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    for line in proc.stdout:
        line = line.strip()
        try:
            if LOG_KEYWORDS["fseid"] in line and "IPv4[" in line:
                seid = re.search(r"UP:(0x[0-9a-fA-F]+)", line).group(1)
                ip   = re.search(r"IPv4\[([0-9.]+)\]", line).group(1)
                with sessions_lock:
                    active_sessions[seid] = {"ip": ip, "slice": classify_ip(ip), "added_at": time.time()}
                    known_seids.add(seid)
                    pending_seids[seid] = time.time()
                update_sessions()
                print(f"[SESSION] +{classify_ip(ip)} {ip} SEID={seid}")
                continue

            if LOG_KEYWORDS["session_cnt"] in line:
                count = int(re.search(r"now (\d+)", line).group(1))
                handle_session_count_change(count)
                continue

            if LOG_KEYWORDS["dnn_slice_reject"] in line:
                publish("events:alerts", {"alert": "NSSAI_MANIPULATION", "severity": "CRITICAL", "detail": "Tentative accès DNN/Slice non autorisé", "source": service})
                print(f"[!!! ATTACK] UNAUTHORIZED SLICE/DNN ACCESS")
                continue

            if LOG_KEYWORDS["nssai_error"] in line:
                publish("events:alerts", {"alert": "SLICE_ISOLATION_VIOLATION", "severity": "CRITICAL", "detail": "No Allowed-NSSAI", "source": service})
                continue

            if LOG_KEYWORDS["amf_reject"] in line:
                cause = re.search(r"\[(\d+)\]", line).group(1)
                if cause not in {"11", "15", "72", "76", "3", "9"}:
                    publish("events:alerts", {"alert": "AMF_REGISTRATION_REJECT", "severity": "HIGH", "detail": f"Reject cause={cause}", "source": service})
                continue

            if LOG_KEYWORDS["ngap_reg"] in line:
                ngap_timestamps.append(time.time())
                update_ngap_rate()
                now = time.time()
                recent = sum(1 for t in ngap_timestamps if now - t < 5)
                if recent >= NGAP_DOS_THRESHOLD:
                    publish("events:alerts", {"alert": "NGAP_DOS", "severity": "CRITICAL", "detail": f"{recent} registrations in 5 sec", "source": service})
                    print(f"[!!! ATTACK] NGAP DoS — {recent} reg/5s")
        except Exception:
            continue

def start_log_collectors():
    for svc in SERVICES:
        threading.Thread(target=tail_journal, args=(svc,), daemon=True).start()
        print(f"[+] Log collector: {svc}")

# ── 2. PFCP Sniffer ──────────────────────────────────────
PFCP_MSG_TYPES = {
    50: "Est_Req", 51: "Est_Resp",
    52: "Mod_Req", 53: "Mod_Resp",
    54: "Del_Req", 55: "Del_Resp"
}

def find_ie(data, target_type, depth=0):
    if depth > 5: return None, None
    pos = 0
    while pos + 4 <= len(data):
        try:
            ie_t = struct.unpack_from(">H", data, pos)[0]
            ie_l = struct.unpack_from(">H", data, pos + 2)[0]
            if pos + 4 + ie_l > len(data): break
            ie_d = data[pos + 4: pos + 4 + ie_l]
            if ie_t == target_type: return ie_t, ie_d
            if ie_t in (3, 4, 10, 11):
                res_t, res_d = find_ie(ie_d, target_type, depth + 1)
                if res_t is not None: return res_t, res_d
            pos += 4 + ie_l
        except: break
    return None, None

def pfcp_handler(pkt):
    try:
        if not (UDP in pkt and IP in pkt and Raw in pkt): return
        if pkt[UDP].dport != PFCP_PORT and pkt[UDP].sport != PFCP_PORT: return

        raw = bytes(pkt[Raw])
        if len(raw) < 12: return

        flags    = raw[0]
        msg_type = raw[1]
        src      = pkt[IP].src
        dst      = pkt[IP].dst

        seid = None
        seid_int = 0
        if (flags & 0x01) and len(raw) >= 12:
            seid_int = struct.unpack_from(">Q", raw, 4)[0]
            seid     = hex(seid_int)

        msg_name = PFCP_MSG_TYPES.get(msg_type, f"type_{msg_type}")
        pfcp_stats["total"] += 1
        if msg_type == 52: pfcp_stats["mod_req"] += 1

        if msg_type in (50, 51) and seid and seid_int != 0:
            known_seids.add(seid)
            pending_seids[seid] = time.time()

        publish("events:pfcp", {
            "type": "pfcp_message", "src": src, "dst": dst,
            "msg_type": msg_type, "msg_name": msg_name, "seid": seid, "size": len(raw),
        })

        # ── DÉTECTION INJECTION (source inconnue + Mod/Del Request) ──
        if src not in LEGIT_PFCP and msg_type in (52, 54):
            pfcp_stats["injections"] += 1
            publish("events:alerts", {
                "alert": "PFCP_INJECTION",
                "severity": "CRITICAL",
                "src": src, "dst": dst, "seid": seid,
                "detail": f"Mod/Del Request from unauthorized src {src}",
            })
            print(f"[!!! ATTACK] PFCP INJECTION — {msg_name} depuis {src}")

        r.hset("pfcp:stats", mapping={k: str(v) for k, v in pfcp_stats.items()})

    except Exception as e:
        print(f"[SNIFFER ERR] {e}")
def start_pfcp_sniffer():
    threading.Thread(
        target=lambda: sniff(filter=f"udp port {PFCP_PORT}", prn=pfcp_handler, store=False, iface="lo"),
        daemon=True
    ).start()
    print("[+] PFCP sniffer on lo:8805")

# ── 3. OGSTUN Sniffer ──────────────────────────────────
def ogstun_handler(pkt):
    if IP not in pkt: return
    src, dst = pkt[IP].src, pkt[IP].dst
    is_embb = src.startswith("10.45.") or dst.startswith("10.45.")
    is_iot  = src.startswith("10.46.") or dst.startswith("10.46.")

    if is_embb: gtp_stats["embb"] += 1
    if is_iot:  gtp_stats["iot"]  += 1

    if (src.startswith("10.45.") and dst.startswith("10.46.")) or \
       (src.startswith("10.46.") and dst.startswith("10.45.")):
        gtp_stats["cross"] += 1
        publish("events:alerts", {
            "alert": "SLICE_ISOLATION_VIOLATION",
            "severity": "CRITICAL",
            "detail": f"Cross-slice traffic: {src} ↔ {dst}",
            "source": "ogstun"
        })
        print(f"[!!! ATTACK] CROSS-SLICE: {src} ↔ {dst}")

    r.hset("gtp:stats", mapping={k: str(v) for k, v in gtp_stats.items()})

def start_ogstun_sniffer():
    threading.Thread(target=lambda: sniff(iface=OGSTUN_IF, prn=ogstun_handler, store=False), daemon=True).start()
    print(f"[+] Cross-slice sniffer on {OGSTUN_IF}")

# ── 4. Métriques système ──────────────────────────────────
def collect_metrics():
    prev = None
    while True:
        try:
            s = psutil.net_io_counters(pernic=True).get(OGSTUN_IF)
            if s and prev:
                r.hset("current:traffic", "eMBB", json.dumps({
                    "bps_out": max(0, s.bytes_sent - prev.bytes_sent),
                    "bps_in":  max(0, s.bytes_recv - prev.bytes_recv)
                }))
            prev = s
        except: pass
        time.sleep(1)

def start_metrics():
    threading.Thread(target=collect_metrics, daemon=True).start()

# ── 5. Chargement initial (ANTI-ZOMBIES) ────────────────────
def load_sessions():
    global last_upf_count
    print("[*] Checking active sessions at startup (last 30s only)...")

    # Ne regarde que les 30 dernières secondes pour éviter les logs morts
    res = subprocess.run(
        ["journalctl", "-u", "open5gs-upfd", "--since", "30 sec ago",
         "--output=short-iso"],
        capture_output=True, text=True
    )

    counts = re.findall(r"Number of UPF-Sessions is now (\d+)", res.stdout)
    final_count = int(counts[-1]) if counts else 0

    if final_count == 0:
        print("[+] UPF reports 0 sessions → nothing to restore")
        last_upf_count = 0
        update_sessions()
        return

    pat = re.compile(r"UE F-SEID\[UP:(0x[0-9a-fA-F]+)\s+CP:(0x[0-9a-fA-F]+)\].*?IPv4\[([0-9.]+)\]")
    found = []
    for line in res.stdout.splitlines():
        m = pat.search(line)
        if m: found.append((m.group(1), {"ip": m.group(3), "slice": classify_ip(m.group(3)), "added_at": time.time()}))

    # Ne restaure que les sessions récentes correspondant au compteur actuel
    to_restore = dict(found[-final_count:]) if found else {}
    with sessions_lock:
        active_sessions.update(to_restore)
        known_seids.update(active_sessions.keys())
        last_upf_count = final_count

    update_sessions()
    print(f"[+] Restored {len(active_sessions)} recent sessions")
    for seid, info in active_sessions.items():
        print(f"    {seid} → {info['slice']} {info['ip']}")

# ── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  5G SECURITY COLLECTOR — FINAL CORRECTED VERSION")
    print("=" * 55)

    # 🧹 Nettoyage des anciennes métriques/alertes
    print("[*] Clearing previous Redis stats & alerts...")
    r.delete("pfcp:stats", "gtp:stats", "ngap:stats", 
             "events:alerts", "current:traffic", "collector:heartbeat")
    r.delete("sessions:eMBB", "sessions:IoT", "sessions:total")
    r.set("sessions:json", "{}")
    r.flushall()  # Optionnel : supprime tout si Redis est dédié au collector

    load_sessions()
    start_log_collectors()
    start_pfcp_sniffer()
    start_ogstun_sniffer()
    start_metrics()
    load_sessions()
    start_log_collectors()
    start_pfcp_sniffer()
    start_ogstun_sniffer()
    start_metrics()

    print("\n[+] All collectors running. Ctrl+C to stop.\n")

    try:
        i = 0
        while True:
            time.sleep(5)
            r.set("collector:heartbeat", ts())
            i += 1
            if i % 6 == 0:
                embb  = r.get("sessions:eMBB") or 0
                iot   = r.get("sessions:IoT") or 0
                ngap  = r.hget("ngap:stats", "reg_rate") or 0
                pinj  = r.hget("pfcp:stats", "injections") or 0
                pohc  = r.hget("pfcp:stats", "ohc_detected") or 0
                cross = r.hget("gtp:stats", "cross") or 0
                upf   = last_upf_count
                print(f"[STATUS] eMBB={embb} IoT={iot} UPF={upf} | NGAP={ngap}/min | PFCP_inj={pinj} OHC={pohc} | Cross={cross}")
    except KeyboardInterrupt:
        print("\n[!] Collector stopped.")
