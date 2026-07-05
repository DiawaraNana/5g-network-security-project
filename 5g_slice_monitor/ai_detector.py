import json, time, redis
from datetime import datetime, timezone
from collections import deque

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# 🔧 Seuils & Politiques de sécurité
THRESHOLDS = {
    "ngap_reg_rate": 15,
    "pfcp_injections": 50,
    "gtp_cross": 3
}
ALLOWED_SST = {2, 3} # Slices autorisés (0x01, 0x02, 0x03)
ALLOWED_PFCP_IPS = {"127.0.0.1", "192.168.139.130", "192.168.139.140"} # UPF/GNB légitimes

def read_stats():
    pfcp = r.hgetall("pfcp:stats") or {}
    gtp  = r.hgetall("gtp:stats")  or {}
    ngap = r.hgetall("ngap:stats") or {}

    # Parsing sécurisé des alertes externes
    alerts_raw = r.lrange("events:alerts", 0, 199)
    recent = []
    for a in alerts_raw:
        try:
            parsed = json.loads(a)
            if parsed.get("alert") and not parsed["alert"].startswith("RULE_DETECTED_"):
                recent.append(parsed)
        except: pass

    cnt = lambda n: sum(1 for x in recent if x.get("alert") == n)

    return {
        "pfcp_inj_alerts": cnt("PFCP_INJECTION"),
        "pfcp_injections": int(pfcp.get("injections", 0)),
        "slice_viol_alerts": cnt("SLICE_ISOLATION_VIOLATION"),
        "nssai_alerts": cnt("NSSAI_MANIPULATION"),
        "ngap_dos_alerts": cnt("NGAP_DOS"),
        "ngap_reg_rate": float(ngap.get("reg_rate", 0)),
        "gtp_cross": int(gtp.get("cross", 0)),
        "used_nssai": json.loads(ngap.get("used_nssai", "[]")),
        "pfcp_far_ips": json.loads(pfcp.get("far_dest_ips", "[]"))
    }

def detect(s):
    # 🚨 1. DoS NGAP
    if s["ngap_dos_alerts"] > 0 or s["ngap_reg_rate"] > THRESHOLDS["ngap_reg_rate"]:
        return "Attack", "NGAP_DOS", f"DoS NGAP (rate: {s['ngap_reg_rate']}/s)", 1.0

    # 🚨 2. DoS PFCP
    if s["pfcp_injections"] > THRESHOLDS["pfcp_injections"]:
        return "Attack", "PFCP_DOS", f"DoS PFCP (injections: {s['pfcp_injections']})", 1.0

    # 🔍 3. NSSAI Manipulation / Slice Forcé
    if s["nssai_alerts"] > 0:
        return "Attack", "NSSAI_MANIPULATION", "Manipulation S-NSSAI/DNN", 0.95
    for sst in s["used_nssai"]:
        if sst not in ALLOWED_SST:
            return "Attack", "NSSAI_FORCED_SLICE", f"Slice forcé SST={hex(sst)} non autorisé", 0.95

    # 🔍 4. PFCP Hijack (Redirection vers IP non topologique)
    rogue_ips = [ip for ip in s["pfcp_far_ips"] if ip not in ALLOWED_PFCP_IPS]
    if rogue_ips:
        return "Attack", "PFCP_FAR_HIJACK", f"Redirection FAR vers IP non autorisée: {rogue_ips[0]}", 1.0
    if s["pfcp_inj_alerts"] > 0:
        return "Attack", "PFCP_MANIPULATION", "Injection/Modification FAR PFCP", 1.0

    # 🔍 5. Cross-Slice
    if s["slice_viol_alerts"] > 0:
        return "Attack", "CROSS_SLICE_ATTACK", "Violation isolation slice", 0.95
    if s["gtp_cross"] > THRESHOLDS["gtp_cross"]:
        return "Suspicious", "CROSS_SLICE_ATTEMPT", f"Fuite inter-slice GTP x{s['gtp_cross']}", 0.7

    return "Normal", None, None, 0.0

class Hyst:
    def __init__(self): self.buf=deque(maxlen=5); self.st="Normal"
    def update(self, l):
        self.buf.append(l); n={"Attack":1,"Suspicious":3,"Normal":5}.get(l,3)
        if len(self.buf)>=n and all(x==l for x in list(self.buf)[-n:]): self.st=l
        return self.st

class Engine:
    def __init__(self): self.cyc=0; self.h=Hyst(); self.prev=None; print("[*] Rule-Based Detector Ready\n")
    def run_once(self):
        self.cyc+=1; s=read_stats(); raw,atk,rsn,sc=detect(s); fin=self.h.update(raw)
        if fin=="Normal": sc=0.0
        out={"timestamp":datetime.now(timezone.utc).isoformat(),"ensemble":fin,"anomaly_score":round(sc,4),"models":[{"model":"Rules","label":fin,"score":sc,"detail":rsn or "OK"}],"features":s,"attack_type":atk,"rule_reason":rsn,"cycle":self.cyc}
        r.set("rules:latest",json.dumps(out)); r.lpush("rules:history",json.dumps(out)); r.ltrim("rules:history",0,3599)
        if fin in ("Attack","Suspicious") and atk!=self.prev:
            r.lpush("events:alerts",json.dumps({"timestamp":out["timestamp"],"alert":f"RULE_DETECTED_{atk}","attack_type":atk,"severity":"CRITICAL" if fin=="Attack" else "HIGH","score":sc,"reason":rsn}))
            r.ltrim("events:alerts",0,9999); self.prev=atk
        elif fin=="Normal": self.prev=None
        return out
    def run(self):
        while True:
            try:
                o=self.run_once()
                if o["ensemble"]!="Normal": print(f"[RULE] 🔴 {o['ensemble']} | {o['attack_type']} | {o['rule_reason']}")
                elif o["cycle"]%30==0: print(f"[RULE] ✅ Normal | inj={o['features']['pfcp_injections']} cross={o['features']['gtp_cross']}")
            except Exception as e: print(f"[!] {e}")
            time.sleep(1)

if __name__=="__main__": Engine().run()
