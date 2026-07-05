"""
features.py — VERSION 3 (Règles + ML)
======================================
Features ancrées sur de vrais indicateurs d'attaque :
  - pfcp_injections   : injection PFCP détectée par le collector
  - pfcp_alien_srcs   : source PFCP non-SMF
  - critical_alerts   : alertes critiques réelles
  - pfcp_mod_spike    : pic anormal de Session Modification Requests
  - gtp_redirect      : redirection GTP-U suspecte

Le vecteur de features sépare clairement trafic NORMAL vs ATTAQUE.
"""

import time
import redis
import numpy as np
from collections import deque
from datetime import datetime

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

WINDOW_SEC = 60   # fenêtre plus large pour mieux voir les pics

class FeatureExtractor:
    def __init__(self, window_sec=WINDOW_SEC):
        self.window = window_sec

        # Buffers (timestamp, ...)
        self.pfcp_events  = deque()  # (t, msg_type, src)
        self.gtp_events   = deque()  # (t, slice, size, dst)
        self.alert_events = deque()  # (t, alert_type, severity)
        self.traffic_buf  = deque()  # (t, bps_in, bps_out)

        # Compteurs cumulatifs vrais (depuis Redis)
        self._last_injections = 0
        self._last_mod_req    = 0

    def _prune(self):
        cutoff = time.time() - self.window
        for buf in [self.pfcp_events, self.gtp_events,
                    self.alert_events, self.traffic_buf]:
            while buf and buf[0][0] < cutoff:
                buf.popleft()

    def ingest_pfcp(self, event: dict):
        t = time.time()
        self.pfcp_events.append((
            t,
            event.get("msg_type", 0),
            event.get("src", "")
        ))

    def ingest_gtp(self, event: dict):
        t = time.time()
        self.gtp_events.append((
            t,
            event.get("slice", "unknown"),
            event.get("size", 0),
            event.get("dst", "")
        ))

    def ingest_alert(self, event: dict):
        # Ignorer les alertes auto-générées par le detector
        alert = event.get("alert", "")
        if alert.startswith("AI_DETECTED_"):
            return
        t = time.time()
        self.alert_events.append((
            t,
            alert,
            event.get("severity", "LOW")
        ))

    def ingest_traffic(self, event: dict):
        t = time.time()
        self.traffic_buf.append((
            t,
            event.get("bps_in", 0),
            event.get("bps_out", 0)
        ))

    def extract(self) -> dict:
        self._prune()

        # ── PFCP features ────────────────────────────────
        pfcp_total   = len(self.pfcp_events)
        pfcp_mod_req = sum(1 for _, mt, _ in self.pfcp_events if mt == 52)

        # Sources PFCP légitimes
        LEGIT = {"127.0.0.4", "127.0.0.7", ""}
        pfcp_alien_srcs = len({
            src for _, _, src in self.pfcp_events
            if src not in LEGIT
        })

        # ── Lire les vrais compteurs d'attaque depuis Redis ──
        # Ces valeurs sont écrites par le collector quand il détecte
        # une vraie injection (source non-SMF)
        pfcp_stats = r.hgetall("pfcp:stats")
        real_injections = int(pfcp_stats.get("injections", 0))
        real_mod_req    = int(pfcp_stats.get("mod_req", 0))

        # Delta injections depuis la dernière lecture
        delta_injections = max(0, real_injections - self._last_injections)
        self._last_injections = real_injections

        # Pic de Mod Requests (> 5 dans la fenêtre = suspect)
        mod_req_rate = pfcp_mod_req / max(self.window / 60, 1)  # par minute
        mod_spike    = 1.0 if mod_req_rate > 5 else 0.0

        # ── Alert features (vrais alertes collecteur) ────
        critical_alerts = sum(
            1 for _, alert, sev in self.alert_events
            if sev == "CRITICAL"
            and not alert.startswith("AI_DETECTED_")
        )
        high_alerts = sum(
            1 for _, alert, sev in self.alert_events
            if sev == "HIGH"
            and not alert.startswith("AI_DETECTED_")
        )

        # Types d'alertes spécifiques
        pfcp_inj_alerts = sum(
            1 for _, alert, _ in self.alert_events
            if alert == "PFCP_INJECTION"
        )
        gtp_redir_alerts = sum(
            1 for _, alert, _ in self.alert_events
            if alert == "GTP_REDIRECTION"
        )
        slice_viol_alerts = sum(
            1 for _, alert, _ in self.alert_events
            if alert in ("SLICE_ISOLATION_VIOLATION",
                         "AMF_REGISTRATION_REJECT")
        )

        # ── GTP features ─────────────────────────────────
        gtp_total = len(self.gtp_events)
        gtp_stats = r.hgetall("gtp:stats")
        gtp_cross = int(gtp_stats.get("cross", 0))

        # ── Traffic features ─────────────────────────────
        bps_vals = [b for _, b, _ in self.traffic_buf]
        avg_bps  = float(np.mean(bps_vals)) if bps_vals else 0.0

        return {
            # ── Indicateurs d'attaque DIRECTS ──────────────
            # Ces features sont 0 en situation normale
            # et > 0 uniquement lors d'une vraie attaque
            "pfcp_injections":    min(real_injections, 100),
            "pfcp_alien_srcs":    min(pfcp_alien_srcs, 20),
            "pfcp_inj_alerts":    min(pfcp_inj_alerts, 50),
            "gtp_redir_alerts":   min(gtp_redir_alerts, 50),
            "slice_viol_alerts":  min(slice_viol_alerts, 50),
            "critical_alerts":    min(critical_alerts, 50),

            # ── Indicateurs comportementaux ─────────────────
            # Peuvent varier même en situation normale
            "pfcp_total":         min(pfcp_total, 1000),
            "pfcp_mod_req":       min(pfcp_mod_req, 500),
            "mod_req_spike":      mod_spike,
            "high_alerts":        min(high_alerts, 50),

            # ── Trafic réseau ───────────────────────────────
            "gtp_total":          min(gtp_total, 5000),
            "gtp_cross_slice":    min(gtp_cross, 100),
            "avg_bps":            min(avg_bps, 1e6),

            # ── Meta ────────────────────────────────────────
            "window_sec":         self.window,
            "timestamp":          datetime.utcnow().isoformat(),
        }

    def feature_vector(self) -> np.ndarray:
        """16 features pour les modèles ML."""
        f = self.extract()
        return np.array([
            # Groupe 1 : Indicateurs d'attaque directs (poids forts)
            f["pfcp_injections"],
            f["pfcp_alien_srcs"],
            f["pfcp_inj_alerts"],
            f["gtp_redir_alerts"],
            f["slice_viol_alerts"],
            f["critical_alerts"],
            # Groupe 2 : Comportement PFCP
            f["pfcp_total"],
            f["pfcp_mod_req"],
            f["mod_req_spike"],
            f["high_alerts"],
            # Groupe 3 : GTP
            f["gtp_total"],
            f["gtp_cross_slice"],
            # Groupe 4 : Trafic
            f["avg_bps"],
            # Padding pour garder 16 features
            0.0, 0.0, 0.0,
        ], dtype=np.float32)

    @staticmethod
    def feature_names():
        return [
            "pfcp_injections", "pfcp_alien_srcs", "pfcp_inj_alerts",
            "gtp_redir_alerts", "slice_viol_alerts", "critical_alerts",
            "pfcp_total", "pfcp_mod_req", "mod_req_spike", "high_alerts",
            "gtp_total", "gtp_cross_slice", "avg_bps",
            "pad1", "pad2", "pad3",
        ]
