# from flask import Flask, jsonify, request, render_template
# import sqlite3
# import random
# import time
# from datetime import datetime

# app = Flask(__name__)

# # ── In-memory blocked IPs set ──────────────────────────────────────────────
# blocked_ips: set = set()

# # ── Country pool for simulated geo-lookup ─────────────────────────────────
# COUNTRIES = [
#     "India", "China", "Russia", "United States", "Brazil",
#     "Germany", "Ukraine", "South Korea", "Vietnam", "Nigeria",
#     "Iran", "Pakistan", "Indonesia", "France", "United Kingdom",
# ]

# # Deterministic-ish mapping so the same IP doesn't flip countries each poll
# _ip_country_cache: dict = {}

# def get_country(ip: str) -> str:
#     if ip not in _ip_country_cache:
#         _ip_country_cache[ip] = random.choice(COUNTRIES)
#     return _ip_country_cache[ip]


# def risk_level(packets: int) -> str:
#     if packets > 5000:
#         return "HIGH"
#     if packets >= 2000:
#         return "MEDIUM"
#     return "LOW"


# def anomaly_score(packets: int) -> float:
#     """Simple normalised score: clamps at 1.0 above 10 000 packets."""
#     raw = min(packets / 10_000, 1.0)
#     return round(raw, 2)


# def query_traffic() -> list[dict]:
#     """Return aggregated traffic from the last 5 seconds."""
#     db_path = "../database/ddos.db"
#     cutoff = time.time() - 5          # UNIX timestamp, 5-second window

#     try:
#         conn = sqlite3.connect(db_path)
#         conn.row_factory = sqlite3.Row
#         cur = conn.cursor()
#         cur.execute(
#             """
#             SELECT source_ip, SUM(packets) AS total_packets
#             FROM   traffic_logs
#             WHERE  timestamp >= ?
#             GROUP  BY source_ip
#             ORDER  BY total_packets DESC
#             """,
#             (cutoff,),
#         )
#         rows = cur.fetchall()
#         conn.close()
#     except sqlite3.OperationalError:
#         # DB not ready yet — return empty list gracefully
#         rows = []

#     results = []
#     for row in rows:
#         ip = row["source_ip"]
#         if ip in blocked_ips:
#             continue
#         pkts = int(row["total_packets"])
#         results.append(
#             {
#                 "ip":            ip,
#                 "packets":       pkts,
#                 "risk":          risk_level(pkts),
#                 "country":       get_country(ip),
#                 "anomaly_score": anomaly_score(pkts),
#             }
#         )
#     return results


# # ── Routes ─────────────────────────────────────────────────────────────────

# @app.route("/")
# def index():
#     return render_template("index.html")


# @app.route("/data", methods=["GET"])
# def data():
#     """Return live traffic data as JSON."""
#     return jsonify(query_traffic())


# @app.route("/block", methods=["POST"])
# def block():
#     """Block an IP address (persists for the lifetime of the process)."""
#     payload = request.get_json(force=True, silent=True) or {}
#     ip = payload.get("ip", "").strip()
#     if not ip:
#         return jsonify({"error": "No IP provided"}), 400
#     blocked_ips.add(ip)
#     return jsonify({"status": "blocked", "ip": ip})


# @app.route("/blocked", methods=["GET"])
# def get_blocked():
#     return jsonify(list(blocked_ips))


# if __name__ == "__main__":
#     app.run(debug=True, port=5000)


"""
dashboard/app.py
─────────────────
Flask backend for the SENTINEL DDoS monitoring dashboard.

Endpoints
  GET  /           → render index.html
  GET  /data        → live threat data (consumed by script.js every 3 s)
  GET  /summary     → high-level stats (total, high count, peak, etc.)
  POST /block       → block an IP  { "ip": "..." }
  POST /unblock     → unblock an IP { "ip": "..." }
  GET  /blocked     → list all blocked IPs

Data flow
  script.js  →  GET /data  →  DDoSDetector.analyse()
                            →  database.fetch_window()
                            →  WindowAggregator → AnomalyScorer → RiskClassifier
                            →  list[ThreatRecord]  →  JSON response

The detector is instantiated once at startup and reused across requests.
Blocked IPs are stored both in memory (for speed) and persisted to the DB
so they survive a server restart.
"""

from __future__ import annotations

import os
import sys
import time

from flask import Flask, jsonify, request, render_template

# ── Path setup — allow imports from project root ──────────────────────────────
_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT  = os.path.dirname(_DASHBOARD_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.database import (
    init_db, DB_PATH,
    block_ip   as db_block_ip,
    unblock_ip as db_unblock_ip,
    get_blocked_ips,
)
from detection_engine.detector import DDoSDetector

# ── App init ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Ensure the database schema exists before we do anything
init_db(DB_PATH)

# ── In-memory blocked IP set (fast lookup; kept in sync with DB) ──────────────
_blocked: set[str] = {row["ip"] for row in get_blocked_ips(DB_PATH)}

# ── Detector instance (stateless per call, safe to share) ────────────────────
detector = DDoSDetector(
    window_seconds=5.0,
    db_path=DB_PATH,
    blocked_ips=_blocked,          # detector reads this reference each call
)


# ╔══════════════════════════════════════════════════════╗
# ║  ROUTES                                              ║
# ╚══════════════════════════════════════════════════════╝

@app.route("/")
def index():
    return render_template("index.html")


# ── /data — primary endpoint polled by the frontend every 3 seconds ───────────
@app.route("/data", methods=["GET"])
def data():
    """
    Returns the full threat list for the current 5-second window.

    Each item shape (matches frontend expectations in script.js):
    {
        "ip":            "1.2.3.4",
        "packets":       6200,
        "bytes":         3100000,
        "risk":          "HIGH",          // LOW | MEDIUM | HIGH
        "country":       "Russia",
        "anomaly_score": 0.743,           // 0.0 – 1.0
        "log_count":     87,              // raw event count
        "protocols":     ["TCP", "UDP"],
        "top_ports":     [80, 443, 8080],
        "pps":           1240.0,          // packets / second
        "bps":           620000.0         // bytes / second
    }
    """
    try:
        threats = detector.analyse_as_dicts()
    except Exception as exc:
        app.logger.error("Detector error: %s", exc)
        threats = []

    return jsonify(threats)


# ── /summary — lightweight stats panel data ───────────────────────────────────
@app.route("/summary", methods=["GET"])
def summary():
    """
    Returns aggregate stats for the top-bar cards.
    The frontend already computes these client-side from /data,
    but this endpoint is available for server-side consumers.

    {
        "total_ips": 12,
        "total_packets": 84200,
        "high_risk_count": 3,
        "medium_risk_count": 4,
        "low_risk_count": 5,
        "peak_packets": 12400,
        "top_threat_ip": "192.168.1.55"
    }
    """
    try:
        s = detector.summary()
    except Exception as exc:
        app.logger.error("Summary error: %s", exc)
        s = {}
    return jsonify(s)


# ── /block — add an IP to the block list ─────────────────────────────────────
@app.route("/block", methods=["POST"])
def block():
    """
    Body: { "ip": "1.2.3.4" }

    1. Adds IP to the in-memory set   → detector skips it immediately
    2. Persists to blocked_ips table  → survives restarts
    """
    payload = request.get_json(force=True, silent=True) or {}
    ip = (payload.get("ip") or "").strip()

    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    _blocked.add(ip)
    db_block_ip(ip, reason="dashboard-manual", path=DB_PATH)

    return jsonify({"status": "blocked", "ip": ip})


# ── /unblock — remove an IP from the block list ───────────────────────────────
@app.route("/unblock", methods=["POST"])
def unblock():
    """
    Body: { "ip": "1.2.3.4" }
    """
    payload = request.get_json(force=True, silent=True) or {}
    ip = (payload.get("ip") or "").strip()

    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    _blocked.discard(ip)
    db_unblock_ip(ip, path=DB_PATH)

    return jsonify({"status": "unblocked", "ip": ip})


# ── /blocked — list all currently blocked IPs ─────────────────────────────────
@app.route("/blocked", methods=["GET"])
def blocked():
    """
    Returns full metadata for each blocked IP:
    [{ "ip": "...", "blocked_at": 1712345678.0, "reason": "dashboard-manual" }]
    """
    rows = get_blocked_ips(DB_PATH)
    return jsonify(rows)


# ── /health — simple liveness check ──────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ts": time.time()})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[SENTINEL] Dashboard starting → http://localhost:5000")
    print(f"[SENTINEL] DB path: {DB_PATH}")
    app.run(debug=True, port=5000, use_reloader=False)