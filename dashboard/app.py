from flask import Flask, jsonify, request, render_template
import sqlite3
import random
import time
from datetime import datetime

app = Flask(__name__)

# ── In-memory blocked IPs set ──────────────────────────────────────────────
blocked_ips: set = set()

# ── Country pool for simulated geo-lookup ─────────────────────────────────
COUNTRIES = [
    "India", "China", "Russia", "United States", "Brazil",
    "Germany", "Ukraine", "South Korea", "Vietnam", "Nigeria",
    "Iran", "Pakistan", "Indonesia", "France", "United Kingdom",
]

# Deterministic-ish mapping so the same IP doesn't flip countries each poll
_ip_country_cache: dict = {}

def get_country(ip: str) -> str:
    if ip not in _ip_country_cache:
        _ip_country_cache[ip] = random.choice(COUNTRIES)
    return _ip_country_cache[ip]


def risk_level(packets: int) -> str:
    if packets > 5000:
        return "HIGH"
    if packets >= 2000:
        return "MEDIUM"
    return "LOW"


def anomaly_score(packets: int) -> float:
    """Simple normalised score: clamps at 1.0 above 10 000 packets."""
    raw = min(packets / 10_000, 1.0)
    return round(raw, 2)


def query_traffic() -> list[dict]:
    """Return aggregated traffic from the last 5 seconds."""
    db_path = "../database/ddos.db"
    cutoff = time.time() - 5          # UNIX timestamp, 5-second window

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT source_ip, SUM(packets) AS total_packets
            FROM   traffic_logs
            WHERE  timestamp >= ?
            GROUP  BY source_ip
            ORDER  BY total_packets DESC
            """,
            (cutoff,),
        )
        rows = cur.fetchall()
        conn.close()
    except sqlite3.OperationalError:
        # DB not ready yet — return empty list gracefully
        rows = []

    results = []
    for row in rows:
        ip = row["source_ip"]
        if ip in blocked_ips:
            continue
        pkts = int(row["total_packets"])
        results.append(
            {
                "ip":            ip,
                "packets":       pkts,
                "risk":          risk_level(pkts),
                "country":       get_country(ip),
                "anomaly_score": anomaly_score(pkts),
            }
        )
    return results


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/data", methods=["GET"])
def data():
    """Return live traffic data as JSON."""
    return jsonify(query_traffic())


@app.route("/block", methods=["POST"])
def block():
    """Block an IP address (persists for the lifetime of the process)."""
    payload = request.get_json(force=True, silent=True) or {}
    ip = payload.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    blocked_ips.add(ip)
    return jsonify({"status": "blocked", "ip": ip})


@app.route("/blocked", methods=["GET"])
def get_blocked():
    return jsonify(list(blocked_ips))


if __name__ == "__main__":
    app.run(debug=True, port=5000)