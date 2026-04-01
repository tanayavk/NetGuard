"""
data_ingestion/traffic_generator.py
─────────────────────────────────────
Simulates network traffic and writes it into traffic_logs.

Traffic model
  • N_NORMAL normal IPs  → low packet rate, varied ports, random intervals
  • At random intervals, 1-3 "attack" IPs flood the target with high packet
    volumes to trigger the detector's HIGH / MEDIUM thresholds.

Run this in a separate terminal before starting app.py:
    python data_ingestion/traffic_generator.py
"""

from __future__ import annotations

import os
import sys
import time
import random
import signal

# ── Path resolution ──────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.database import init_db, insert_logs_bulk, purge_old_logs, DB_PATH

# ── Config ────────────────────────────────────────────────────────────────────
TICK_INTERVAL   = 1.0          # seconds between generation ticks
PURGE_INTERVAL  = 60           # purge old rows every N ticks
PURGE_OLDER_THAN = 300.0       # keep only last 5 minutes of logs

N_NORMAL_IPS    = 12           # number of benign source IPs in the pool
NORMAL_PKTS_MIN = 20
NORMAL_PKTS_MAX = 400
NORMAL_BYTES_PER_PKT = 512     # avg bytes per normal packet

ATTACK_PROB     = 0.25         # probability that an attack tick fires
N_ATTACKERS     = 2            # simultaneous attack IPs per attack tick
ATTACK_PKTS_MIN = 3_000
ATTACK_PKTS_MAX = 12_000
ATTACK_BYTES_PER_PKT = 1_024

DEST_IP         = "10.0.0.1"  # simulated server being targeted
PROTOCOLS       = ["TCP", "UDP", "ICMP"]
WEB_PORTS       = [80, 443, 8080, 8443, 3000]
OTHER_PORTS     = [22, 25, 53, 110, 143, 3306, 5432, 6379]

# ── IP pool generation ────────────────────────────────────────────────────────
def _make_ip_pool(n: int, prefix: str = "192.168.") -> list[str]:
    pool = set()
    while len(pool) < n:
        pool.add(f"{prefix}{random.randint(1,254)}.{random.randint(2,254)}")
    return list(pool)

NORMAL_IPS  = _make_ip_pool(N_NORMAL_IPS, prefix="192.168.")
ATTACK_IPS  = _make_ip_pool(6, prefix="10.10.")    # pool of potential attackers

# ── Row builders ──────────────────────────────────────────────────────────────
def _normal_row(ip: str, now: float) -> dict:
    pkts  = random.randint(NORMAL_PKTS_MIN, NORMAL_PKTS_MAX)
    proto = random.choice(PROTOCOLS)
    port  = random.choice(WEB_PORTS + OTHER_PORTS)
    return {
        "timestamp": now,
        "source_ip": ip,
        "dest_ip":   DEST_IP,
        "packets":   pkts,
        "bytes":     pkts * NORMAL_BYTES_PER_PKT + random.randint(-100, 100),
        "protocol":  proto,
        "port":      port,
    }


def _attack_row(ip: str, now: float) -> dict:
    pkts  = random.randint(ATTACK_PKTS_MIN, ATTACK_PKTS_MAX)
    # Attackers hammer a single port (SYN flood characteristic)
    port  = random.choice(WEB_PORTS)
    return {
        "timestamp": now,
        "source_ip": ip,
        "dest_ip":   DEST_IP,
        "packets":   pkts,
        "bytes":     pkts * ATTACK_BYTES_PER_PKT,
        "protocol":  "TCP",
        "port":      port,
    }


# ── Main loop ─────────────────────────────────────────────────────────────────
def run() -> None:
    init_db(DB_PATH)
    print(f"[GENERATOR] DB → {DB_PATH}")
    print(f"[GENERATOR] Normal IPs : {len(NORMAL_IPS)}")
    print(f"[GENERATOR] Attack pool: {len(ATTACK_IPS)}")
    print(f"[GENERATOR] Tick every {TICK_INTERVAL}s  |  attack_prob={ATTACK_PROB}")
    print("[GENERATOR] Running — Ctrl+C to stop\n")

    tick = 0
    running = True

    def _shutdown(sig, frame):
        nonlocal running
        print("\n[GENERATOR] Shutting down…")
        running = False

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while running:
        now  = time.time()
        rows: list[dict] = []

        # Every normal IP emits one row per tick (staggered slightly)
        for ip in NORMAL_IPS:
            if random.random() < 0.85:   # 85% chance each IP sends this tick
                rows.append(_normal_row(ip, now + random.uniform(0, 0.5)))

        # Random attack burst
        if random.random() < ATTACK_PROB:
            attackers = random.sample(ATTACK_IPS, k=min(N_ATTACKERS, len(ATTACK_IPS)))
            for ip in attackers:
                # Attackers send multiple rows per tick to simulate burst
                for _ in range(random.randint(3, 8)):
                    rows.append(_attack_row(ip, now + random.uniform(0, 0.9)))
            print(f"[GENERATOR] ⚠ Attack tick — {len(attackers)} IPs firing")

        if rows:
            insert_logs_bulk(rows, path=DB_PATH)

        tick += 1

        # Periodic maintenance — delete logs older than PURGE_OLDER_THAN seconds
        if tick % PURGE_INTERVAL == 0:
            deleted = purge_old_logs(older_than_seconds=PURGE_OLDER_THAN, path=DB_PATH)
            print(f"[GENERATOR] Purged {deleted} old rows (tick {tick})")

        time.sleep(TICK_INTERVAL)

    print("[GENERATOR] Stopped.")


if __name__ == "__main__":
    run()