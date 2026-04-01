"""
detection_engine/detector.py
─────────────────────────────
The core DDoS detection brain.

Architecture
  ┌─────────────────────────────────────────────────────┐
  │  Raw DB rows (last N seconds)                        │
  │         ↓                                            │
  │  WindowAggregator   →  per-IP stats dict             │
  │         ↓                                            │
  │  AnomalyScorer      →  anomaly_score  (0.0 – 1.0)   │
  │         ↓                                            │
  │  RiskClassifier     →  LOW / MEDIUM / HIGH           │
  │         ↓                                            │
  │  DDoSDetector.analyse() → list[ThreatRecord]         │
  └─────────────────────────────────────────────────────┘

Key design decisions
  • Pure Python — no external ML deps, runs anywhere.
  • Stateless per call: detector reads from DB on every .analyse() call,
    so it is safe to call from multiple threads / processes.
  • AnomalyScorer uses a *composite* score from four independent signals,
    each weighted. This avoids false positives from a single metric spike.
  • Geo data is simulated (deterministic random) — replace get_country()
    with a real MaxMind / ip-api call in production.
"""

from __future__ import annotations

import os
import sys
import time
import random
import math
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Resolve project root so we can import database regardless of cwd ──────────
_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.database import fetch_window, DB_PATH


# ╔══════════════════════════════════════════════════════╗
# ║  CONSTANTS & THRESHOLDS                              ║
# ╚══════════════════════════════════════════════════════╝

# Risk classification (packets / window)
THRESHOLD_HIGH   = 5_000
THRESHOLD_MEDIUM = 2_000

# Anomaly score tuning — each signal contributes a weighted fraction
WEIGHT_PACKET_RATE   = 0.40   # dominant signal
WEIGHT_BYTE_RATE     = 0.20
WEIGHT_LOG_FREQUENCY = 0.25   # how many log entries (requests) per window
WEIGHT_ENTROPY       = 0.15   # low entropy in dest_ip == likely flood

# Normalisation ceilings (values at or above these → score component = 1.0)
CEIL_PACKETS   = 15_000
CEIL_BYTES     = 15_000_000   # 15 MB / window
CEIL_LOG_FREQ  = 500          # number of individual log entries
CEIL_ENTROPY   = 4.0          # bits; real diverse traffic has high entropy

# Geo simulation seed (same IP always gets same country)
_GEO_CACHE: dict[str, str] = {}

COUNTRIES = [
    "India", "China", "Russia", "United States", "Brazil",
    "Germany", "Ukraine", "South Korea", "Vietnam", "Nigeria",
    "Iran", "Pakistan", "Indonesia", "France", "United Kingdom",
    "Netherlands", "Romania", "Turkey", "Thailand", "Bangladesh",
]


# ╔══════════════════════════════════════════════════════╗
# ║  DATA STRUCTURES                                     ║
# ╚══════════════════════════════════════════════════════╝

@dataclass
class IPStats:
    """Aggregated statistics for one source IP within the analysis window."""
    source_ip:    str
    total_packets: int   = 0
    total_bytes:   int   = 0
    log_count:     int   = 0          # number of raw DB rows
    dest_ips:      list  = field(default_factory=list)   # for entropy
    protocols:     list  = field(default_factory=list)
    ports:         list  = field(default_factory=list)
    first_seen:    float = 0.0
    last_seen:     float = 0.0


@dataclass
class ThreatRecord:
    """
    One fully-enriched record returned by DDoSDetector.analyse().
    Shape matches what app.py forwards to the frontend as JSON.
    """
    ip:            str
    packets:       int
    bytes:         int
    risk:          str        # "LOW" | "MEDIUM" | "HIGH"
    country:       str
    anomaly_score: float      # 0.00 – 1.00
    log_count:     int        # raw event count in window
    protocols:     list[str]
    top_ports:     list[int]
    pps:           float      # packets per second (within window)
    bps:           float      # bytes per second

    def to_dict(self) -> dict:
        return asdict(self)


# ╔══════════════════════════════════════════════════════╗
# ║  WINDOW AGGREGATOR                                   ║
# ╚══════════════════════════════════════════════════════╝

class WindowAggregator:
    """
    Collapses raw DB rows into per-IP IPStats objects.
    Called once per detection cycle with the raw rows from the DB window.
    """

    @staticmethod
    def aggregate(rows: list[dict]) -> dict[str, IPStats]:
        stats: dict[str, IPStats] = {}
        for row in rows:
            ip = row["source_ip"]
            if ip not in stats:
                stats[ip] = IPStats(
                    source_ip  = ip,
                    first_seen = row["timestamp"],
                    last_seen  = row["timestamp"],
                )
            s = stats[ip]
            s.total_packets += row["packets"]
            s.total_bytes   += row["bytes"]
            s.log_count     += 1
            s.last_seen      = max(s.last_seen, row["timestamp"])
            s.dest_ips.append(row["dest_ip"])
            if row["protocol"]:
                s.protocols.append(row["protocol"])
            if row["port"] is not None:
                s.ports.append(row["port"])

        return stats


# ╔══════════════════════════════════════════════════════╗
# ║  ANOMALY SCORER                                      ║
# ╚══════════════════════════════════════════════════════╝

class AnomalyScorer:
    """
    Computes a composite anomaly score in [0.0, 1.0] for one IPStats.

    Signals
    -------
    1. Packet rate   — absolute packet volume vs CEIL_PACKETS
    2. Byte rate     — absolute byte volume vs CEIL_BYTES
    3. Log frequency — number of individual log entries (high → automated flood)
    4. Dest entropy  — Shannon entropy of destination IPs:
                       LOW entropy means all traffic hits the same target
                       (classic DDoS), HIGH entropy is more natural browsing
                       So we invert: score = 1 - (entropy / CEIL_ENTROPY)
    """

    @staticmethod
    def _shannon_entropy(values: list) -> float:
        if not values:
            return 0.0
        total = len(values)
        counts: dict = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def score(cls, s: IPStats) -> float:
        # Signal 1 — packet volume
        sig_packets = min(s.total_packets / CEIL_PACKETS, 1.0)

        # Signal 2 — byte volume
        sig_bytes = min(s.total_bytes / CEIL_BYTES, 1.0)

        # Signal 3 — log frequency (number of distinct traffic events)
        sig_freq = min(s.log_count / CEIL_LOG_FREQ, 1.0)

        # Signal 4 — destination entropy (inverted)
        entropy = cls._shannon_entropy(s.dest_ips)
        # Clamp entropy to ceiling, then invert (low entropy → high anomaly)
        sig_entropy = 1.0 - min(entropy / CEIL_ENTROPY, 1.0)

        composite = (
            WEIGHT_PACKET_RATE   * sig_packets +
            WEIGHT_BYTE_RATE     * sig_bytes   +
            WEIGHT_LOG_FREQUENCY * sig_freq    +
            WEIGHT_ENTROPY       * sig_entropy
        )
        return round(min(composite, 1.0), 3)


# ╔══════════════════════════════════════════════════════╗
# ║  RISK CLASSIFIER                                     ║
# ╚══════════════════════════════════════════════════════╝

class RiskClassifier:
    """
    Maps raw packet count → risk label.
    Also applies a score boost rule: if anomaly_score >= 0.85
    and risk is MEDIUM, escalates to HIGH (multi-signal confirmation).
    """

    @staticmethod
    def classify(packets: int, anomaly_score: float) -> str:
        if packets > THRESHOLD_HIGH:
            return "HIGH"
        if packets >= THRESHOLD_MEDIUM:
            # Escalate MEDIUM to HIGH when score is very high
            if anomaly_score >= 0.85:
                return "HIGH"
            return "MEDIUM"
        return "LOW"


# ╔══════════════════════════════════════════════════════╗
# ║  GEO LOOKUP (simulated)                              ║
# ╚══════════════════════════════════════════════════════╝

def get_country(ip: str) -> str:
    """
    Deterministic geo simulation — same IP always returns same country.
    Replace this function with a real GeoIP library (e.g. geoip2) in prod.
    """
    if ip not in _GEO_CACHE:
        rng = random.Random(ip)          # seed with IP for determinism
        _GEO_CACHE[ip] = rng.choice(COUNTRIES)
    return _GEO_CACHE[ip]


# ╔══════════════════════════════════════════════════════╗
# ║  MAIN DETECTOR                                       ║
# ╚══════════════════════════════════════════════════════╝

class DDoSDetector:
    """
    Orchestrates the full detection pipeline.

    Usage
    -----
        detector = DDoSDetector(window_seconds=5, db_path=DB_PATH)
        threats  = detector.analyse()   # returns list[ThreatRecord]

    The detector is stateless between calls — safe for multi-threaded use.
    """

    def __init__(
        self,
        window_seconds: float = 5.0,
        db_path: str = DB_PATH,
        blocked_ips: Optional[set] = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.db_path        = db_path
        self.blocked_ips    = blocked_ips or set()

        self._aggregator = WindowAggregator()
        self._scorer     = AnomalyScorer()
        self._classifier = RiskClassifier()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyse(self) -> list[ThreatRecord]:
        """
        Full pipeline:
          1. Fetch raw rows from the sliding window
          2. Aggregate into per-IP stats
          3. Score + classify each IP
          4. Filter blocked IPs
          5. Sort by packets descending
        Returns a list of ThreatRecord, ready for JSON serialisation.
        """
        rows = fetch_window(
            window_seconds=self.window_seconds,
            path=self.db_path,
        )

        if not rows:
            return []

        per_ip_stats = self._aggregator.aggregate(rows)

        # Compute the actual observation window width (time from first to last row)
        all_timestamps = [r["timestamp"] for r in rows]
        t_min = min(all_timestamps)
        t_max = max(all_timestamps)
        observed_window = max(t_max - t_min, 1.0)   # avoid div-by-zero

        threats: list[ThreatRecord] = []

        for ip, s in per_ip_stats.items():
            if ip in self.blocked_ips:
                continue

            score  = self._scorer.score(s)
            risk   = self._classifier.classify(s.total_packets, score)

            pps    = s.total_packets / observed_window
            bps    = s.total_bytes   / observed_window

            # Deduplicate protocols and pick top 3 ports by frequency
            protocols = list(set(s.protocols)) if s.protocols else ["TCP"]
            port_freq: dict[int, int] = {}
            for p in s.ports:
                port_freq[p] = port_freq.get(p, 0) + 1
            top_ports = sorted(port_freq, key=port_freq.get, reverse=True)[:3]

            threats.append(ThreatRecord(
                ip            = ip,
                packets       = s.total_packets,
                bytes         = s.total_bytes,
                risk          = risk,
                country       = get_country(ip),
                anomaly_score = score,
                log_count     = s.log_count,
                protocols     = protocols,
                top_ports     = top_ports,
                pps           = round(pps, 1),
                bps           = round(bps, 1),
            ))

        threats.sort(key=lambda t: t.packets, reverse=True)
        return threats

    def analyse_as_dicts(self) -> list[dict]:
        """Convenience wrapper — returns dicts instead of dataclasses."""
        return [t.to_dict() for t in self.analyse()]

    # ── Summary helpers ───────────────────────────────────────────────────────

    def summary(self) -> dict:
        """
        Returns a high-level summary dict — useful for logging / monitoring.
        """
        threats = self.analyse()
        if not threats:
            return {
                "total_ips": 0,
                "total_packets": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "peak_packets": 0,
                "top_threat_ip": None,
            }

        high   = [t for t in threats if t.risk == "HIGH"]
        medium = [t for t in threats if t.risk == "MEDIUM"]
        low    = [t for t in threats if t.risk == "LOW"]

        return {
            "total_ips":       len(threats),
            "total_packets":   sum(t.packets for t in threats),
            "high_risk_count": len(high),
            "medium_risk_count": len(medium),
            "low_risk_count":  len(low),
            "peak_packets":    threats[0].packets,
            "top_threat_ip":   threats[0].ip,
        }


# ╔══════════════════════════════════════════════════════╗
# ║  CLI / STANDALONE RUN                                ║
# ╚══════════════════════════════════════════════════════╝

if __name__ == "__main__":
    """
    Run the detector once and print a report.
    Useful for manual testing:
        python detection_engine/detector.py
    """
    from database.database import init_db
    init_db()

    detector = DDoSDetector(window_seconds=5)
    threats  = detector.analyse()

    if not threats:
        print("[DETECTOR] No traffic in the last 5-second window.")
        print("           Make sure traffic_generator.py is running.")
    else:
        print(f"\n{'─'*72}")
        print(f"  SENTINEL · Detection Report   window=5s   IPs={len(threats)}")
        print(f"{'─'*72}")
        print(f"  {'IP':<18} {'PKTS':>8} {'BYTES':>10} {'RISK':<8} {'SCORE':>6}  COUNTRY")
        print(f"{'─'*72}")
        for t in threats:
            print(
                f"  {t.ip:<18} {t.packets:>8,} {t.bytes:>10,} "
                f"{t.risk:<8} {t.anomaly_score:>6.3f}  {t.country}"
            )
        print(f"{'─'*72}")
        s = detector.summary()
        print(f"  HIGH: {s['high_risk_count']}  "
              f"MEDIUM: {s['medium_risk_count']}  "
              f"LOW: {s['low_risk_count']}  "
              f"PEAK: {s['peak_packets']:,} pkts")
        print(f"{'─'*72}\n")