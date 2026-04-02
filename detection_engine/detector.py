"""
detection_engine/detector.py  ·  NETGUARD  ·  Upgraded Detection Engine
════════════════════════════════════════════════════════════════════════════════

Architecture (upgraded pipeline):

  Raw DB rows  →  WindowAggregator  →  per-IP IPStats
                        ↓
              ┌─────────────────────┐
              │  Feature Extraction │  packets, bytes, pps, bps, log_count, entropy
              └─────────────────────┘
                        ↓
         ┌──────────────┬─────────────────┬────────────────┐
         ▼              ▼                 ▼                ▼
   AnomalyScorer  AdaptiveThreshold  IsolationForest  RandomForest
   (rule-based)   (stats-based)      (unsupervised)   (supervised)
         └──────────────┴─────────────────┴────────────────┘
                        ↓
              HybridDecisionEngine  →  final risk + explanation
                        ↓
                  ThreatRecord  →  JSON  →  Frontend


NEW MODULES ADDED
─────────────────
  AdaptiveThreshold         Compute mean ± k×std from the current window
  IsolationForestDetector   Scikit-learn iForest — catches unknown attacks
  RandomForestClassifier    Scikit-learn RF — classifies NORMAL vs ATTACK
  ExplanationEngine         Builds human-readable reasons for each flag
  HybridDecisionEngine      OR-gate: any positive signal → HIGH risk

ALL existing classes (WindowAggregator, AnomalyScorer, RiskClassifier,
DDoSDetector) are UNCHANGED in interface — new fields are additive.

PARAMETER TUNING GUIDE
───────────────────────
  ADAPTIVE_K             (default 2.0)
    Controls how many standard deviations above the mean counts as anomalous.
    Lower k  → more sensitive (more false positives).
    Higher k → less sensitive (may miss subtle attacks).
    Good range: 1.5 – 3.0

  IF_CONTAMINATION       (default 0.15)
    Expected fraction of outliers in the dataset for Isolation Forest.
    Matches the approximate attack probability in the traffic generator (0.25).
    Good range: 0.05 – 0.30. Set lower if false-positive rate is high.

  IF_N_ESTIMATORS        (default 100)
    Number of trees in the Isolation Forest.
    More trees → more stable but slower. 50–200 is a good range.

  RF_N_ESTIMATORS        (default 100)
    Number of trees in the Random Forest.
    Same tradeoff as IF_N_ESTIMATORS.

  RF_ATTACK_PROB_THRESH  (default 0.55)
    Probability threshold above which RF considers traffic an ATTACK.
    Lower → more aggressive labelling.

  MIN_IPS_FOR_ML         (default 3)
    Minimum number of IPs needed in a window before ML models are trained.
    Below this count, ML output is skipped (too few samples to fit reliably).
"""

from __future__ import annotations

import os
import sys
import time
import random
import math
import statistics
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Resolve project root ──────────────────────────────────────────────────────
_ENGINE_DIR   = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_ENGINE_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.database import fetch_window, DB_PATH

# ── Optional scikit-learn import (graceful fallback if not installed) ─────────
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    print("[DETECTOR] WARNING: scikit-learn not installed. "
          "Run `pip install scikit-learn` for ML features. "
          "Rule-based detection is still active.")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CONSTANTS                                                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Rule-based thresholds (unchanged from original) ───────────────────────────
THRESHOLD_HIGH   = 5_000
THRESHOLD_MEDIUM = 2_000

WEIGHT_PACKET_RATE    = 0.40
WEIGHT_BYTE_RATE      = 0.20
WEIGHT_LOG_FREQUENCY  = 0.25
WEIGHT_ENTROPY        = 0.15

CEIL_PACKETS   = 15_000
CEIL_BYTES     = 15_000_000
CEIL_LOG_FREQ  = 500
CEIL_ENTROPY   = 4.0

# ── Adaptive threshold tuning ─────────────────────────────────────────────────
ADAPTIVE_K = 2.0          # threshold = mean + K * std

# ── Isolation Forest tuning ───────────────────────────────────────────────────
IF_CONTAMINATION  = 0.15   # expected fraction of anomalies in the dataset
IF_N_ESTIMATORS   = 100    # number of trees

# ── Random Forest tuning ──────────────────────────────────────────────────────
RF_N_ESTIMATORS        = 100   # number of trees
RF_ATTACK_PROB_THRESH  = 0.55  # probability above which → ATTACK label

# ── Minimum window population for ML to activate ─────────────────────────────
MIN_IPS_FOR_ML = 3

# ── Geo simulation ────────────────────────────────────────────────────────────
_GEO_CACHE: dict[str, str] = {}
COUNTRIES = [
    "India", "China", "Russia", "United States", "Brazil",
    "Germany", "Ukraine", "South Korea", "Vietnam", "Nigeria",
    "Iran", "Pakistan", "Indonesia", "France", "United Kingdom",
    "Netherlands", "Romania", "Turkey", "Thailand", "Bangladesh",
]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  DATA STRUCTURES                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class IPStats:
    """Aggregated statistics for one source IP within the analysis window."""
    source_ip:     str
    total_packets: int   = 0
    total_bytes:   int   = 0
    log_count:     int   = 0
    dest_ips:      list  = field(default_factory=list)
    protocols:     list  = field(default_factory=list)
    ports:         list  = field(default_factory=list)
    first_seen:    float = 0.0
    last_seen:     float = 0.0


@dataclass
class ThreatRecord:
    """
    One fully-enriched record returned by DDoSDetector.analyse().

    New fields added (all additive — existing API is unchanged):
      adaptive_score   float      stats-based anomaly score (0.0–1.0)
      adaptive_risk    str        LOW|MEDIUM|HIGH from adaptive logic
      if_label         str        NORMAL|ANOMALY from Isolation Forest
      if_score         float      IF raw score (more negative = more anomalous)
      rf_prediction    str        NORMAL|ATTACK from Random Forest
      rf_probability   float      RF confidence for ATTACK class (0.0–1.0)
      explanation      list[str]  human-readable reasons for the flag
      final_risk       str        final decision from HybridDecisionEngine
    """
    # ── original fields (unchanged) ───────────────────────────────────────────
    ip:            str
    packets:       int
    bytes:         int
    risk:          str        # rule-based risk (backward-compatible)
    country:       str
    anomaly_score: float
    log_count:     int
    protocols:     list
    top_ports:     list
    pps:           float
    bps:           float

    # ── new fields from upgraded engine ──────────────────────────────────────
    adaptive_score:  float      = 0.0
    adaptive_risk:   str        = "LOW"
    if_label:        str        = "N/A"
    if_score:        float      = 0.0
    rf_prediction:   str        = "N/A"
    rf_probability:  float      = 0.0
    explanation:     list       = field(default_factory=list)
    final_risk:      str        = "LOW"   # ← authoritative combined decision

    def to_dict(self) -> dict:
        return asdict(self)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  WINDOW AGGREGATOR  (unchanged)                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class WindowAggregator:
    """
    Collapses raw DB rows into per-IP IPStats objects.
    Completely unchanged from the original — documented here for completeness.
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


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  ANOMALY SCORER  (unchanged)                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class AnomalyScorer:
    """
    Composite rule-based anomaly score in [0.0, 1.0].
    Unchanged — still used as Signal 1 in the hybrid decision gate.

    Signals: packet rate (40%) · byte rate (20%) · log freq (25%) · dest entropy (15%)
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
        sig_packets = min(s.total_packets / CEIL_PACKETS, 1.0)
        sig_bytes   = min(s.total_bytes   / CEIL_BYTES,   1.0)
        sig_freq    = min(s.log_count     / CEIL_LOG_FREQ, 1.0)
        entropy     = cls._shannon_entropy(s.dest_ips)
        sig_entropy = 1.0 - min(entropy / CEIL_ENTROPY, 1.0)

        composite = (
            WEIGHT_PACKET_RATE   * sig_packets +
            WEIGHT_BYTE_RATE     * sig_bytes   +
            WEIGHT_LOG_FREQUENCY * sig_freq    +
            WEIGHT_ENTROPY       * sig_entropy
        )
        return round(min(composite, 1.0), 3)

    @classmethod
    def entropy_for(cls, s: IPStats) -> float:
        """Expose entropy separately so AdaptiveThreshold can use it."""
        return cls._shannon_entropy(s.dest_ips)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  RISK CLASSIFIER  (unchanged)                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class RiskClassifier:
    """
    Maps raw packet count + anomaly_score → risk label.
    Unchanged from original. Used for the backward-compatible `risk` field.
    """

    @staticmethod
    def classify(packets: int, anomaly_score: float) -> str:
        if packets > THRESHOLD_HIGH:
            return "HIGH"
        if packets >= THRESHOLD_MEDIUM:
            if anomaly_score >= 0.85:
                return "HIGH"
            return "MEDIUM"
        return "LOW"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NEW: ADAPTIVE THRESHOLD                                                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class AdaptiveThreshold:
    """
    Computes per-metric thresholds from the CURRENT window's distribution.

    Why this matters
    ────────────────
    Static thresholds (e.g. > 5 000 packets = HIGH) assume the network is
    always at baseline. But if ALL hosts are sending 8 000 packets (e.g. during
    a legitimate event), a static threshold mislabels everyone as HIGH.

    Adaptive logic instead asks: "Is this IP unusual relative to its peers
    right now?" An IP sending 8 000 packets when the average is 7 800 (std=200)
    is NOT anomalous; one sending 8 000 when the average is 300 (std=100) IS.

    Formula
    ───────
      threshold_i = mean_i + ADAPTIVE_K × std_i

    where i ∈ {packets, bytes, entropy}
    and ADAPTIVE_K is the sensitivity constant (default 2.0).

    Score output
    ────────────
    0.0 = at or below mean (completely normal)
    0.5 = at the threshold boundary (mean + K×std)
    1.0 = 2× above the threshold (capped)

    Each metric contributes equally (1/3 weight each).
    """

    def __init__(self, k: float = ADAPTIVE_K) -> None:
        self.k = k

    def compute(
        self,
        all_stats: list[IPStats],
        scorer: AnomalyScorer,
    ) -> dict[str, dict]:
        """
        Compute mean, std, and threshold for each metric across all IPs.

        Returns a dict keyed by metric name, each containing:
            mean, std, threshold
        """
        if len(all_stats) < 2:
            # Cannot compute std with fewer than 2 samples
            return {}

        packets_list = [s.total_packets for s in all_stats]
        bytes_list   = [s.total_bytes   for s in all_stats]
        entropy_list = [scorer.entropy_for(s) for s in all_stats]

        def _stats(lst):
            m = statistics.mean(lst)
            sd = statistics.stdev(lst) if len(lst) > 1 else 0.0
            return m, sd, m + self.k * sd

        p_mean, p_std, p_thresh = _stats(packets_list)
        b_mean, b_std, b_thresh = _stats(bytes_list)
        e_mean, e_std, e_thresh = _stats(entropy_list)

        return {
            "packets": {"mean": p_mean, "std": p_std, "threshold": p_thresh},
            "bytes":   {"mean": b_mean, "std": b_std, "threshold": b_thresh},
            "entropy": {"mean": e_mean, "std": e_std, "threshold": e_thresh},
        }

    def score_ip(
        self,
        s: IPStats,
        thresholds: dict,
        scorer: AnomalyScorer,
    ) -> tuple[float, str]:
        """
        Score a single IP against the pre-computed adaptive thresholds.

        Returns
        ───────
        (adaptive_score, adaptive_risk)
          adaptive_score ∈ [0.0, 1.0]
          adaptive_risk  ∈ {"LOW", "MEDIUM", "HIGH"}
        """
        if not thresholds:
            return 0.0, "LOW"

        def _norm(value, threshold, mean):
            """
            Normalise value relative to threshold.
              value ≤ mean      → 0.0 (well below threshold)
              value = threshold → 0.5
              value ≥ 2×thresh  → 1.0 (capped)
            """
            if threshold <= mean:
                return 0.0
            ratio = (value - mean) / (threshold - mean)
            return min(max(ratio * 0.5, 0.0), 1.0)

        entropy = scorer.entropy_for(s)

        p_score = _norm(
            s.total_packets,
            thresholds["packets"]["threshold"],
            thresholds["packets"]["mean"],
        )
        b_score = _norm(
            s.total_bytes,
            thresholds["bytes"]["threshold"],
            thresholds["bytes"]["mean"],
        )
        # Entropy is INVERTED: LOW entropy == anomalous (flood hits same target)
        # So we compare the threshold against the negative-entropy contribution
        e_inv_value  = CEIL_ENTROPY - entropy          # high when entropy is low
        e_inv_thresh = CEIL_ENTROPY - thresholds["entropy"]["threshold"]
        e_inv_mean   = CEIL_ENTROPY - thresholds["entropy"]["mean"]
        e_score = _norm(e_inv_value, e_inv_thresh, e_inv_mean) if e_inv_thresh > e_inv_mean else 0.0

        # Equal weight to all three adaptive signals
        adaptive_score = round((p_score + b_score + e_score) / 3.0, 3)

        if adaptive_score >= 0.65:
            adaptive_risk = "HIGH"
        elif adaptive_score >= 0.35:
            adaptive_risk = "MEDIUM"
        else:
            adaptive_risk = "LOW"

        return adaptive_score, adaptive_risk


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NEW: ISOLATION FOREST DETECTOR                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class IsolationForestDetector:
    """
    Detects UNKNOWN / zero-day anomalies using Isolation Forest.

    Why Isolation Forest?
    ─────────────────────
    Random Forests and rule-based systems only catch what they've been trained/
    tuned for. Isolation Forest is UNSUPERVISED — it learns the structure of
    normal data by asking "how easy is it to isolate this point?".
    Anomalous points (DDoS sources) are far from normal clusters and get
    isolated in fewer splits, giving them a LOW anomaly score (sklearn convention:
    negative = outlier, near zero = inlier).

    Training strategy
    ─────────────────
    The model is RETRAINED on every detection cycle using the current 5-second
    window. This means:
      • No labelled training data needed
      • The model adapts to the current baseline
      • Attack IPs that are numerically extreme will be flagged as outliers
    The downside is that if ALL IPs in the window are attackers, none appear
    anomalous (they form a cluster). This is mitigated by the other signals.

    Feature vector per IP (6 features):
      [packets, bytes, pps, bps, log_count, dest_entropy]
    """

    def __init__(
        self,
        n_estimators: int   = IF_N_ESTIMATORS,
        contamination: float = IF_CONTAMINATION,
    ) -> None:
        self.n_estimators  = n_estimators
        self.contamination = contamination
        self._model: Optional[object] = None

    def _build_feature_matrix(
        self,
        all_stats: list[IPStats],
        scorer: AnomalyScorer,
        observed_window: float,
    ) -> list[list[float]]:
        """Build a 2-D feature matrix: one row per IP, six features per row."""
        matrix = []
        for s in all_stats:
            pps     = s.total_packets / observed_window
            bps     = s.total_bytes   / observed_window
            entropy = scorer.entropy_for(s)
            matrix.append([
                float(s.total_packets),
                float(s.total_bytes),
                pps,
                bps,
                float(s.log_count),
                entropy,
            ])
        return matrix

    def fit_predict(
        self,
        all_stats: list[IPStats],
        scorer: AnomalyScorer,
        observed_window: float,
    ) -> dict[str, tuple[str, float]]:
        """
        Fit the model on the current window and predict each IP.

        Returns
        ───────
        dict mapping source_ip → (label, raw_score)
          label      : "ANOMALY" | "NORMAL"
          raw_score  : sklearn decision_function score
                       (negative → anomalous, near 0 → normal)
        """
        if not _SKLEARN_AVAILABLE or len(all_stats) < MIN_IPS_FOR_ML:
            return {s.source_ip: ("N/A", 0.0) for s in all_stats}

        X = self._build_feature_matrix(all_stats, scorer, observed_window)

        # Cap contamination: can't exceed (n_samples - 1) / n_samples
        cap = (len(X) - 1) / len(X) if len(X) > 1 else 0.5
        contamination = min(self.contamination, cap)

        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=contamination,
            random_state=42,       # deterministic results
            n_jobs=-1,             # use all CPU cores
        )
        model.fit(X)

        # sklearn: predict returns 1 (inlier) or -1 (outlier)
        predictions   = model.predict(X)
        # decision_function: more negative = more anomalous
        decision_scores = model.decision_function(X)

        result = {}
        for i, s in enumerate(all_stats):
            label      = "ANOMALY" if predictions[i] == -1 else "NORMAL"
            raw_score  = round(float(decision_scores[i]), 4)
            result[s.source_ip] = (label, raw_score)

        return result


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NEW: RANDOM FOREST CLASSIFIER                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class RandomForestModule:
    """
    Classifies traffic as NORMAL vs ATTACK using a Random Forest.

    Why Random Forest?
    ──────────────────
    Random Forest is an ensemble of decision trees. Each tree votes on the
    label, and the majority wins. This gives:
      • High accuracy with diverse features
      • Robustness to noise (trees average out errors)
      • Built-in feature importance (useful for explanation)

    Label generation (self-supervised bootstrapping)
    ────────────────────────────────────────────────
    We don't have a pre-labelled dataset. Instead we use the rule-based
    anomaly_score to GENERATE initial labels:
      anomaly_score >= 0.5  →  ATTACK  (1)
      anomaly_score <  0.5  →  NORMAL  (0)

    This is a common bootstrapping technique for operational systems:
    the rule-based system provides weak labels, and the RF learns to
    generalise — often catching attacks the rules miss. Over time, analyst
    feedback (block/unblock) can replace these auto-labels.

    Training strategy
    ─────────────────
    The model is retrained on the current 5-second window each cycle.
    If the window has no variation in labels (all NORMAL or all ATTACK),
    training is skipped and the fallback ("N/A") is returned.

    Feature vector (same 6 features as Isolation Forest):
      [packets, bytes, pps, bps, log_count, dest_entropy]
    """

    def __init__(
        self,
        n_estimators: int       = RF_N_ESTIMATORS,
        attack_prob_thresh: float = RF_ATTACK_PROB_THRESH,
    ) -> None:
        self.n_estimators       = n_estimators
        self.attack_prob_thresh = attack_prob_thresh

    def _build_features_and_labels(
        self,
        all_stats: list[IPStats],
        anomaly_scores: dict[str, float],
        scorer: AnomalyScorer,
        observed_window: float,
    ) -> tuple[list[list[float]], list[int]]:
        X, y = [], []
        for s in all_stats:
            pps     = s.total_packets / observed_window
            bps     = s.total_bytes   / observed_window
            entropy = scorer.entropy_for(s)
            X.append([
                float(s.total_packets),
                float(s.total_bytes),
                pps,
                bps,
                float(s.log_count),
                entropy,
            ])
            # Bootstrapped label from rule-based anomaly_score
            label = 1 if anomaly_scores.get(s.source_ip, 0.0) >= 0.5 else 0
            y.append(label)
        return X, y

    def fit_predict(
        self,
        all_stats: list[IPStats],
        anomaly_scores: dict[str, float],
        scorer: AnomalyScorer,
        observed_window: float,
    ) -> dict[str, tuple[str, float]]:
        """
        Train on the current window and predict each IP.

        Returns
        ───────
        dict mapping source_ip → (prediction, probability)
          prediction  : "ATTACK" | "NORMAL" | "N/A"
          probability : RF confidence for ATTACK class (0.0–1.0)
        """
        if not _SKLEARN_AVAILABLE or len(all_stats) < MIN_IPS_FOR_ML:
            return {s.source_ip: ("N/A", 0.0) for s in all_stats}

        X, y = self._build_features_and_labels(
            all_stats, anomaly_scores, scorer, observed_window
        )

        # Skip training if all labels are identical (no discriminative signal)
        if len(set(y)) < 2:
            return {s.source_ip: ("N/A", 0.0) for s in all_stats}

        model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",  # handle imbalanced attack/normal ratios
        )
        model.fit(X, y)

        probas = model.predict_proba(X)
        # Class order: [0=NORMAL, 1=ATTACK]
        attack_col = list(model.classes_).index(1) if 1 in model.classes_ else 1

        result = {}
        for i, s in enumerate(all_stats):
            attack_prob = round(float(probas[i][attack_col]), 3)
            prediction  = "ATTACK" if attack_prob >= self.attack_prob_thresh else "NORMAL"
            result[s.source_ip] = (prediction, attack_prob)

        return result


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NEW: EXPLANATION ENGINE                                                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class ExplanationEngine:
    """
    Generates human-readable explanations for why an IP was flagged.

    Each triggered condition produces one explanation string.
    The resulting list is attached to ThreatRecord.explanation and
    returned to the frontend as JSON for potential display in the UI.

    Example output for a HIGH-risk IP:
      [
        "Packet count (8420) exceeds adaptive threshold (6100) — 38% above normal peers",
        "Rule-based anomaly score (0.812) is HIGH — packet volume and low entropy",
        "Isolation Forest classified this IP as ANOMALY (score: -0.243)",
        "Random Forest predicted ATTACK with 89.2% confidence",
        "Low destination entropy — traffic concentrated on a single target (DDoS pattern)",
        "Hybrid engine: multiple signals agree → final classification HIGH"
      ]
    """

    @staticmethod
    def explain(
        s: IPStats,
        anomaly_score: float,
        rule_risk: str,
        adaptive_score: float,
        adaptive_risk: str,
        thresholds: dict,
        if_label: str,
        if_score: float,
        rf_prediction: str,
        rf_probability: float,
        final_risk: str,
        scorer: AnomalyScorer,
    ) -> list[str]:
        reasons = []

        # ── Rule-based signal ─────────────────────────────────────────────────
        if rule_risk == "HIGH":
            reasons.append(
                f"Rule-based: packet count ({s.total_packets:,}) exceeds HIGH threshold "
                f"({THRESHOLD_HIGH:,}). Anomaly score: {anomaly_score:.3f}."
            )
        elif rule_risk == "MEDIUM":
            reasons.append(
                f"Rule-based: packet count ({s.total_packets:,}) in MEDIUM range "
                f"({THRESHOLD_MEDIUM:,}–{THRESHOLD_HIGH:,}). Anomaly score: {anomaly_score:.3f}."
            )
        elif anomaly_score >= 0.5:
            reasons.append(
                f"Rule-based anomaly score elevated ({anomaly_score:.3f}) despite low packet count. "
                f"Possible low-volume flood."
            )

        # ── Adaptive threshold signal ─────────────────────────────────────────
        if thresholds and "packets" in thresholds:
            p_thresh = thresholds["packets"]["threshold"]
            p_mean   = thresholds["packets"]["mean"]
            if s.total_packets > p_thresh:
                pct_above = int(((s.total_packets - p_thresh) / max(p_thresh, 1)) * 100)
                reasons.append(
                    f"Adaptive threshold: packets ({s.total_packets:,}) exceeds "
                    f"mean+{ADAPTIVE_K}σ threshold ({p_thresh:,.0f}, "
                    f"mean={p_mean:,.0f}) — {pct_above}% above adaptive limit."
                )
            if "bytes" in thresholds:
                b_thresh = thresholds["bytes"]["threshold"]
                if s.total_bytes > b_thresh:
                    reasons.append(
                        f"Adaptive threshold: byte volume ({s.total_bytes:,} B) exceeds "
                        f"adaptive limit ({b_thresh:,.0f} B)."
                    )

        # ── Entropy signal ────────────────────────────────────────────────────
        entropy = scorer.entropy_for(s)
        if entropy < 0.5:
            reasons.append(
                f"Very low destination entropy ({entropy:.3f} bits) — all traffic targeting "
                f"a single destination. Classic DDoS flood pattern."
            )
        elif entropy < 1.0:
            reasons.append(
                f"Low destination entropy ({entropy:.3f} bits) — traffic concentrated on "
                f"few destinations."
            )

        # ── Isolation Forest signal ───────────────────────────────────────────
        if if_label == "ANOMALY":
            reasons.append(
                f"Isolation Forest: classified as ANOMALY (decision score: {if_score:.4f}). "
                f"This IP is statistically isolated from normal traffic peers."
            )
        elif if_label == "NORMAL":
            reasons.append(
                f"Isolation Forest: classified as NORMAL (score: {if_score:.4f})."
            )

        # ── Random Forest signal ──────────────────────────────────────────────
        if rf_prediction == "ATTACK":
            reasons.append(
                f"Random Forest: predicted ATTACK with {rf_probability*100:.1f}% confidence."
            )
        elif rf_prediction == "NORMAL":
            reasons.append(
                f"Random Forest: predicted NORMAL ({(1-rf_probability)*100:.1f}% confidence)."
            )

        # ── Protocol / port signals ───────────────────────────────────────────
        if set(s.protocols) == {"TCP"} and s.log_count > 10:
            reasons.append(
                f"Single protocol (TCP only) across {s.log_count} log events — "
                f"consistent with SYN flood."
            )

        # ── Hybrid summary ────────────────────────────────────────────────────
        if final_risk == "HIGH":
            reasons.append(
                "Hybrid engine: one or more signals flagged HIGH → "
                "final classification: HIGH RISK."
            )
        elif final_risk == "MEDIUM":
            reasons.append(
                "Hybrid engine: moderate signals only → "
                "final classification: MEDIUM RISK."
            )
        else:
            reasons.append("Hybrid engine: all signals within normal range → LOW RISK.")

        return reasons


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NEW: HYBRID DECISION ENGINE                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class HybridDecisionEngine:
    """
    OR-gate combinator: if ANY signal fires HIGH, the final decision is HIGH.

    Rationale
    ─────────
    Each detection signal has different strengths and blind spots:
      • Rule-based     — fast, interpretable, but rigid
      • Adaptive       — context-aware, but can miss if all hosts are attacked
      • Isolation Forest — catches outliers including unknown attacks
      • Random Forest  — accurate for known patterns, trained on current data

    Combining them with an OR-gate maximises recall (we catch more attacks)
    at the cost of potentially higher false-positive rate. For a DDoS dashboard,
    missing an attack is more costly than an extra flag — so OR-gate is correct.

    Final risk levels:
      HIGH   — any signal fires HIGH / ANOMALY / ATTACK
      MEDIUM — any signal is MEDIUM but none are HIGH
      LOW    — all signals are LOW / NORMAL
    """

    @staticmethod
    def decide(
        rule_risk:      str,
        adaptive_risk:  str,
        if_label:       str,
        rf_prediction:  str,
    ) -> str:
        # HIGH if any signal is HIGH/ANOMALY/ATTACK
        high_conditions = [
            rule_risk     == "HIGH",
            adaptive_risk == "HIGH",
            if_label      == "ANOMALY",
            rf_prediction == "ATTACK",
        ]
        if any(high_conditions):
            return "HIGH"

        # MEDIUM if any signal is MEDIUM and none are HIGH
        medium_conditions = [
            rule_risk     == "MEDIUM",
            adaptive_risk == "MEDIUM",
        ]
        if any(medium_conditions):
            return "MEDIUM"

        return "LOW"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  GEO LOOKUP  (unchanged)                                                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def get_country(ip: str) -> str:
    if ip not in _GEO_CACHE:
        rng = random.Random(ip)
        _GEO_CACHE[ip] = rng.choice(COUNTRIES)
    return _GEO_CACHE[ip]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MAIN DETECTOR  (upgraded — backward-compatible interface)                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class DDoSDetector:
    """
    Orchestrates the FULL upgraded detection pipeline.

    Public interface is IDENTICAL to the original. New fields in ThreatRecord
    are additive — the frontend will receive them but can ignore unknown keys.

    Pipeline per call
    ─────────────────
      1.  fetch_window()              → raw DB rows
      2.  WindowAggregator.aggregate  → per-IP IPStats
      3.  AnomalyScorer.score         → rule-based anomaly_score per IP
      4.  AdaptiveThreshold.compute   → window-level mean/std/threshold
          AdaptiveThreshold.score_ip  → adaptive_score per IP
      5.  IsolationForestDetector     → trained + predicted on window
      6.  RandomForestModule          → trained + predicted on window
      7.  HybridDecisionEngine.decide → final_risk per IP
      8.  ExplanationEngine.explain   → reasons list per IP
      9.  Assemble ThreatRecord list, sort by packets desc
    """

    def __init__(
        self,
        window_seconds: float = 5.0,
        db_path: str          = DB_PATH,
        blocked_ips: Optional[set] = None,
        adaptive_k: float          = ADAPTIVE_K,
        if_contamination: float    = IF_CONTAMINATION,
        if_n_estimators: int       = IF_N_ESTIMATORS,
        rf_n_estimators: int       = RF_N_ESTIMATORS,
        rf_attack_prob_thresh: float = RF_ATTACK_PROB_THRESH,
    ) -> None:
        self.window_seconds = window_seconds
        self.db_path        = db_path
        self.blocked_ips    = blocked_ips or set()

        # Instantiate all pipeline components
        self._aggregator   = WindowAggregator()
        self._scorer       = AnomalyScorer()
        self._classifier   = RiskClassifier()
        self._adaptive     = AdaptiveThreshold(k=adaptive_k)
        self._if_detector  = IsolationForestDetector(
                                n_estimators=if_n_estimators,
                                contamination=if_contamination,
                             )
        self._rf_module    = RandomForestModule(
                                n_estimators=rf_n_estimators,
                                attack_prob_thresh=rf_attack_prob_thresh,
                             )
        self._hybrid       = HybridDecisionEngine()
        self._explainer    = ExplanationEngine()

    # ── Public API (unchanged signatures) ────────────────────────────────────

    def analyse(self) -> list[ThreatRecord]:
        """
        Run the full upgraded pipeline and return enriched ThreatRecords.
        All new fields are populated; `risk` is preserved for backward compat.
        """
        rows = fetch_window(window_seconds=self.window_seconds, path=self.db_path)
        if not rows:
            return []

        # ── Step 1: Aggregate raw rows into per-IP stats ─────────────────────
        per_ip_stats = self._aggregator.aggregate(rows)

        all_timestamps  = [r["timestamp"] for r in rows]
        observed_window = max(max(all_timestamps) - min(all_timestamps), 1.0)

        # Filter blocked IPs before any ML (saves compute)
        active_stats: list[IPStats] = [
            s for ip, s in per_ip_stats.items()
            if ip not in self.blocked_ips
        ]

        if not active_stats:
            return []

        # ── Step 2: Rule-based anomaly score for every IP ────────────────────
        rule_scores: dict[str, float] = {
            s.source_ip: self._scorer.score(s)
            for s in active_stats
        }

        # ── Step 3: Adaptive thresholds (window-level computation) ───────────
        thresholds = self._adaptive.compute(active_stats, self._scorer)

        # ── Step 4: Isolation Forest (single fit, all IPs) ───────────────────
        if_results = self._if_detector.fit_predict(
            active_stats, self._scorer, observed_window
        )

        # ── Step 5: Random Forest (single fit, all IPs) ──────────────────────
        rf_results = self._rf_module.fit_predict(
            active_stats, rule_scores, self._scorer, observed_window
        )

        # ── Step 6: Assemble ThreatRecords ───────────────────────────────────
        threats: list[ThreatRecord] = []

        for s in active_stats:
            ip            = s.source_ip
            anomaly_score = rule_scores[ip]
            rule_risk     = self._classifier.classify(s.total_packets, anomaly_score)

            # Adaptive
            adaptive_score, adaptive_risk = self._adaptive.score_ip(
                s, thresholds, self._scorer
            )

            # Isolation Forest
            if_label, if_score = if_results.get(ip, ("N/A", 0.0))

            # Random Forest
            rf_prediction, rf_probability = rf_results.get(ip, ("N/A", 0.0))

            # Hybrid final decision
            final_risk = self._hybrid.decide(
                rule_risk, adaptive_risk, if_label, rf_prediction
            )

            # Explanation
            explanation = self._explainer.explain(
                s, anomaly_score, rule_risk,
                adaptive_score, adaptive_risk,
                thresholds, if_label, if_score,
                rf_prediction, rf_probability,
                final_risk, self._scorer,
            )

            # Derive utility fields
            pps = s.total_packets / observed_window
            bps = s.total_bytes   / observed_window

            protocols = list(set(s.protocols)) if s.protocols else ["TCP"]
            port_freq: dict[int, int] = {}
            for p in s.ports:
                port_freq[p] = port_freq.get(p, 0) + 1
            top_ports = sorted(port_freq, key=port_freq.get, reverse=True)[:3]

            threats.append(ThreatRecord(
                ip             = ip,
                packets        = s.total_packets,
                bytes          = s.total_bytes,
                risk           = final_risk,      # upgraded: final_risk drives `risk`
                country        = get_country(ip),
                anomaly_score  = anomaly_score,
                log_count      = s.log_count,
                protocols      = protocols,
                top_ports      = top_ports,
                pps            = round(pps, 1),
                bps            = round(bps, 1),
                # ── new fields ────────────────────────────────────────────
                adaptive_score  = adaptive_score,
                adaptive_risk   = adaptive_risk,
                if_label        = if_label,
                if_score        = if_score,
                rf_prediction   = rf_prediction,
                rf_probability  = rf_probability,
                explanation     = explanation,
                final_risk      = final_risk,
            ))

        threats.sort(key=lambda t: t.packets, reverse=True)
        return threats

    def analyse_as_dicts(self) -> list[dict]:
        """Convenience wrapper — returns plain dicts instead of dataclasses."""
        return [t.to_dict() for t in self.analyse()]

    def summary(self) -> dict:
        """High-level stats dict — interface unchanged from original."""
        threats = self.analyse()
        if not threats:
            return {
                "total_ips": 0, "total_packets": 0,
                "high_risk_count": 0, "medium_risk_count": 0,
                "low_risk_count": 0, "peak_packets": 0,
                "top_threat_ip": None,
            }
        high   = [t for t in threats if t.final_risk == "HIGH"]
        medium = [t for t in threats if t.final_risk == "MEDIUM"]
        low    = [t for t in threats if t.final_risk == "LOW"]
        return {
            "total_ips":         len(threats),
            "total_packets":     sum(t.packets for t in threats),
            "high_risk_count":   len(high),
            "medium_risk_count": len(medium),
            "low_risk_count":    len(low),
            "peak_packets":      threats[0].packets,
            "top_threat_ip":     threats[0].ip,
        }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CLI / STANDALONE RUN                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    """
    Run the upgraded detector once and print a detailed report.
    Make sure traffic_generator.py is running in another terminal first.

        python detection_engine/detector.py
    """
    from database.database import init_db
    init_db()

    print("\n" + "═" * 80)
    print("  NETGUARD · Upgraded Detection Engine  ·  Test Run")
    print("═" * 80)
    print(f"  sklearn available : {_SKLEARN_AVAILABLE}")
    print(f"  Adaptive K        : {ADAPTIVE_K}")
    print(f"  IF contamination  : {IF_CONTAMINATION}")
    print(f"  RF n_estimators   : {RF_N_ESTIMATORS}")
    print("═" * 80)

    detector = DDoSDetector(window_seconds=5)
    threats  = detector.analyse()

    if not threats:
        print("\n  No traffic in the last 5-second window.")
        print("  Start traffic_generator.py first.\n")
    else:
        print(f"\n  {'IP':<18} {'PKTS':>7} {'RULE':<7} {'ADPT':<7} "
              f"{'IF':<8} {'RF':<8} {'PROB':>5}  FINAL")
        print(f"  {'─'*78}")
        for t in threats:
            print(
                f"  {t.ip:<18} {t.packets:>7,} {t.risk:<7} {t.adaptive_risk:<7} "
                f"{t.if_label:<8} {t.rf_prediction:<8} {t.rf_probability:>5.2f}  "
                f"{'*** '+t.final_risk+' ***' if t.final_risk == 'HIGH' else t.final_risk}"
            )

        print(f"\n  {'─'*78}")
        s = detector.summary()
        print(f"  HIGH: {s['high_risk_count']}  MEDIUM: {s['medium_risk_count']}  "
              f"LOW: {s['low_risk_count']}  TOTAL IPs: {s['total_ips']}")

        # Print full explanation for the top threat
        top = threats[0]
        print(f"\n  EXPLANATION FOR TOP THREAT  →  {top.ip}")
        print(f"  {'─'*78}")
        for line in top.explanation:
            print(f"    • {line}")
        print("═" * 80 + "\n")