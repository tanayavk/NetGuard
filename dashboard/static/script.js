/**
 * NETGUARD · SOC Dashboard — script.js (upgraded)
 *
 * New sections powered by upgraded detector.py:
 *   • Adaptive Threshold panel  — per-metric bars with mean/threshold markers
 *   • Isolation Forest panel    — doughnut gauge + per-IP label list
 *   • Random Forest panel       — summary counters + per-IP confidence bars
 *   • Explainability panel      — click a table row → AI reasoning list
 *   • Hybrid Decision panel     — per-signal OR-gate breakdown
 *
 * All original behaviour (polling, charts, alerts, block) is untouched.
 */

"use strict";

// ── Config ────────────────────────────────────────────────────────────────
const POLL_INTERVAL    = 3000;
const MAX_TREND_POINTS = 30;
const MAX_ALERTS       = 50;

// ── State ─────────────────────────────────────────────────────────────────
let trendLabels   = [];
let trendValues   = [];
let alertHistory  = [];
let knownHighIPs  = new Set();
let blockedIPs    = new Set();
let selectedIP    = null;       // IP whose explanation is currently shown
let lastData      = [];         // most recent /data payload (for re-render on click)

// ── DOM refs — original ───────────────────────────────────────────────────
const $statTotal    = document.getElementById("statTotal");
const $statIPs      = document.getElementById("statIPs");
const $statHigh     = document.getElementById("statHigh");
const $statPeak     = document.getElementById("statPeak");
const $tableBody    = document.getElementById("tableBody");
const $ipCount      = document.getElementById("ipCount");
const $alertFeed    = document.getElementById("alertFeed");
const $alertCount   = document.getElementById("alertCount");
const $blockedList  = document.getElementById("blockedList");
const $blockedCount = document.getElementById("blockedCount");
const $statusDot    = document.getElementById("statusDot");
const $statusLabel  = document.getElementById("statusLabel");
const $clock        = document.getElementById("clock");

// ── DOM refs — ML panels ──────────────────────────────────────────────────
const $adaptiveIPList  = document.getElementById("adaptiveIPList");
const $ifIPList        = document.getElementById("ifIPList");
const $ifAnomalyCount  = document.getElementById("ifAnomalyCount");
const $rfIPList        = document.getElementById("rfIPList");
const $rfAttackCount   = document.getElementById("rfAttackCount");
const $rfNormalCount   = document.getElementById("rfNormalCount");
const $rfNACount       = document.getElementById("rfNACount");
const $explainBody     = document.getElementById("explainBody");
const $explainIPBadge  = document.getElementById("explainIPBadge");
const $hybridSignals   = document.getElementById("hybridSignals");
const $hybridBadge     = document.getElementById("hybridBadge");

// ── Clock ─────────────────────────────────────────────────────────────────
function tickClock() {
  const now = new Date();
  $clock.textContent =
    String(now.getHours()).padStart(2,"0") + ":" +
    String(now.getMinutes()).padStart(2,"0") + ":" +
    String(now.getSeconds()).padStart(2,"0");
}
setInterval(tickClock, 1000);
tickClock();

// ── Chart setup — original ────────────────────────────────────────────────
Chart.defaults.color       = "#a8c7dd";
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size   = 11;

const lineCtx   = document.getElementById("lineChart").getContext("2d");
const lineChart = new Chart(lineCtx, {
  type: "line",
  data: {
    labels: trendLabels,
    datasets: [{
      label: "Total Packets",
      data: trendValues,
      borderColor: "#00e5ff",
      backgroundColor: "rgba(0,229,255,0.06)",
      borderWidth: 1.5,
      pointRadius: 2,
      pointBackgroundColor: "#00e5ff",
      tension: 0.4,
      fill: true,
    }],
  },
  options: {
    responsive: true,
    animation: { duration: 400 },
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: "#1e2d3d" }, ticks: { maxRotation: 0, maxTicksLimit: 6 } },
      y: { grid: { color: "#1e2d3d" }, beginAtZero: true },
    },
  },
});

const barCtx   = document.getElementById("barChart").getContext("2d");
const barChart = new Chart(barCtx, {
  type: "bar",
  data: {
    labels: [],
    datasets: [{
      label: "Packets",
      data: [],
      backgroundColor: [],
      borderRadius: 2,
      borderWidth: 0,
    }],
  },
  options: {
    responsive: true,
    animation: { duration: 400 },
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: "#1e2d3d" }, ticks: { maxRotation: 45 } },
      y: { grid: { color: "#1e2d3d" }, beginAtZero: true },
    },
  },
});

// ── Isolation Forest doughnut gauge ───────────────────────────────────────
const ifGaugeCtx   = document.getElementById("ifGaugeChart").getContext("2d");
const ifGaugeChart = new Chart(ifGaugeCtx, {
  type: "doughnut",
  data: {
    labels: ["ANOMALY", "NORMAL", "N/A"],
    datasets: [{
      data: [0, 0, 1],
      backgroundColor: [
        "rgba(255,45,85,0.75)",
        "rgba(57,255,138,0.65)",
        "rgba(30,45,61,0.6)",
      ],
      borderWidth: 0,
      hoverOffset: 3,
    }],
  },
  options: {
    responsive: true,
    cutout: "68%",
    animation: { duration: 500 },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: ctx => ` ${ctx.label}: ${ctx.raw}`,
        },
      },
    },
  },
});

// ── Helpers — original ────────────────────────────────────────────────────
function riskClass(risk) {
  return risk === "HIGH" ? "high" : risk === "MEDIUM" ? "medium" : "low";
}

function barColor(risk) {
  if (risk === "HIGH")   return "rgba(255,45,85,0.75)";
  if (risk === "MEDIUM") return "rgba(255,179,0,0.75)";
  return "rgba(57,255,138,0.65)";
}

function flashEl(el) {
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}

function nowLabel() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`;
}

function setStatus(live) {
  if (live) {
    $statusDot.classList.add("live");
    $statusLabel.textContent = "LIVE";
    $statusLabel.style.color = "var(--green)";
  } else {
    $statusDot.classList.remove("live");
    $statusLabel.textContent = "OFFLINE";
    $statusLabel.style.color = "var(--red)";
  }
}

function setTextAndFlash(el, value) {
  if (el.textContent !== String(value)) {
    el.textContent = value;
    flashEl(el);
  }
}

// ── Block IP ──────────────────────────────────────────────────────────────
async function blockIP(ip) {
  try {
    const res = await fetch("/block", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    if (res.ok) {
      blockedIPs.add(ip);
      renderBlockedList();
      if (selectedIP === ip) clearExplain();
    }
  } catch (err) {
    console.error("Block failed:", err);
  }
}

function renderBlockedList() {
  if (blockedIPs.size === 0) {
    $blockedList.innerHTML = '<li class="alert-placeholder">No IPs blocked…</li>';
    $blockedCount.textContent = "0";
    return;
  }
  $blockedList.innerHTML = [...blockedIPs]
    .map(ip => `<li class="blocked-item">
      <span class="blocked-ip">${ip}</span>
      <span class="blocked-label">BLOCKED</span>
    </li>`).join("");
  $blockedCount.textContent = blockedIPs.size;
}

// ── Alert Feed ────────────────────────────────────────────────────────────
function pushAlert(ip) {
  if (knownHighIPs.has(ip)) return;
  knownHighIPs.add(ip);
  alertHistory.unshift({ ip, timestamp: nowLabel() });
  if (alertHistory.length > MAX_ALERTS) alertHistory.pop();
  renderAlertFeed();
}

function renderAlertFeed() {
  if (alertHistory.length === 0) {
    $alertFeed.innerHTML = '<li class="alert-placeholder">No threats detected…</li>';
    $alertCount.textContent = "0";
    return;
  }
  $alertFeed.innerHTML = alertHistory.map(a => `
    <li class="alert-item">
      <span class="alert-icon">▲</span>
      <span class="alert-msg">
        DDoS attack detected from
        <span class="alert-ip">${a.ip}</span>
        <span class="alert-time">${a.timestamp}</span>
      </span>
    </li>`).join("");
  $alertCount.textContent = alertHistory.length;
}

// ── Table render ──────────────────────────────────────────────────────────
function renderTable(data) {
  if (data.length === 0) {
    $tableBody.innerHTML = '<tr><td colspan="6" class="empty-state">No active traffic in window…</td></tr>';
    $ipCount.textContent = "0 IPs";
    return;
  }
  $ipCount.textContent = `${data.length} IP${data.length > 1 ? "s" : ""}`;
  $tableBody.innerHTML = data.map(row => {
    const rc  = riskClass(row.final_risk || row.risk);
    const pct = Math.round((row.anomaly_score || 0) * 100);
    const sel = (selectedIP === row.ip) ? "selected-row" : "";
    return `
      <tr class="${sel}" onclick="selectIP('${row.ip}')">
        <td>${row.ip}</td>
        <td>${row.packets.toLocaleString()}</td>
        <td><span class="risk-badge ${rc}">${row.final_risk || row.risk}</span></td>
        <td>${row.country}</td>
        <td>
          <div class="anomaly-bar">
            <div class="anomaly-track">
              <div class="anomaly-fill ${rc}" style="width:${pct}%"></div>
            </div>
            <span>${(row.anomaly_score || 0).toFixed(2)}</span>
          </div>
        </td>
        <td>
          <button class="btn-block" onclick="event.stopPropagation(); blockIP('${row.ip}')">BLOCK</button>
        </td>
      </tr>`;
  }).join("");
}

// ── Stats update ──────────────────────────────────────────────────────────
function updateStats(data) {
  const total = data.reduce((s, r) => s + r.packets, 0);
  const high  = data.filter(r => (r.final_risk || r.risk) === "HIGH").length;
  const peak  = data.length ? Math.max(...data.map(r => r.packets)) : 0;
  setTextAndFlash($statTotal, total.toLocaleString());
  setTextAndFlash($statIPs,   data.length);
  setTextAndFlash($statHigh,  high);
  setTextAndFlash($statPeak,  peak.toLocaleString());
}

// ── Charts update — original ──────────────────────────────────────────────
function updateCharts(data) {
  const total = data.reduce((s, r) => s + r.packets, 0);
  trendLabels.push(nowLabel());
  trendValues.push(total);
  if (trendLabels.length > MAX_TREND_POINTS) {
    trendLabels.shift();
    trendValues.shift();
  }
  lineChart.update("none");

  const top10 = data.slice(0, 10);
  barChart.data.labels                          = top10.map(r => r.ip);
  barChart.data.datasets[0].data               = top10.map(r => r.packets);
  barChart.data.datasets[0].backgroundColor    = top10.map(r => barColor(r.final_risk || r.risk));
  barChart.update("none");
}

// ═══════════════════════════════════════════════════════════════════════════
//  ML PANEL RENDERERS
// ═══════════════════════════════════════════════════════════════════════════

// ── Adaptive Threshold ────────────────────────────────────────────────────
/**
 * For the 3 metric bars (packets, bytes, entropy) we need window-level
 * stats. The backend doesn't send aggregate stats directly, so we compute
 * them from the current data array (same values the backend used).
 *
 * Each bar shows:
 *   • A fill representing the CURRENT IP being inspected (or window max)
 *   • A mean marker (dotted vertical line at mean position)
 *   • A threshold marker (dashed vertical line at mean + 2σ position)
 */
function updateAdaptivePanel(data) {
  if (data.length === 0) {
    $adaptiveIPList.innerHTML = '<span class="ml-no-data">No data…</span>';
    return;
  }

  // Compute window stats for packets and bytes
  const packetVals  = data.map(r => r.packets);
  const byteVals    = data.map(r => r.bytes || 0);
  // Use anomaly_score as proxy for entropy (0 = high entropy, 1 = low)
  // We don't have raw entropy from the backend, so use adaptive_score as signal

  function windowStats(vals) {
    const mean = vals.reduce((a,b) => a+b, 0) / vals.length;
    const variance = vals.reduce((a,b) => a + (b-mean)**2, 0) / vals.length;
    const std  = Math.sqrt(variance);
    const thresh = mean + 2 * std;
    return { mean, std, thresh };
  }

  const pStat = windowStats(packetVals);
  const bStat = windowStats(byteVals);

  // Update the 3 metric track bars
  // We show window-level metrics: use peak as the "fill" reference
  const peakPkts  = Math.max(...packetVals);
  const peakBytes = Math.max(...byteVals);
  const avgAdaptiveScore = data.reduce((a,r) => a + (r.adaptive_score||0), 0) / data.length;

  const CEIL_PKTS  = Math.max(pStat.thresh * 1.5, peakPkts * 1.1, 1);
  const CEIL_BYTES = Math.max(bStat.thresh * 1.5, peakBytes * 1.1, 1);

  function updateTrack(rowIndex, value, mean, thresh, ceil, extraClass) {
    const rows = document.querySelectorAll(".metric-row");
    if (!rows[rowIndex]) return;
    const fill   = rows[rowIndex].querySelector(".metric-fill");
    const mmk    = rows[rowIndex].querySelector(".metric-mean-marker");
    const tmk    = rows[rowIndex].querySelector(".metric-thresh-marker");
    const valEl  = rows[rowIndex].querySelector(".metric-value");

    const pctFill   = Math.min((value  / ceil) * 100, 100);
    const pctMean   = Math.min((mean   / ceil) * 100, 100);
    const pctThresh = Math.min((thresh / ceil) * 100, 100);

    const isOver = value > thresh;

    fill.style.width = pctFill + "%";
    fill.className   = "metric-fill" + (extraClass ? " " + extraClass : "") + (isOver ? " over-thresh" : "");
    mmk.style.left   = pctMean   + "%";
    tmk.style.left   = pctThresh + "%";

    if (isOver) {
      valEl.textContent = "HIGH";
      valEl.className   = "metric-value over";
    } else {
      valEl.textContent = "OK";
      valEl.className   = "metric-value";
    }
  }

  updateTrack(0, peakPkts,  pStat.mean,  pStat.thresh,  CEIL_PKTS,  "");
  updateTrack(1, peakBytes, bStat.mean,  bStat.thresh,  CEIL_BYTES, "");
  updateTrack(2, avgAdaptiveScore * 10000, 5000, 7000, 12000, "entropy-fill");

  // Per-IP adaptive pills
  $adaptiveIPList.innerHTML = data.map(r => {
    const rc = (r.adaptive_risk || "LOW").toLowerCase();
    const score = (r.adaptive_score || 0).toFixed(2);
    return `<div class="adpt-pill adpt-${rc}">
      <span class="adpt-ip">${r.ip}</span>
      <span class="adpt-risk">${r.adaptive_risk || "LOW"}</span>
      <span class="adpt-score">${score}</span>
    </div>`;
  }).join("");
}

// ── Isolation Forest ──────────────────────────────────────────────────────
function updateIFPanel(data) {
  if (data.length === 0) {
    $ifIPList.innerHTML     = '<span class="ml-no-data">No data…</span>';
    $ifAnomalyCount.textContent = "0";
    ifGaugeChart.data.datasets[0].data = [0, 0, 1];
    ifGaugeChart.update("none");
    return;
  }

  const anomalies = data.filter(r => r.if_label === "ANOMALY").length;
  const normals   = data.filter(r => r.if_label === "NORMAL").length;
  const nas       = data.filter(r => !r.if_label || r.if_label === "N/A").length;

  // Update gauge
  ifGaugeChart.data.datasets[0].data = [
    anomalies,
    normals,
    Math.max(nas, anomalies + normals === 0 ? 1 : 0),
  ];
  ifGaugeChart.update("none");

  // Update big anomaly count
  $ifAnomalyCount.textContent = anomalies;
  $ifAnomalyCount.className   = "if-big-num" + (anomalies === 0 ? " safe" : "");

  // Per-IP list
  $ifIPList.innerHTML = data.map(r => {
    const label     = r.if_label || "N/A";
    const labelCls  = label === "ANOMALY" ? "anomaly" : label === "NORMAL" ? "normal" : "na";
    const score     = (r.if_score || 0).toFixed(3);
    return `<div class="if-ip-row">
      <span class="if-ip-addr">${r.ip}</span>
      <span class="if-ip-label ${labelCls}">${label}</span>
      <span class="if-ip-score">${score}</span>
    </div>`;
  }).join("");
}

// ── Random Forest ─────────────────────────────────────────────────────────
function updateRFPanel(data) {
  if (data.length === 0) {
    $rfIPList.innerHTML = '<span class="ml-no-data">No data…</span>';
    setTextAndFlash($rfAttackCount, "0");
    setTextAndFlash($rfNormalCount, "0");
    setTextAndFlash($rfNACount,     "0");
    return;
  }

  const attacks = data.filter(r => r.rf_prediction === "ATTACK").length;
  const normals = data.filter(r => r.rf_prediction === "NORMAL").length;
  const nas     = data.filter(r => !r.rf_prediction || r.rf_prediction === "N/A").length;

  setTextAndFlash($rfAttackCount, attacks);
  setTextAndFlash($rfNormalCount, normals);
  setTextAndFlash($rfNACount,     nas);

  $rfIPList.innerHTML = data.map(r => {
    const pred = r.rf_prediction || "N/A";
    const prob = r.rf_probability || 0;
    const cls  = pred === "ATTACK" ? "attack" : pred === "NORMAL" ? "normal" : "na";
    const pct  = Math.round(
      pred === "ATTACK" ? prob * 100 :
      pred === "NORMAL" ? (1 - prob) * 100 : 0
    );
    const label = pred === "ATTACK" ? `ATK ${pct}%` :
                  pred === "NORMAL" ? `NRM ${pct}%` : "N/A";
    return `<div class="rf-ip-row">
      <span class="rf-ip-addr">${r.ip}</span>
      <div class="rf-conf-track">
        <div class="rf-conf-fill ${cls}" style="width:${pct}%"></div>
      </div>
      <span class="rf-ip-pct ${cls}">${label}</span>
    </div>`;
  }).join("");
}

// ── Explainability ────────────────────────────────────────────────────────
/**
 * Map each explanation line to a visual category so the left border colour
 * hints at which engine produced the reason.
 */
function categoriseExplain(line) {
  const l = line.toLowerCase();
  if (l.includes("rule-based"))                      return "rule";
  if (l.includes("adaptive"))                        return "adpt";
  if (l.includes("entropy"))                         return "entr";
  if (l.includes("isolation forest"))                return "ifor";
  if (l.includes("random forest"))                   return "rfml";
  if (l.includes("protocol") || l.includes("tcp"))   return "proto";
  if (l.includes("hybrid"))                          return "hybr";
  return "rule";
}

function categoriseBullet(cat) {
  return { rule:"◈", adpt:"≈", entr:"∿", ifor:"◉", rfml:"▣", proto:"⊡", hybr:"▲" }[cat] || "•";
}

function selectIP(ip) {
  selectedIP = ip;
  renderExplainPanel();
  renderHybridPanel();
  // Re-render table to update selected-row highlight
  renderTable(lastData);
}

function clearExplain() {
  selectedIP = null;
  $explainIPBadge.textContent = "SELECT IP";
  $explainBody.innerHTML = `
    <div class="explain-placeholder">
      <span class="explain-icon">◈</span>
      <span>Click a row in the traffic table<br>to inspect AI reasoning</span>
    </div>`;
  $hybridSignals.innerHTML = '<div class="hybrid-placeholder">Select an IP to inspect signals</div>';
  $hybridBadge.textContent = "OR-GATE";
}

function renderExplainPanel() {
  if (!selectedIP) { clearExplain(); return; }
  const row = lastData.find(r => r.ip === selectedIP);
  if (!row) { clearExplain(); return; }

  $explainIPBadge.textContent = selectedIP;

  const finalRisk = (row.final_risk || row.risk || "LOW").toLowerCase();
  const explanations = row.explanation || [];

  let html = `
    <div class="explain-ip-header">
      <span>${selectedIP}</span>
      <span class="explain-final-badge ${finalRisk}">${(row.final_risk || row.risk || "LOW").toUpperCase()}</span>
    </div>`;

  if (explanations.length === 0) {
    html += '<div class="explain-placeholder"><span>No explanation data available.<br>Ensure the upgraded detector.py is running.</span></div>';
  } else {
    html += '<ul class="explain-list">';
    explanations.forEach(line => {
      const cat    = categoriseExplain(line);
      const bullet = categoriseBullet(cat);
      html += `<li class="explain-item ${cat}">
        <span class="explain-bullet">${bullet}</span>
        <span>${line}</span>
      </li>`;
    });
    html += '</ul>';
  }

  $explainBody.innerHTML = html;
}

// ── Hybrid Decision Engine ────────────────────────────────────────────────
function renderHybridPanel() {
  if (!selectedIP) return;
  const row = lastData.find(r => r.ip === selectedIP);
  if (!row) return;

  const finalRisk    = row.final_risk || row.risk || "LOW";
  const ruleRisk     = row.risk       || "LOW";
  const adaptiveRisk = row.adaptive_risk || "LOW";
  const ifLabel      = row.if_label      || "N/A";
  const rfPred       = row.rf_prediction || "N/A";

  // Determine fired state for each signal
  function signalState(value, highValues, warnValues) {
    if (highValues.includes(value)) return "fired";
    if (warnValues.includes(value)) return "fired-warn";
    return "ok";
  }

  const signals = [
    {
      name:   "RULE-BASED ENGINE",
      value:  ruleRisk,
      state:  signalState(ruleRisk, ["HIGH"], ["MEDIUM"]),
      icon:   ruleRisk === "HIGH" ? "▲" : ruleRisk === "MEDIUM" ? "◆" : "◎",
    },
    {
      name:   "ADAPTIVE THRESHOLD",
      value:  adaptiveRisk,
      state:  signalState(adaptiveRisk, ["HIGH"], ["MEDIUM"]),
      icon:   adaptiveRisk === "HIGH" ? "▲" : adaptiveRisk === "MEDIUM" ? "◆" : "◎",
    },
    {
      name:   "ISOLATION FOREST",
      value:  ifLabel,
      state:  signalState(ifLabel, ["ANOMALY"], []),
      icon:   ifLabel === "ANOMALY" ? "▲" : ifLabel === "NORMAL" ? "◎" : "○",
    },
    {
      name:   "RANDOM FOREST",
      value:  rfPred,
      state:  signalState(rfPred, ["ATTACK"], []),
      icon:   rfPred === "ATTACK" ? "▲" : rfPred === "NORMAL" ? "◎" : "○",
    },
  ];

  const anyFired = signals.some(s => s.state === "fired");
  const verdictCls = finalRisk === "HIGH" ? "v-high" : finalRisk === "MEDIUM" ? "v-medium" : "v-low";

  $hybridBadge.textContent = finalRisk === "HIGH" ? "THREAT CONFIRMED" :
                             finalRisk === "MEDIUM" ? "MONITORING" : "CLEAR";

  $hybridSignals.innerHTML =
    signals.map(s => `
      <div class="hybrid-signal-row ${s.state}">
        <span class="hybrid-signal-icon">${s.icon}</span>
        <span class="hybrid-signal-name">${s.name}</span>
        <span class="hybrid-signal-value">${s.value}</span>
      </div>`).join("") +
    `<div class="hybrid-verdict ${verdictCls}">
      <span class="hybrid-verdict-label">FINAL DECISION</span>
      <span class="hybrid-verdict-value">${finalRisk}</span>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN POLL
// ═══════════════════════════════════════════════════════════════════════════
async function poll() {
  try {
    const res  = await fetch("/data");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    setStatus(true);

    // Filter blocked IPs
    const filtered = data.filter(r => !blockedIPs.has(r.ip));

    // Trim knownHighIPs to IPs still in window
    const currentIPs = new Set(filtered.map(r => r.ip));
    for (const ip of knownHighIPs) {
      if (!currentIPs.has(ip)) knownHighIPs.delete(ip);
    }

    // Push HIGH alerts (use final_risk when available)
    filtered
      .filter(r => (r.final_risk || r.risk) === "HIGH")
      .forEach(r => pushAlert(r.ip));

    // Store for click-based re-render
    lastData = filtered;

    // ── Render all panels ─────────────────────────────────────────────
    renderTable(filtered);
    updateStats(filtered);
    updateCharts(filtered);

    // ML panels
    updateAdaptivePanel(filtered);
    updateIFPanel(filtered);
    updateRFPanel(filtered);

    // If an IP is selected, keep explainability panels live
    if (selectedIP) {
      if (currentIPs.has(selectedIP)) {
        renderExplainPanel();
        renderHybridPanel();
      } else {
        // Selected IP left the window — clear panel
        clearExplain();
      }
    }

  } catch (err) {
    setStatus(false);
    console.error("Poll error:", err);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────
poll();
setInterval(poll, POLL_INTERVAL);