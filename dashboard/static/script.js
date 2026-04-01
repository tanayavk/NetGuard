/**
 * SENTINEL · SOC Dashboard — script.js
 * Polls /data every 3 s, updates all panels, charts, and alerts.
 */

"use strict";

// ── Config ────────────────────────────────────────────────────────────────
const POLL_INTERVAL  = 3000;        // ms
const MAX_TREND_POINTS = 30;        // points kept in the trend line
const MAX_ALERTS     = 50;          // alert list cap

// ── State ─────────────────────────────────────────────────────────────────
let trendLabels   = [];             // timestamps for line chart x-axis
let trendValues   = [];             // total packets at each tick
let alertHistory  = [];             // deduplicated HIGH-IP alerts
let knownHighIPs  = new Set();      // IPs already in the alert feed
let blockedIPs    = new Set();      // locally mirrored blocked set

// ── DOM refs ──────────────────────────────────────────────────────────────
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

// ── Clock ─────────────────────────────────────────────────────────────────
function tickClock() {
  const now  = new Date();
  const hh   = String(now.getHours()).padStart(2, "0");
  const mm   = String(now.getMinutes()).padStart(2, "0");
  const ss   = String(now.getSeconds()).padStart(2, "0");
  $clock.textContent = `${hh}:${mm}:${ss}`;
}
setInterval(tickClock, 1000);
tickClock();

// ── Chart setup ───────────────────────────────────────────────────────────
const CHART_DEFAULTS = {
  color: "#a8c7dd",
  borderColor: "#1e2d3d",
};

Chart.defaults.color   = CHART_DEFAULTS.color;
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size   = 11;

// Line chart — traffic trend
const lineCtx = document.getElementById("lineChart").getContext("2d");
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
      x: {
        grid: { color: "#1e2d3d" },
        ticks: { maxRotation: 0, maxTicksLimit: 6 },
      },
      y: {
        grid: { color: "#1e2d3d" },
        beginAtZero: true,
      },
    },
  },
});

// Bar chart — packets per IP
const barCtx = document.getElementById("barChart").getContext("2d");
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
      x: {
        grid: { color: "#1e2d3d" },
        ticks: { maxRotation: 45 },
      },
      y: {
        grid: { color: "#1e2d3d" },
        beginAtZero: true,
      },
    },
  },
});

// ── Helpers ───────────────────────────────────────────────────────────────
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
  // Force reflow so the animation restarts
  void el.offsetWidth;
  el.classList.add("flash");
}

function nowLabel() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`;
}

// ── Status indicator ──────────────────────────────────────────────────────
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
    .map(ip => `
      <li class="blocked-item">
        <span class="blocked-ip">${ip}</span>
        <span class="blocked-label">BLOCKED</span>
      </li>`)
    .join("");
  $blockedCount.textContent = blockedIPs.size;
}

// ── Alert Feed ────────────────────────────────────────────────────────────
function pushAlert(ip) {
  if (knownHighIPs.has(ip)) return;
  knownHighIPs.add(ip);

  const timestamp = nowLabel();
  alertHistory.unshift({ ip, timestamp });
  if (alertHistory.length > MAX_ALERTS) alertHistory.pop();

  renderAlertFeed();
}

function renderAlertFeed() {
  if (alertHistory.length === 0) {
    $alertFeed.innerHTML = '<li class="alert-placeholder">No threats detected…</li>';
    $alertCount.textContent = "0";
    return;
  }

  $alertFeed.innerHTML = alertHistory
    .map(a => `
      <li class="alert-item">
        <span class="alert-icon">▲</span>
        <span class="alert-msg">
          DDoS attack detected from
          <span class="alert-ip">${a.ip}</span>
          <span class="alert-time">${a.timestamp}</span>
        </span>
      </li>`)
    .join("");

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
    const rc    = riskClass(row.risk);
    const score = row.anomaly_score;
    const pct   = Math.round(score * 100);
    return `
      <tr>
        <td>${row.ip}</td>
        <td>${row.packets.toLocaleString()}</td>
        <td><span class="risk-badge ${rc}">${row.risk}</span></td>
        <td>${row.country}</td>
        <td>
          <div class="anomaly-bar">
            <div class="anomaly-track">
              <div class="anomaly-fill ${rc}" style="width:${pct}%"></div>
            </div>
            <span>${score.toFixed(2)}</span>
          </div>
        </td>
        <td>
          <button class="btn-block" onclick="blockIP('${row.ip}')">BLOCK</button>
        </td>
      </tr>`;
  }).join("");
}

// ── Stats update ──────────────────────────────────────────────────────────
function updateStats(data) {
  const total = data.reduce((s, r) => s + r.packets, 0);
  const high  = data.filter(r => r.risk === "HIGH").length;
  const peak  = data.length ? Math.max(...data.map(r => r.packets)) : 0;

  setTextAndFlash($statTotal, total.toLocaleString());
  setTextAndFlash($statIPs,   data.length);
  setTextAndFlash($statHigh,  high);
  setTextAndFlash($statPeak,  peak.toLocaleString());
}

function setTextAndFlash(el, value) {
  if (el.textContent !== String(value)) {
    el.textContent = value;
    flashEl(el);
  }
}

// ── Charts update ─────────────────────────────────────────────────────────
function updateCharts(data) {
  const total = data.reduce((s, r) => s + r.packets, 0);

  // Trend
  trendLabels.push(nowLabel());
  trendValues.push(total);
  if (trendLabels.length > MAX_TREND_POINTS) {
    trendLabels.shift();
    trendValues.shift();
  }
  lineChart.update("none");

  // Bar — top 10 IPs
  const top10 = data.slice(0, 10);
  barChart.data.labels   = top10.map(r => r.ip);
  barChart.data.datasets[0].data            = top10.map(r => r.packets);
  barChart.data.datasets[0].backgroundColor = top10.map(r => barColor(r.risk));
  barChart.update("none");
}

// ── Main poll ─────────────────────────────────────────────────────────────
async function poll() {
  try {
    const res  = await fetch("/data");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    setStatus(true);

    // Filter out already-blocked IPs (defensive; backend should do this too)
    const filtered = data.filter(r => !blockedIPs.has(r.ip));

    // Clear knownHighIPs that are no longer in the feed (rolled out of window)
    const currentIPs = new Set(filtered.map(r => r.ip));
    for (const ip of knownHighIPs) {
      if (!currentIPs.has(ip)) knownHighIPs.delete(ip);
    }

    // Push new HIGH alerts
    filtered.filter(r => r.risk === "HIGH").forEach(r => pushAlert(r.ip));

    renderTable(filtered);
    updateStats(filtered);
    updateCharts(filtered);

  } catch (err) {
    setStatus(false);
    console.error("Poll error:", err);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────
poll();
setInterval(poll, POLL_INTERVAL);