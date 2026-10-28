// C300 dashboard: fetch /api/summary and draw it. No libraries, so it works offline.
"use strict";

const $ = (id) => document.getElementById(id);
// SECURITY: values come from scanned hosts (config files), which an attacker could
// control. Always escape before putting anything into HTML.
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtPct = (v) => (v === null || v === undefined ? "–" : `${Math.round(v)}%`);
const scoreColor = (v) => (v === null || v === undefined ? "var(--faint)" : v >= 80 ? "var(--good)" : v >= 60 ? "var(--warn)" : "var(--bad)");
const when = (iso) => (iso ? new Date(iso).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "");
const shortDate = (iso) => new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short" });
const show = (v) => (v === null || v === undefined ? "not found" : typeof v === "object" ? JSON.stringify(v) : String(v));

const ICONS = {
  pos: '<path d="M4 9h16v10H4zM7 9V5h10v4M8 13h2m4 0h2m-8 3h8" />',
  office: '<path d="M3 5h18v11H3zM8 20h8m-4-4v4" />',
  web: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
  db: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
  server: '<path d="M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01"/>',
  identity: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4.5-6 8-6s7 2 8 6"/>',
  remote: '<path d="M4 5h16v11H4zM2 20h20M10 9l3 2-3 2"/>',
  network: '<path d="M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z"/>',
  endpoint: '<path d="M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6zM9 12l2 2 4-4"/>',
  patching: '<path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/>',
  logging: '<path d="M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h3"/>',
  data: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  web_d: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
  general: '<circle cx="12" cy="12" r="9"/>',
};
const icon = (k) => `<svg class="kicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICONS[k] || ICONS.general}</svg>`;

let SUMMARY = null;

// ---------------------------------------------------------------- charts (SVG)
function gauge(score, delta) {
  const r = 62, cx = 85, cy = 80, start = Math.PI * 0.85, end = Math.PI * 2.15;
  const pt = (a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  const arc = (a0, a1) => { const [x0, y0] = pt(a0), [x1, y1] = pt(a1); return `M${x0} ${y0} A${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x1} ${y1}`; };
  const v = score ?? 0, a = start + (end - start) * Math.max(0, Math.min(100, v)) / 100;
  const d = delta === null || delta === undefined ? "" :
    `<div class="delta ${delta > 0 ? "up" : delta < 0 ? "down" : ""}">${delta > 0 ? "▲" : delta < 0 ? "▼" : "■"} ${delta > 0 ? "+" : ""}${delta} pts since last scan</div>`;
  return `<svg viewBox="0 0 170 130" role="img" aria-label="Posture score ${fmtPct(score)}">
    <path d="${arc(start, end)}" stroke="#2a2b33" stroke-width="12" fill="none" stroke-linecap="round"/>
    ${score === null ? "" : `<path d="${arc(start, a)}" stroke="${scoreColor(score)}" stroke-width="12" fill="none" stroke-linecap="round"/>`}
    <text x="85" y="86" text-anchor="middle" fill="#e7e8ec" font-size="30" font-weight="600">${fmtPct(score)}</text>
    <text x="85" y="106" text-anchor="middle" fill="#8d909b" font-size="11">posture score</text></svg>${d}`;
}

function trendChart(points) {
  const W = 560, H = 150, L = 30, R = 10, T = 10, B = 24;
  const pts = points.filter((p) => p.score !== null);
  if (pts.length < 2) return `<svg viewBox="0 0 ${W} ${H}"><text x="${W / 2}" y="${H / 2}" text-anchor="middle" fill="#8d909b" font-size="13">Run at least two scans to see the trend</text></svg>`;
  const x = (i) => L + (W - L - R) * (i / (pts.length - 1));
  const y = (s) => T + (H - T - B) * (1 - s / 100);
  let grid = "";
  for (const g of [0, 25, 50, 75, 100]) grid += `<line x1="${L}" x2="${W - R}" y1="${y(g)}" y2="${y(g)}" stroke="#23242b"/><text x="${L - 6}" y="${y(g) + 4}" text-anchor="end" fill="#5d606b" font-size="10">${g}</text>`;
  const line = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.score).toFixed(1)}`).join(" ");
  const area = `${line} L${x(pts.length - 1)} ${y(0)} L${x(0)} ${y(0)} Z`;
  const step = Math.max(1, Math.ceil(pts.length / 8));
  const labels = pts.map((p, i) => (i % step === 0 || i === pts.length - 1) ? `<text x="${x(i)}" y="${H - 6}" text-anchor="middle" fill="#5d606b" font-size="10">${esc(shortDate(p.at))}</text>` : "").join("");
  const dots = pts.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.score)}" r="3.5" fill="${p.trigger === "scheduled" ? "#5b8cff" : "#e7e8ec"}"><title>Scan #${p.run_id} · ${esc(when(p.at))} · ${esc(p.trigger)} · ${fmtPct(p.score)}</title></circle>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Score trend">
    <defs><linearGradient id="g" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#5b8cff" stop-opacity=".45"/><stop offset="1" stop-color="#5b8cff" stop-opacity="0"/></linearGradient></defs>
    ${grid}<path d="${area}" fill="url(#g)"/><path d="${line}" fill="none" stroke="#7aa2ff" stroke-width="2"/>${dots}${labels}</svg>`;
}

const bar = (score) => `<div class="track"><div class="fill" style="width:${score ?? 0}%;background:${scoreColor(score)}"></div></div>`;
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const hostIcon = (name) => { const h = (SUMMARY.hosts || []).find((x) => x.name === name); return icon(h ? h.kind : "server"); };

// ---------------------------------------------------------------- panels
function renderFailures(rows) {
  const t = $("failures");
  if (!rows.length) { t.innerHTML = `<tr class="empty-row"><td>No failing checks. Nice.</td></tr>`; return; }
  t.innerHTML = `<tr><th>Host</th><th>Check</th><th>Severity</th></tr>` + rows.map((r, i) => `
    <tr class="row" data-i="${i}"><td><div class="hostcell">${hostIcon(r.host)}${esc(r.host)}</div></td>
      <td>${esc(r.control_id)} · ${esc(r.title)}</td><td>${sev(r.severity)}</td></tr>
    <tr class="detail" data-for="${i}" hidden><td colspan="3">
      Found <b class="mono">${esc(show(r.actual))}</b>, expected ${esc(r.operator)} <b class="mono">${esc(show(r.expected))}</b><br>
      <b>Fix:</b> ${esc(r.fix)}</td></tr>`).join("");
  t.querySelectorAll("tr.row").forEach((tr) => tr.addEventListener("click", () => {
    const d = t.querySelector(`tr.detail[data-for="${tr.dataset.i}"]`); d.hidden = !d.hidden;
  }));
}

function renderHosts(hosts) {
  $("hosts").innerHTML = hosts.map((h) => `
    <div class="bar click" data-host="${esc(h.name)}">${icon(h.kind)}
      <div class="name"><div>${esc(h.name)}</div><span class="muted">${esc(h.role)} · ${esc(h.platform)} via ${esc(h.transport)}</span></div>
      ${h.error ? `<div class="pct" style="color:var(--bad)">–</div><div class="muted">unreachable</div><div class="err">${esc(h.error)}</div>`
        : `<div class="pct" style="color:${scoreColor(h.score)}">${fmtPct(h.score)}</div>${bar(h.score)}`}
    </div>`).join("");
  $("hosts").querySelectorAll(".bar").forEach((el) => el.addEventListener("click", () => openHost(el.dataset.host)));
}

function renderDomains(domains) {
  $("domains").innerHTML = domains.map((d) => `
    <div class="bar">${icon(d.domain === "web" ? "web_d" : d.domain)}
      <div class="name"><div>${esc(d.label)}</div><span class="muted">${d.PASS} pass · ${d.FAIL} fail${d.NOT_COLLECTED + d.ERROR ? ` · ${d.NOT_COLLECTED + d.ERROR} not checked` : ""}</span></div>
      <div class="pct" style="color:${scoreColor(d.score)}">${fmtPct(d.score)}</div>${bar(d.score)}</div>`).join("");
}

function renderDrift(rows, hosts) {
  const against = [...new Set(hosts.map((h) => h.drift_against).filter(Boolean))];
  $("driftNote").textContent = against.length ? `compared with each host's ${against.join(" / ")}` : "";
  const t = $("drift");
  if (!rows.length) {
    t.innerHTML = `<tr class="empty-row"><td>No drift: every host matches its baseline${hosts.some((h) => h.drift_against) ? "" : " (scan again after a change to compare)"}.</td></tr>`;
    return;
  }
  const arrow = { worse: "▼ worse", better: "▲ fixed", changed: "● changed" };
  t.innerHTML = `<tr><th>Host</th><th>Check</th><th>Was → now</th><th></th></tr>` + rows.map((r) => `
    <tr><td><div class="hostcell">${hostIcon(r.host)}${esc(r.host)}</div></td>
      <td>${esc(r.control_id)} · ${esc(r.title)} ${sev(r.severity)}</td>
      <td class="mono">${esc(show(r.old_actual))} → ${esc(show(r.new_actual))}</td>
      <td class="arrow ${r.direction}" style="white-space:nowrap">${arrow[r.direction]}</td></tr>`).join("");
}

function renderGaps(rows) {
  const t = $("gaps");
  if (!rows.length) { t.innerHTML = `<tr class="empty-row"><td>Every applicable check was collected.</td></tr>`; return; }
  t.innerHTML = `<tr><th>Host</th><th>Check</th><th>Why</th></tr>` + rows.map((r) => `
    <tr><td><div class="hostcell">${hostIcon(r.host)}${esc(r.host)}</div></td><td>${esc(r.control_id)} · ${esc(r.title)}</td>
    <td class="muted">${esc(r.message)}</td></tr>`).join("");
}

function renderFrameworks(fws) {
  $("frameworks").innerHTML = fws.map((f) => {
    const tot = f.requirements || 1;
    return `<div class="fw"><div class="name">${esc(f.name)}</div>
      <div class="line"><span>Requirements fully passed</span><b>${f.requirements_passed} / ${f.requirements}</b></div>
      <div class="line"><span>Checks passed</span><b>${fmtPct(f.checks_pass_rate)}</b></div>
      <div class="line"><span>Checks mapped</span><b>${f.total}${f.NOT_COLLECTED + f.ERROR ? ` (${f.NOT_COLLECTED + f.ERROR} not checked)` : ""}</b></div>
      <div class="stack" title="passed / failed / not checked">
        <div style="width:${100 * f.requirements_passed / tot}%;background:var(--good)"></div>
        <div style="width:${100 * f.requirements_failed / tot}%;background:var(--bad)"></div></div></div>`;
  }).join("");
}

function render(s) {
  SUMMARY = s;
  $("emptyState").hidden = s.has_data;
  $("content").hidden = !s.has_data;
  if (!s.has_data) return;
  $("lastScan").innerHTML = `Last scan ${esc(when(s.run.started_at))}<br><span>${esc(s.run.trigger)} · ${s.hosts.length} hosts · ${s.controls_total} controls</span>`;
  const ev = $("evidenceLink"); ev.hidden = false; ev.href = `/api/runs/${s.run.id}/evidence.json`;
  $("gauge").innerHTML = gauge(s.score, s.delta);
  $("trend").innerHTML = trendChart(s.trend);
  $("trendNote").textContent = `last ${s.trend.length} scans · blue dots are scheduled scans`;
  const c = s.counts;
  $("kpis").innerHTML = [
    [c.PASS, "Passed"], [c.FAIL, "Failed"], [c.NOT_COLLECTED + c.ERROR, "Not checked"], [fmtPct(s.pass_rate), "Plain pass rate"],
  ].map(([v, l]) => `<div class="kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  const rec = s.recommendation;
  $("recommendation").innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.6.4 1 1.1 1 1.8V16h5v-.3c0-.7.4-1.4 1-1.8A6 6 0 0 0 12 3Z"/></svg>
    <div><b style="color:var(--text)">Recommendation</b><br>${rec.high_failures
      ? `Fixing the <b>${rec.high_failures}</b> high-severity failures first would raise the score from ${fmtPct(s.score)} to <b>${fmtPct(rec.score_if_fixed)}</b>.`
      : "No high-severity failures left. Work through the medium ones in the list."}</div>`;
  renderFailures(s.top_failures);
  renderHosts(s.hosts);
  renderDomains(s.domains);
  renderDrift(s.drift, s.hosts);
  renderGaps(s.gaps);
  renderFrameworks(s.frameworks);
}

async function load() {
  const r = await fetch("/api/summary");
  render(await r.json());
}

// ---------------------------------------------------------------- host drawer
let drawerHost = null, drawerRows = [], drawerFilter = "all";
async function openHost(name) {
  const h = SUMMARY.hosts.find((x) => x.name === name);
  drawerHost = h;
  $("drawerTitle").textContent = `${h.name} · ${fmtPct(h.score)}`;
  $("drawerSub").textContent = `${h.role} · ${h.platform} via ${h.transport} · ${h.location}` +
    (h.baseline_set_at ? ` · baseline set ${when(h.baseline_set_at)}` : " · no baseline yet");
  drawerRows = h.error ? [] : await (await fetch(`/api/host-scans/${h.host_scan_id}`)).json();
  drawerFilter = "all";
  document.querySelectorAll("#drawerFilter button").forEach((b) => b.classList.toggle("on", b.dataset.f === "all"));
  renderDrawer();
  $("drawer").hidden = $("scrim").hidden = false;
}
function renderDrawer() {
  const order = { FAIL: 0, ERROR: 1, NOT_COLLECTED: 2, PASS: 3 };
  const rows = drawerRows.filter((r) => drawerFilter === "all" || r.status === drawerFilter ||
    (drawerFilter === "GAP" && (r.status === "NOT_COLLECTED" || r.status === "ERROR")))
    .sort((a, b) => order[a.status] - order[b.status] || a.control_id.localeCompare(b.control_id));
  $("drawerTable").innerHTML = drawerHost.error ? `<tr class="empty-row"><td>${esc(drawerHost.error)}</td></tr>` :
    `<tr><th>Status</th><th>Check</th><th>Found</th><th>Expected</th></tr>` + rows.map((r) => `
    <tr><td class="st ${r.status}">${r.status.replace("_", " ")}</td>
      <td>${esc(r.control_id)} · ${esc(r.title)} ${sev(r.severity)}${r.status === "FAIL" ? `<div class="muted">Fix: ${esc((r.remediation || {})[drawerHost.platform] || Object.values(r.remediation || {})[0] || "")}</div>` : ""}</td>
      <td class="mono">${esc(show(r.actual))}</td><td class="mono">${esc(r.operator)} ${esc(show(r.expected))}</td></tr>`).join("");
}
function closeDrawer() { $("drawer").hidden = $("scrim").hidden = true; }

// ---------------------------------------------------------------- one-click scan
async function post(url) {
  return fetch(url, { method: "POST", headers: { "X-CC-Token": window.CC_TOKEN } });
}
function setScanning(on) {
  const b = $("scanBtn");
  b.disabled = on;
  b.innerHTML = on ? `<span class="spin"></span><span>Scanning…</span>` : `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7z" fill="currentColor"/></svg><span>Run scan</span>`;
}
async function pollScan() {
  const s = await (await fetch("/api/scan/status")).json();
  const p = $("progress");
  p.hidden = false;
  p.innerHTML = Object.entries(s.hosts).map(([h, st]) => `<span class="pchip ${esc(st)}">${esc(h)} · ${esc(st)}</span>`).join("") +
    (s.error ? `<span class="pchip error">Scan failed: ${esc(s.error)}</span>` : "");
  if (s.running) { setTimeout(pollScan, 800); return; }
  setScanning(false);
  await load();
  if (!s.error) setTimeout(() => { p.hidden = true; }, 4000);
}
$("scanBtn").addEventListener("click", async () => {
  setScanning(true);
  const r = await post("/api/scan");
  if (r.status !== 202 && r.status !== 409) { setScanning(false); alertBar(`Could not start scan (HTTP ${r.status})`); return; }
  pollScan();
});
function alertBar(msg) { const p = $("progress"); p.hidden = false; p.innerHTML = `<span class="pchip error">${esc(msg)}</span>`; }

$("drawerClose").addEventListener("click", closeDrawer);
$("scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
document.querySelectorAll("#drawerFilter button").forEach((b) => b.addEventListener("click", () => {
  drawerFilter = b.dataset.f;
  document.querySelectorAll("#drawerFilter button").forEach((x) => x.classList.toggle("on", x === b));
  renderDrawer();
}));
$("baselineBtn").addEventListener("click", async () => {
  if (!drawerHost) return;
  const r = await post(`/api/hosts/${encodeURIComponent(drawerHost.name)}/baseline`);
  $("baselineBtn").textContent = r.ok ? "Baseline saved ✓" : "Could not set baseline";
  setTimeout(() => { $("baselineBtn").textContent = "Set latest scan as baseline"; }, 2500);
  await load();
});

// Resume the progress display if a scan was already running (e.g. page reloaded).
fetch("/api/scan/status").then((r) => r.json()).then((s) => { if (s.running) { setScanning(true); pollScan(); } });
load();
