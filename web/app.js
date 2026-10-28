"use strict";
/* Mini SIEM dashboard - plain JS, no build step. Every value that comes from logs is escaped with esc()
   because log content is attacker-controlled (a log line can contain <script>). */
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const RANK = { viewer: 0, analyst: 1, admin: 2 };
const SEV_COLOR = { critical: "#ff4d6d", high: "#ff9f43", medium: "#ffd166", low: "#4fc3f7", info: "#7a8aa8" };
const badge = s => `<span class="badge ${esc(s)}">${esc(String(s).replace("_", " "))}</span>`;
const parseTs = s => (s ? new Date(/[zZ]$|[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z") : null);
const fmt = s => { const d = parseTs(s); return d ? d.toLocaleString() : "-"; };
const hhmm = s => { const d = parseTs(s); return d ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""; };
const S = { token: localStorage.getItem("siem_token"), user: localStorage.getItem("siem_user"), role: localStorage.getItem("siem_role"),
  timers: [], charts: [], map: null, ws: null, live: [], liveTotal: 0, route: "" };
const can = r => (RANK[S.role] ?? -1) >= RANK[r];

async function api(path, { method = "GET", body, raw } = {}) {
  const res = await fetch(path, { method, headers: { ...(body ? { "Content-Type": "application/json" } : {}), Authorization: "Bearer " + S.token },
    body: body ? JSON.stringify(body) : undefined });
  if (res.status === 401) { logout(); throw new Error("session expired - please sign in again"); }
  if (!res.ok) {
    let m = res.statusText;
    try { const j = await res.json(); m = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (e) { /* ignore */ }
    throw new Error(m);
  }
  return raw ? res : res.json();
}
async function download(path, name) {
  const blob = await (await api(path, { raw: true })).blob();
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
function toast(msg, sev = "info") {
  const t = document.createElement("div"); t.className = "toast " + sev; t.textContent = msg; $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 6000);
}
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, "high"); } };
function openModal(html) { $("#mbody").innerHTML = html; $("#modal").hidden = false; }
function closeModal() { $("#modal").hidden = true; $("#mbody").innerHTML = ""; }
const every = (fn, ms) => S.timers.push(setInterval(() => guard(fn)(), ms));
function mkChart(id, cfg) { const c = new Chart($("#" + id), cfg); S.charts.push(c); return c; }
function table(head, rows, cls = "") {
  return `<div class="scroll"><table class="${cls}"><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>` +
    (rows.length ? rows.join("") : `<tr><td colspan="${head.length}" class="muted">nothing here yet</td></tr>`) + "</tbody></table></div>";
}
const ipLink = ip => ip ? `<a href="#/investigate/${encodeURIComponent(ip)}">${esc(ip)}</a>` : "-";

/* ------------------------------------------------------------------ auth */
function showApp() {
  $("#login").hidden = true; $("#app").hidden = false;
  $("#who").textContent = `${S.user} (${S.role})`; $("#nav-admin").hidden = !can("admin");
  connectWS(); nav();
}
function logout() {
  ["siem_token", "siem_user", "siem_role"].forEach(k => localStorage.removeItem(k));
  S.token = null; if (S.ws) { S.ws.close(); S.ws = null; }
  clearTimers(); $("#app").hidden = true; $("#login").hidden = false;
}
async function doLogin() {
  $("#lerr").textContent = "";
  try {
    const r = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("#lu").value, password: $("#lp").value }) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || "login failed");
    S.token = j.token; S.user = j.username; S.role = j.role;
    localStorage.setItem("siem_token", j.token); localStorage.setItem("siem_user", j.username); localStorage.setItem("siem_role", j.role);
    $("#lp").value = ""; showApp();
  } catch (e) { $("#lerr").textContent = e.message; }
}

/* ------------------------------------------------------------------ live websocket */
function connectWS() {
  if (S.ws) S.ws.close();
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/live?token=${encodeURIComponent(S.token)}`);
  S.ws = ws;
  ws.onopen = () => { $("#wsdot").classList.add("on"); $("#wslabel").textContent = "live feed connected"; };
  ws.onclose = () => { $("#wsdot").classList.remove("on"); $("#wslabel").textContent = "reconnecting..."; if (S.token && S.ws === ws) setTimeout(connectWS, 3000); };
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.type === "events") {
      S.live.unshift(...m.items.reverse()); S.live.length = Math.min(S.live.length, 300); S.liveTotal += m.total;
      if (S.route === "live") renderLiveRows();
    } else if (m.type === "alert") {
      toast(`${m.alert.severity.toUpperCase()}: ${m.alert.rule_name} - ${m.alert.entity}`, m.alert.severity);
      refreshBadge(); if (S.route === "alerts") guard(alerts)(); if (S.route === "map" && S.mapDraw) guard(S.mapDraw)();   // map updates the moment an alert fires
    } else if (m.type === "incident") toast(`Incident #${m.id} escalated: ${m.title}`, "critical");
  };
}
const refreshBadge = guard(async () => {
  const r = await api("/api/alerts?status=new&limit=1"); const b = $("#alertbadge");
  b.hidden = !r.total; b.textContent = r.total;
});

/* ------------------------------------------------------------------ router */
function clearTimers() { S.timers.forEach(clearInterval); S.timers = []; S.charts.forEach(c => c.destroy()); S.charts = []; if (S.map) { S.map.remove(); S.map = null; } }
const VIEWS = { overview: () => overview(), live: () => live(), map: () => mapView(), mitre: () => mitre(), alerts: () => alerts(),
  incidents: a => (a ? incidentDetail(a) : incidents()), investigate: a => investigate(a), search: () => search(), rules: () => rules(),
  response: () => hostsResponse(), admin: () => admin(),
  hunt: () => hunt(), graph: a => graphView(a), watchlists: () => watchlists(), intel: () => intel(), automation: () => automationView() };
const TITLES = { overview: "Overview", live: "Live event stream", map: "Attack map", mitre: "MITRE ATT&CK coverage", alerts: "Alerts", incidents: "Incidents",
  investigate: "Investigation", search: "Log search", rules: "Detection rules", response: "Hosts & active response", admin: "Administration",
  hunt: "Threat hunting (KQL)", graph: "Investigation graph", watchlists: "Watchlists", intel: "Threat intelligence", automation: "Automation rules" };
function nav() {
  if (!S.token) return;
  const [name, arg] = (location.hash.replace(/^#\//, "") || "overview").split("/");
  const key = VIEWS[name] ? name : "overview";
  clearTimers(); S.route = key;
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", a.getAttribute("href") === "#/" + key));
  $("#title").textContent = TITLES[key];
  guard(VIEWS[key])(arg ? decodeURIComponent(arg) : undefined); refreshBadge();
}

/* ------------------------------------------------------------------ overview */
async function overview() {
  $("#view").innerHTML = `<div class="grid g6" id="cards"></div><div class="grid g2" style="margin-top:14px">
    <div class="card"><h3>Alerts per hour (24h)</h3><canvas id="c1" height="150"></canvas></div>
    <div class="card"><h3>Events per minute (30 min)</h3><canvas id="c2" height="150"></canvas></div>
    <div class="card"><h3>Top attacker IPs (failed / blocked events, 24h)</h3><div id="tips"></div></div>
    <div class="card"><h3>Top targeted users</h3><div id="tusers"></div></div>
    <div class="card"><h3>Events by source (24h)</h3><canvas id="c3" height="150"></canvas></div></div>`;
  const draw = async () => {
    const o = await api("/api/stats/overview");
    const card = (n, l) => `<div class="card stat"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
    $("#cards").innerHTML = card(o.events_24h, "events (24h)") + card(o.events_per_sec, "events / sec") + card(o.open_alerts, "open alerts") +
      card(o.critical_open, "critical open") + card(o.open_incidents, "open incidents") + card(`${o.hosts_online}/${o.hosts_total}`, "hosts online");
    const upd = (id, cfg) => { const ex = S.charts.find(c => c.canvas.id === id); if (ex) { ex.data = cfg.data; ex.update("none"); } else mkChart(id, cfg); };
    upd("c1", { type: "bar", data: { labels: o.alerts_timeline.map(h => hhmm(h.hour)),
      datasets: ["critical", "high", "medium", "low"].map(s => ({ label: s, data: o.alerts_timeline.map(h => h[s]), backgroundColor: SEV_COLOR[s] })) },
      options: { scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { labels: { color: "#dbe4f5" } } } } });
    upd("c2", { type: "line", data: { labels: o.events_timeline.map(m => hhmm(m.minute)), datasets: [{ label: "events", data: o.events_timeline.map(m => m.count), borderColor: "#4f9cff", fill: false, tension: .3 }] },
      options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } } });
    upd("c3", { type: "doughnut", data: { labels: o.events_by_source.map(s => s.source), datasets: [{ data: o.events_by_source.map(s => s.count), backgroundColor: ["#4f9cff", "#ff9f43", "#2ecc71", "#ffd166", "#ff4d6d", "#8394b5"] }] },
      options: { plugins: { legend: { position: "right", labels: { color: "#dbe4f5" } } } } });
    $("#tips").innerHTML = table(["IP", "events", "risk"], o.top_ips.map(r => `<tr><td>${ipLink(r.ip)}</td><td>${esc(r.events)}</td>
      <td><div class="bar"><i style="width:${Math.min(r.risk, 100)}%"></i></div><small class="muted">${esc(r.risk)}</small></td></tr>`));
    $("#tusers").innerHTML = table(["user", "failed events"], o.top_users.map(r => `<tr><td><a href="#/investigate/${encodeURIComponent(r.user)}">${esc(r.user)}</a></td><td>${esc(r.events)}</td></tr>`));
  };
  await draw(); every(draw, 10000);
}

/* ------------------------------------------------------------------ live stream */
function live() {
  $("#view").innerHTML = `<div class="row"><span class="muted">Newest first. Showing the last 300 events pushed over the WebSocket. Events seen since you opened the dashboard: <b id="lt">0</b></span></div><div class="card" id="lv"></div>`;
  renderLiveRows();
}
function renderLiveRows() {
  const el = $("#lv"); if (!el) return; $("#lt").textContent = S.liveTotal;
  el.innerHTML = table(["time", "host", "source", "event", "user", "src ip", "outcome"], S.live.map(e => `<tr><td>${esc(hhmm(e.ts))}</td><td>${esc(e.host)}</td>
    <td>${esc(e.source)}</td><td>${badge(e.severity)} ${esc(e.event_type)}</td><td>${esc(e.user || "-")}</td><td>${ipLink(e.src_ip)}</td><td>${esc(e.outcome || "")}</td></tr>`));
}

/* ------------------------------------------------------------------ attack map */
async function mapView() {
  $("#view").innerHTML = `<div id="map"></div><p class="muted">Attacker IPs from alerts of the last 7 days (updates instantly when an alert fires; needs GeoIP: lab IPs use config/geo_overrides.yaml, real IPs use ip-api.com or GeoLite2).</p>`;
  S.map = L.map("map", { worldCopyJump: true }).setView([25, 10], 2);
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 8, attribution: "&copy; OpenStreetMap contributors" }).addTo(S.map);
  const layer = L.layerGroup().addTo(S.map);
  const draw = async () => {
    const o = await api("/api/stats/overview"); layer.clearLayers();
    o.map.forEach(p => L.circleMarker([p.lat, p.lon], { radius: 7 + Math.min(p.alerts, 12), color: SEV_COLOR[p.severity], fillOpacity: .55 }).addTo(layer)
      .bindPopup(`<b>${esc(p.ip)}</b><br>${esc(p.city || "")} ${esc(p.country || "")}<br>${esc(p.alerts)} alert(s), max severity ${esc(p.severity)}<br><a href="#/investigate/${encodeURIComponent(p.ip)}">investigate</a>`));
  };
  S.mapDraw = draw; await draw(); every(draw, 15000);
}

/* ------------------------------------------------------------------ MITRE heatmap */
const TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"];
async function mitre() {
  const [seen, rl] = await Promise.all([api("/api/stats/mitre?days=30"), api("/api/rules")]);
  const cells = {};   // tactic -> technique id -> {name, count, covered}
  rl.rules.forEach(r => { const m = r.mitre || {}; if (m.tactic) ((cells[m.tactic] ??= {})[m.id] ??= { name: m.technique, count: 0 }); });
  seen.forEach(s => { const t = s.tactic || "Other"; const c = ((cells[t] ??= {})[s.id] ??= { name: s.technique, count: 0 }); c.count += s.count; });
  const max = Math.max(1, ...Object.values(cells).flatMap(t => Object.values(t).map(c => c.count)));
  const cols = [...TACTICS, ...Object.keys(cells).filter(t => !TACTICS.includes(t))].filter(t => cells[t]);
  $("#view").innerHTML = `<p class="muted">Columns are ATT&amp;CK tactics. Every technique your rules cover is shown; the colour shows how often it fired in the last 30 days (grey = covered, never seen).</p>
    <div class="heat">${cols.map(t => `<div><h4>${esc(t)}</h4>${Object.entries(cells[t]).map(([id, c]) => {
      const a = c.count ? 0.25 + 0.65 * c.count / max : 0;
      return `<div class="cell" style="background:${c.count ? `rgba(255,77,109,${a})` : "var(--panel2)"}"><b>${esc(c.count)}</b>${esc(id)}<br>${esc(c.name)}</div>`; }).join("")}</div>`).join("")}</div>`;
}

/* ------------------------------------------------------------------ alerts */
async function alerts() {
  const f = alerts.f ??= { status: "new,investigating", severity: "" };
  const r = await api(`/api/alerts?limit=200&status=${f.status}&severity=${f.severity}`);
  $("#view").innerHTML = `<div class="row"><select id="fs"><option value="new,investigating">open</option><option value="new">new</option><option value="investigating">investigating</option><option value="resolved">resolved</option><option value="false_positive">false positive</option><option value="">all</option></select>
    <select id="fv"><option value="">any severity</option>${["critical", "high", "medium", "low"].map(s => `<option>${s}</option>`).join("")}</select>
    <button id="fx" class="sm">Export CSV</button><span class="muted">${esc(r.total)} alert(s)</span></div>
    <div class="card">${table(["last seen", "severity", "rule", "entity", "events", "x", "MITRE", "status", "incident"], r.items.map(a => `<tr class="click" data-id="${a.id}">
      <td>${esc(fmt(a.last_seen))}</td><td>${badge(a.severity)}</td><td>${esc(a.rule_name)}</td><td>${esc(a.entity)}</td><td>${esc(a.count)}</td><td>${esc(a.occurrences)}</td>
      <td>${esc(a.mitre_id || "")}</td><td>${badge(a.status)}</td><td>${a.incident_id ? `<a href="#/incidents/${a.incident_id}">#${a.incident_id}</a>` : ""}</td></tr>`))}</div>`;
  $("#fs").value = f.status; $("#fv").value = f.severity;
  $("#fs").onchange = e => { f.status = e.target.value; alerts(); }; $("#fv").onchange = e => { f.severity = e.target.value; alerts(); };
  $("#fx").onclick = guard(() => download(`/api/alerts/export.csv?status=${f.status}&severity=${f.severity}`, "alerts.csv"));
  document.querySelectorAll("tr.click").forEach(tr => tr.onclick = ev => { if (ev.target.tagName !== "A") guard(alertDetail)(tr.dataset.id); });
}
const eventsTable = evs => table(["time", "host", "event", "user", "src ip", "detail"], evs.map(e => `<tr><td>${esc(fmt(e.ts))}</td><td>${esc(e.host)}</td><td>${esc(e.event_type)}</td>
  <td>${esc(e.user || "-")}</td><td>${ipLink(e.src_ip)}</td><td class="mono">${esc(e.raw_log.slice(0, 200))}</td></tr>`));
const notesHtml = n => n.length ? n.map(x => `<p><b>${esc(x.author)}</b> <span class="muted">${esc(fmt(x.created_at))}</span><br>${esc(x.text)}</p>`).join("") : `<p class="muted">no notes yet</p>`;
async function alertDetail(id) {
  const a = await api("/api/alerts/" + id); const g = a.geo || {};
  openModal(`<h2>${badge(a.severity)} ${esc(a.rule_name)} <small class="muted">#${esc(a.id)}</small></h2><p>${esc(a.description)}</p>
    <p class="muted">${esc(a.entity_type)} <b>${esc(a.entity)}</b> ${g.country ? `- ${esc(g.city || "")} ${esc(g.country)}` : ""} ${a.reputation != null ? `- AbuseIPDB score ${esc(a.reputation)}` : ""}<br>
    MITRE ${esc(a.mitre_id || "-")} ${esc(a.mitre_technique || "")} (${esc(a.mitre_tactic || "")}) - first ${esc(fmt(a.first_seen))}, last ${esc(fmt(a.last_seen))}, re-fired ${esc(a.occurrences)}x</p>
    ${can("analyst") ? `<div class="row"><select id="as">${["new", "investigating", "resolved", "false_positive"].map(s => `<option ${s === a.status ? "selected" : ""}>${s}</option>`).join("")}</select>
      <input id="aa" placeholder="assignee" value="${esc(a.assignee || "")}"><button id="asave" class="primary sm">Save</button>
      ${a.entity_type === "ip" ? `<button id="ablock" class="danger sm">Block ${esc(a.entity)}</button>` : ""}</div>` : ""}
    <h3>Evidence (${a.events.length} events)</h3>${eventsTable(a.events)}<h3 style="margin-top:14px">Notes</h3>${notesHtml(a.notes)}
    ${can("analyst") ? `<div class="row"><input id="nt" style="flex:1" placeholder="add a note"><button id="nadd" class="sm">Add</button></div>` : ""}`);
  if (!can("analyst")) return;
  $("#asave").onclick = guard(async () => { await api("/api/alerts/" + id, { method: "PATCH", body: { status: $("#as").value, assignee: $("#aa").value } }); toast("saved"); closeModal(); alerts(); refreshBadge(); });
  $("#nadd").onclick = guard(async () => { if (!$("#nt").value.trim()) return; await api(`/api/alerts/${id}/notes`, { method: "POST", body: { text: $("#nt").value } }); alertDetail(id); });
  if ($("#ablock")) $("#ablock").onclick = guard(async () => { if (!confirm(`Ask all agents to block ${a.entity} for 60 minutes?`)) return; await api("/api/response/block", { method: "POST", body: { ip: a.entity, minutes: 60, reason: "blocked from alert #" + id } }); toast("block requested"); });
}

/* ------------------------------------------------------------------ incidents */
async function incidents() {
  const r = await api("/api/incidents?limit=200");
  $("#view").innerHTML = `<div class="card">${table(["#", "severity", "title", "entity", "alerts", "status", "last activity"], r.items.map(i => `<tr class="click" onclick="location.hash='#/incidents/${i.id}'">
    <td>${esc(i.id)}</td><td>${badge(i.severity)}</td><td>${esc(i.title)}</td><td>${esc(i.entity)}</td><td>${esc(i.alert_count)}</td><td>${badge(i.status)}</td><td>${esc(fmt(i.last_seen))}</td></tr>`))}</div>`;
}
async function incidentDetail(id) {
  const i = await api("/api/incidents/" + id);
  $("#view").innerHTML = `<p><a href="#/incidents">&larr; all incidents</a></p><div class="card"><h2>${badge(i.severity)} Incident #${esc(i.id)}</h2><p>${esc(i.title)}</p>
    <p class="muted">${esc(i.entity_type)} <b>${esc(i.entity)}</b> - ${esc(i.alert_count)} alert(s) - ${esc(fmt(i.first_seen))} to ${esc(fmt(i.last_seen))}</p>
    ${can("analyst") ? `<div class="row"><select id="is">${["new", "investigating", "resolved", "false_positive"].map(s => `<option ${s === i.status ? "selected" : ""}>${s}</option>`).join("")}</select>
      <input id="ia" placeholder="assignee" value="${esc(i.assignee || "")}"><button id="isave" class="primary sm">Save</button></div>` : badge(i.status)}</div>
    <div class="card" style="margin-top:14px"><h3>Attack timeline</h3><div class="tl">${i.timeline.map(t => t.kind === "alert"
      ? `<div class="it alert"><b>${esc(fmt(t.ts))}</b> ${badge(t.alert.severity)} <b>${esc(t.alert.rule_name)}</b> <span class="muted">${esc(t.alert.mitre_id || "")}</span><br>${esc(t.alert.description)}</div>`
      : `<div class="it"><span class="muted">${esc(fmt(t.ts))}</span> ${esc(t.event.event_type)} ${esc(t.event.user || "")} ${esc(t.event.src_ip || "")} <span class="mono muted">${esc(t.event.raw_log.slice(0, 140))}</span></div>`).join("")}</div></div>
    <div class="card" style="margin-top:14px"><h3>Notes</h3>${notesHtml(i.notes)}${can("analyst") ? `<div class="row"><input id="nt" style="flex:1" placeholder="add a note"><button id="nadd" class="sm">Add</button></div>` : ""}</div>`;
  if (!can("analyst")) return;
  $("#isave").onclick = guard(async () => { await api("/api/incidents/" + id, { method: "PATCH", body: { status: $("#is").value, assignee: $("#ia").value } }); toast("saved"); incidentDetail(id); });
  $("#nadd").onclick = guard(async () => { if (!$("#nt").value.trim()) return; await api(`/api/incidents/${id}/notes`, { method: "POST", body: { text: $("#nt").value } }); incidentDetail(id); });
}

/* ------------------------------------------------------------------ investigate */
async function investigate(q) {
  $("#view").innerHTML = `<div class="row"><input id="iq" style="width:320px" placeholder="IP address or username" value="${esc(q || "")}"><button id="ig" class="primary">Investigate</button></div><div id="ires"></div>`;
  $("#ig").onclick = () => { const v = $("#iq").value.trim(); if (v) location.hash = "#/investigate/" + encodeURIComponent(v); };
  $("#iq").onkeydown = e => { if (e.key === "Enter") $("#ig").click(); };
  if (!q) return;
  const r = await api("/api/investigate?q=" + encodeURIComponent(q)); const g = r.intel || {};
  $("#ires").innerHTML = `<div class="grid g6"><div class="card stat"><div class="n">${esc(r.events_total)}</div><div class="l">events</div></div>
    <div class="card stat"><div class="n">${esc(r.risk)}</div><div class="l">risk score</div></div><div class="card stat"><div class="n">${esc(r.alerts.length)}</div><div class="l">alerts</div></div>
    <div class="card stat"><div class="n">${esc(r.incidents.length)}</div><div class="l">incidents</div></div></div>
    <div class="card" style="margin-top:14px"><b>${esc(r.type)}: ${esc(r.entity)}</b> ${r.blocked ? `<span class="badge critical">blocked</span>` : ""}
      <p class="muted">first seen ${esc(fmt(r.first_seen))} - last seen ${esc(fmt(r.last_seen))}
      ${r.type === "ip" ? `<br>${g.country ? esc((g.city || "") + " " + g.country) : "location unknown"} ${g.asn ? "- " + esc(g.asn) : ""} - AbuseIPDB: ${g.abuse_score != null ? esc(g.abuse_score) : "n/a"}` : ""}</p>
      ${r.type === "ip" && can("analyst") ? `<button id="bk" class="danger sm">Block this IP</button>` : ""}
      <p>${r.by_event_type.map(t => `<span class="badge info">${esc(t.event_type)} ${esc(t.count)}</span> `).join("")}</p>
      ${r.login_sources ? `<p class="muted">logs in from: ${r.login_sources.map(s => `${ipLink(s.ip)} (${esc(s.count)})`).join(", ") || "-"}</p>` : ""}</div>
    <div class="card" style="margin-top:14px"><h3>Alerts</h3>${table(["last seen", "severity", "rule", "status"], r.alerts.map(a => `<tr class="click" onclick="alertDetail(${a.id})"><td>${esc(fmt(a.last_seen))}</td><td>${badge(a.severity)}</td><td>${esc(a.rule_name)}</td><td>${badge(a.status)}</td></tr>`))}</div>
    <div class="card" style="margin-top:14px"><h3>Recent events</h3>${eventsTable(r.recent_events)}</div>`;
  if ($("#bk")) $("#bk").onclick = guard(async () => { if (!confirm("Block " + q + " for 60 minutes on all agents?")) return; await api("/api/response/block", { method: "POST", body: { ip: q, minutes: 60, reason: "manual from investigation" } }); toast("block requested"); investigate(q); });
}
window.alertDetail = guard(alertDetail);

/* ------------------------------------------------------------------ log search */
async function search() {
  const st = search.st ??= { q: "", offset: 0 };
  $("#view").innerHTML = `<div class="row"><input id="sq" style="flex:1;min-width:280px" placeholder='src_ip=1.2.3.4 AND event_type=login_failed' value="${esc(st.q)}"><button id="sg" class="primary">Search</button></div>
    <p class="muted">Fields: ip, src_ip, dst_ip, user, host, source, event_type, outcome, severity, port, text. Operators: = != ~ (contains). Join with AND. Example: <span class="mono">user~adm AND outcome=failure</span></p><div id="sres"></div>`;
  const run = guard(async () => {
    const r = await api(`/api/events?limit=50&offset=${st.offset}&q=${encodeURIComponent(st.q)}`);
    $("#sres").innerHTML = `<div class="row"><span class="muted">${esc(r.total)} result(s)</span><button id="sp" class="sm">&larr; newer</button><button id="sn" class="sm">older &rarr;</button></div><div class="card">${
      table(["time", "host", "source", "event", "user", "src ip", "port", "raw log"], r.items.map(e => `<tr><td>${esc(fmt(e.ts))}</td><td>${esc(e.host)}</td><td>${esc(e.source)}</td><td>${badge(e.severity)} ${esc(e.event_type)}</td>
        <td>${esc(e.user || "-")}</td><td>${ipLink(e.src_ip)}</td><td>${esc(e.dst_port ?? "")}</td><td class="mono">${esc(e.raw_log.slice(0, 300))}</td></tr>`))}</div>`;
    $("#sp").onclick = () => { st.offset = Math.max(0, st.offset - 50); run(); }; $("#sn").onclick = () => { if (st.offset + 50 < r.total) { st.offset += 50; run(); } };
  });
  $("#sg").onclick = () => { st.q = $("#sq").value; st.offset = 0; run(); }; $("#sq").onkeydown = e => { if (e.key === "Enter") $("#sg").click(); };
  run();
}

/* ------------------------------------------------------------------ rules */
async function rules() {
  const r = await api("/api/rules");
  $("#view").innerHTML = `${r.errors.length ? `<div class="card" style="border-color:var(--critical)"><b>Rejected rule files</b>${r.errors.map(e => `<p>${esc(e.file)}: ${esc(e.error)}</p>`).join("")}</div>` : ""}
    ${can("admin") ? `<div class="row"><button id="rnew" class="sm">+ New rule</button></div>` : ""}
    <div class="card">${table(["enabled", "severity", "rule", "type", "MITRE", "logic", ""], r.rules.map(x => `<tr><td>${can("admin") ? `<input type="checkbox" data-t="${esc(x.id)}" ${x.enabled ? "checked" : ""}>` : (x.enabled ? "yes" : "no")}</td>
      <td>${badge(x.severity)}</td><td><b>${esc(x.name)}</b><br><span class="muted">${esc(x.description)}</span></td><td>${esc(x.type)}</td><td>${esc((x.mitre || {}).id || "")}</td>
      <td class="muted">${x.type === "threshold" ? `${esc(x.threshold)} in ${esc(x.window)}s by ${esc(x.group_by)}` : ""}</td><td><button class="sm" data-e="${esc(x.id)}">${can("admin") ? "Edit" : "View"}</button></td></tr>`))}</div>`;
  document.querySelectorAll("[data-t]").forEach(cb => cb.onchange = guard(async () => { await api(`/api/rules/${cb.dataset.t}/toggle`, { method: "POST", body: { enabled: cb.checked } }); toast("rule updated - active within seconds"); }));
  document.querySelectorAll("[data-e]").forEach(b => b.onclick = guard(async () => editRule(b.dataset.e)));
  if ($("#rnew")) $("#rnew").onclick = () => editRule(null);
}
async function editRule(id) {
  const text = id ? (await api("/api/rules/" + id)).yaml : "id: my-new-rule\nname: My new rule\ndescription: what it detects\nseverity: medium\nenabled: true\ntype: threshold\nmitre: {id: T1110, technique: Brute Force, tactic: Credential Access}\nconditions: {event_type: login_failed}\ngroup_by: src_ip\nthreshold: 10\nwindow: 60\n";
  openModal(`<h3>${id ? "Rule: " + esc(id) : "New rule"}</h3><textarea id="ry" rows="22" ${can("admin") ? "" : "readonly"}>${esc(text)}</textarea>
    <div class="err" id="rerr"></div>${can("admin") ? `<div class="row"><button id="rs" class="primary">Save</button><span class="muted">Validated before saving. Active within ~2 seconds, no restart.</span></div>` : ""}`);
  if (can("admin")) $("#rs").onclick = async () => {
    try { await api(id ? "/api/rules/" + id : "/api/rules", { method: id ? "PUT" : "POST", body: { yaml: $("#ry").value } }); toast("rule saved"); closeModal(); rules(); }
    catch (e) { $("#rerr").textContent = e.message; }
  };
}

/* ------------------------------------------------------------------ hosts + response */
async function hostsResponse() {
  const draw = async () => {
    const [h, b] = await Promise.all([api("/api/hosts"), api("/api/response/blocks")]);
    $("#view").innerHTML = `<div class="row"><button id="vi" class="sm">Verify log integrity</button><button id="rp" class="sm">Download PDF report (24h)</button><button id="rp7" class="sm">PDF report (7 days)</button><span id="vres" class="muted"></span></div>
      <div class="card"><h3>Agents / hosts</h3>
        ${can("admin") ? `<div class="row" style="margin-bottom:12px"><input id="new-host" placeholder="Hostname (e.g. lab-vm)" value="lab-vm" style="width:160px"><button id="add-host-btn" class="sm">Create Agent Key</button><span id="new-host-key" style="font-family:monospace;font-weight:bold;color:var(--ok)"></span></div>` : ""}
        ${table(["host", "status", "last seen", "os", "ip", "sources"], h.map(x => `<tr><td>${esc(x.hostname)}</td><td>${badge(x.status)}</td><td>${esc(fmt(x.last_seen))}</td><td>${esc(x.os || "")}</td><td>${esc(x.ip_address || "")}</td><td>${esc((x.sources || []).join(", "))}</td></tr>`))}</div>
      <div class="card" style="margin-top:14px"><h3>Blocked IPs</h3>${can("analyst") ? `<div class="row"><input id="bip" placeholder="IP address"><input id="bmin" type="number" value="60" style="width:90px"><button id="bgo" class="danger sm">Block</button><span class="muted">minutes</span></div>` : ""}
      ${table(["ip", "active", "reason", "source", "created", "expires", ""], b.map(x => `<tr><td>${ipLink(x.ip)}</td><td>${x.active ? `<span class="badge critical">blocked</span>` : "expired"}</td><td>${esc(x.reason)}</td><td>${esc(x.source)}</td><td>${esc(fmt(x.created_at))}</td><td>${esc(x.expires_at ? fmt(x.expires_at) : "never")}</td>
        <td>${x.active && can("analyst") ? `<button class="sm" data-u="${esc(x.ip)}">Unblock</button>` : ""}</td></tr>`))}</div>
      <p class="muted">Agents apply blocks themselves (dry-run unless enabled in their config). Loopback, allow-listed and agent IPs can never be blocked.</p>`;
    $("#vi").onclick = guard(async () => { const r = await api("/api/integrity/verify"); $("#vres").textContent = r.ok ? `Chain intact - ${r.checked} events verified.` : `TAMPERING DETECTED at event #${r.first_bad_id}: ${r.reason}`; $("#vres").style.color = r.ok ? "var(--ok)" : "var(--critical)"; });
    $("#rp").onclick = guard(() => download("/api/reports/summary.pdf?days=1", "siem-report-1d.pdf")); $("#rp7").onclick = guard(() => download("/api/reports/summary.pdf?days=7", "siem-report-7d.pdf"));
    if ($("#add-host-btn")) $("#add-host-btn").onclick = guard(async () => {
      const hname = ($("#new-host").value || "lab-vm").trim();
      const r = await api("/api/hosts", { method: "POST", body: { hostname: hname } });
      $("#new-host-key").textContent = `Key: ${r.api_key}`;
      if (navigator.clipboard) navigator.clipboard.writeText(r.api_key);
      toast("Agent key created!");
      draw();
    });
    if ($("#bgo")) $("#bgo").onclick = guard(async () => { await api("/api/response/block", { method: "POST", body: { ip: $("#bip").value.trim(), minutes: +$("#bmin").value || 60, reason: "manual block" } }); toast("block requested"); draw(); });
    document.querySelectorAll("[data-u]").forEach(x => x.onclick = guard(async () => { await api("/api/response/unblock", { method: "POST", body: { ip: x.dataset.u } }); toast("unblock requested"); draw(); }));
  };
  await draw(); every(draw, 20000);
}

/* ------------------------------------------------------------------ admin */
async function admin() {
  if (!can("admin")) { $("#view").innerHTML = `<p class="muted">Admins only.</p>`; return; }
  const [u, a] = await Promise.all([api("/api/users"), api("/api/audit?limit=200")]);
  $("#view").innerHTML = `<div class="card"><h3>Users</h3><div class="row"><input id="nu" placeholder="username"><input id="np" type="password" placeholder="password (8+ chars)"><select id="nr"><option>viewer</option><option>analyst</option><option>admin</option></select><button id="nadd" class="primary sm">Create</button></div>
    ${table(["id", "user", "role", "last login", ""], u.map(x => `<tr><td>${esc(x.id)}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${esc(fmt(x.last_login))}</td><td><button class="sm danger" data-d="${x.id}">Delete</button></td></tr>`))}</div>
    <div class="card" style="margin-top:14px"><h3>Audit log</h3>${table(["time", "who", "action", "target", "details", "from"], a.map(x => `<tr><td>${esc(fmt(x.ts))}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${esc(x.target || "")}</td><td class="mono">${esc(x.details ? JSON.stringify(x.details) : "")}</td><td>${esc(x.client_ip || "")}</td></tr>`))}</div>`;
  $("#nadd").onclick = guard(async () => { await api("/api/users", { method: "POST", body: { username: $("#nu").value, password: $("#np").value, role: $("#nr").value } }); toast("user created"); admin(); });
  document.querySelectorAll("[data-d]").forEach(b => b.onclick = guard(async () => { if (confirm("Delete this user?")) { await api("/api/users/" + b.dataset.d, { method: "DELETE" }); admin(); } }));
}


/* ------------------------------------------------------------------ threat hunting (KQL) */
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/, TS_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d/;
function cellHtml(col, v) {
  if (v === null || v === undefined) return '<span class="muted">null</span>';
  if (Array.isArray(v)) return esc(v.join(", "));
  if (typeof v === "object") return `<span class="mono">${esc(JSON.stringify(v))}</span>`;
  if (typeof v === "string" && TS_RE.test(v)) return esc(fmt(v));
  if (typeof v === "string" && IP_RE.test(v)) return `<a href="#/graph/${encodeURIComponent(v)}">${esc(v)}</a>`;
  if (col === "user" && v) return `<a href="#/graph/${encodeURIComponent(v)}">${esc(v)}</a>`;
  return esc(v);
}
async function hunt() {
  const st = hunt.st ??= { q: 'events\n| where event_type == "login_failed"\n| summarize attempts = count(), users = dcount(user) by src_ip\n| top 10 by attempts desc', win: "24h", last: null };
  const [lib, bms, sched] = await Promise.all([api("/api/hunt/library"), api("/api/hunt/bookmarks"), api("/api/hunt/scheduled")]);
  $("#view").innerHTML = `<div class="card"><textarea id="hq" rows="7" spellcheck="false">${esc(st.q)}</textarea>
    <div class="row" style="margin-top:8px"><select id="hw">${["1h", "6h", "24h", "7d", "30d"].map(w => `<option ${w === st.win ? "selected" : ""}>${w}</option>`).join("")}</select>
      <button id="hrun" class="primary">Run (Ctrl+Enter)</button>
      ${can("analyst") ? `<button id="hsave" class="sm">Save query</button><button id="hrule" class="sm">Create alert rule&hellip;</button>` : ""}
      <a href="https://learn.microsoft.com/en-us/kusto/query/" target="_blank" rel="noopener" class="muted">KQL basics</a><span id="hinfo" class="muted"></span></div>
    <div class="err" id="herr"></div><div id="hres"></div></div>
    <div class="grid g2" style="margin-top:14px"><div class="card"><h3>Query library</h3><div id="hlib">${lib.map((q, i) => `<p style="margin:0 0 8px"><a href="#" data-l="${i}"><b>${esc(q.name)}</b></a> <span class="muted">${esc(q.tactic || "")}</span><br><span class="muted">${esc(q.description || "")}</span>${!q.builtin && can("analyst") ? ` <button class="sm" data-dq="${q.id}">delete</button>` : ""}</p>`).join("")}</div></div>
    <div class="card"><h3>Bookmarks</h3>${bms.length ? bms.map(b => `<p style="margin:0 0 8px"><b>${esc(b.title)}</b> <span class="muted">${esc(b.created_by)} &middot; ${esc(fmt(b.created_at))}</span><br>${esc(b.note || "")}
      ${b.entity ? `<a href="#/graph/${encodeURIComponent(b.entity)}">${esc(b.entity)}</a>` : ""} ${can("analyst") ? `<button class="sm" data-db="${b.id}">remove</button>` : ""}</p>`).join("") : '<p class="muted">Bookmark interesting result rows to keep them as evidence.</p>'}
      <h3 style="margin-top:14px">Scheduled detections</h3>${table(["rule", "every", "last run", "rows", ""], sched.map(r => `<tr><td>${esc(r.name)}<br><span class="muted">${esc(r.last_error || "")}</span></td><td>${esc(r.run_every_minutes)}m</td><td>${esc(fmt(r.last_run))}</td><td>${esc(r.last_count ?? "-")}</td>
      <td>${can("admin") ? `<input type="checkbox" data-st="${r.id}" ${r.enabled ? "checked" : ""}> <button class="sm" data-sd="${r.id}">delete</button>` : (r.enabled ? "on" : "off")}</td></tr>`))}</div></div>`;
  const q = () => ($("#hq").value = $("#hq").value);
  const run = guard(async () => {
    st.q = $("#hq").value; st.win = $("#hw").value; $("#herr").textContent = ""; $("#hinfo").textContent = " running...";
    try {
      const r = await api("/api/hunt/query", { method: "POST", body: { query: st.q, window: st.win } });
      st.last = r; $("#hinfo").textContent = ` ${r.rows.length} row(s)${r.truncated ? " (truncated)" : ""} - scanned ${r.scanned} - ${r.ms} ms`;
      $("#hres").innerHTML = table(["", ...r.columns], r.rows.map((row, i) => `<tr><td>${can("analyst") ? `<button class="sm" data-bm="${i}" title="bookmark this row">&#9733;</button>` : ""}</td>${row.map((v, j) => `<td>${cellHtml(r.columns[j], v)}</td>`).join("")}</tr>`));
      document.querySelectorAll("[data-bm]").forEach(b => b.onclick = guard(async () => {
        const row = Object.fromEntries(r.columns.map((c, j) => [c, r.rows[+b.dataset.bm][j]]));
        const ent = Object.values(row).find(v => typeof v === "string" && IP_RE.test(v)) || row.user || null;
        const title = prompt("Bookmark title", ent ? `Suspicious: ${ent}` : "Interesting row"); if (!title) return;
        const note = prompt("Note (optional)") || "";
        await api("/api/hunt/bookmarks", { method: "POST", body: { title, note, query: st.q, row, entity: ent, entity_type: ent && IP_RE.test(ent) ? "ip" : (ent ? "user" : null) } });
        toast("bookmarked"); hunt();
      }));
    } catch (e) { $("#hinfo").textContent = ""; $("#herr").textContent = e.message; $("#hres").innerHTML = ""; }
  });
  $("#hrun").onclick = run; $("#hq").onkeydown = e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } };
  document.querySelectorAll("[data-l]").forEach(a => a.onclick = e => { e.preventDefault(); $("#hq").value = lib[+a.dataset.l].query.trim(); st.q = $("#hq").value; run(); });
  document.querySelectorAll("[data-dq]").forEach(b => b.onclick = guard(async () => { await api("/api/hunt/saved/" + b.dataset.dq, { method: "DELETE" }); hunt(); }));
  document.querySelectorAll("[data-db]").forEach(b => b.onclick = guard(async () => { await api("/api/hunt/bookmarks/" + b.dataset.db, { method: "DELETE" }); hunt(); }));
  document.querySelectorAll("[data-st]").forEach(b => b.onchange = guard(async () => { await api("/api/hunt/scheduled/" + b.dataset.st, { method: "PATCH", body: { enabled: b.checked } }); toast("updated"); }));
  document.querySelectorAll("[data-sd]").forEach(b => b.onclick = guard(async () => { if (confirm("Delete this scheduled detection?")) { await api("/api/hunt/scheduled/" + b.dataset.sd, { method: "DELETE" }); hunt(); } }));
  if ($("#hsave")) $("#hsave").onclick = guard(async () => {
    const name = prompt("Name for this query"); if (!name) return;
    await api("/api/hunt/saved", { method: "POST", body: { name, description: prompt("Description (optional)") || "", query: $("#hq").value } }); toast("saved"); hunt();
  });
  if ($("#hrule")) $("#hrule").onclick = () => ruleForm(st);
}
function ruleForm(st) {
  const col = st.last && st.last.columns.length ? st.last.columns[0] : "";
  openModal(`<h3>Turn this query into a scheduled detection</h3><p class="muted">The query runs on a schedule; each result row raises an alert (de-duplicated). Run it first so you know it returns what you expect.</p>
    <div class="row"><input id="rn" placeholder="Rule name" style="flex:1"><select id="rs">${["low", "medium", "high", "critical"].map(s => `<option ${s === "medium" ? "selected" : ""}>${s}</option>`).join("")}</select></div>
    <div class="row"><label>Look back <select id="rw">${["1h", "6h", "24h", "7d"].map(w => `<option>${w}</option>`).join("")}</select></label><label>Run every <input id="re" type="number" value="15" style="width:70px"> min</label>
      <label>Alert if rows &ge; <input id="rt" type="number" value="1" style="width:70px"></label></div>
    <div class="row"><label>Entity column <input id="rc" value="${esc(col)}" style="width:130px"></label><select id="ry2"><option>ip</option><option>user</option><option>host</option></select>
      <input id="rm1" placeholder="MITRE id (T1110)" style="width:130px"><input id="rm2" placeholder="technique" style="width:150px"><input id="rm3" placeholder="tactic" style="width:130px"></div>
    <textarea id="rq" rows="6">${esc(st.q)}</textarea><div class="err" id="rerr2"></div><button id="rgo" class="primary">Create rule</button>`);
  $("#rgo").onclick = async () => {
    try {
      await api("/api/hunt/to-rule", { method: "POST", body: { name: $("#rn").value, severity: $("#rs").value, query: $("#rq").value, window: $("#rw").value,
        run_every_minutes: +$("#re").value, threshold: +$("#rt").value, entity_column: $("#rc").value || null, entity_type: $("#ry2").value,
        mitre: $("#rm1").value ? { id: $("#rm1").value, technique: $("#rm2").value, tactic: $("#rm3").value } : {} } });
      toast("scheduled detection created"); closeModal(); hunt();
    } catch (e) { $("#rerr2").textContent = e.message; }
  };
}

/* ------------------------------------------------------------------ investigation graph */
const NODE_COLOR = { ip: "#ff5476", user: "#5aa2ff", host: "#41d08a", incident: "#b48cff" };
async function graphView(q) {
  $("#view").innerHTML = `<div class="row"><input id="gq" style="width:280px" placeholder="IP, username or host" value="${esc(q || "")}"><select id="gt"><option value="">auto-detect</option><option>ip</option><option>user</option><option>host</option></select>
    <select id="gh"><option value="1">1 hour</option><option value="24" selected>24 hours</option><option value="168">7 days</option></select><button id="gg" class="primary">Show graph</button></div>
    <div class="card"><svg id="gsvg" viewBox="0 0 900 580" width="100%" role="img" aria-label="investigation graph"></svg></div>
    <p class="muted" id="ginfo">Click a node to re-centre the graph on it (alerts and incidents open their details). Edge labels show the activity between two entities.</p>`;
  const go = () => { const v = $("#gq").value.trim(); if (v) { graphView.opts = { t: $("#gt").value, h: $("#gh").value }; location.hash = "#/graph/" + encodeURIComponent(v); if (v === q) graphView(q); } };
  $("#gg").onclick = go; $("#gq").onkeydown = e => { if (e.key === "Enter") go(); };
  if (!q) return;
  const o = graphView.opts || { t: "", h: "24" }; $("#gt").value = o.t; $("#gh").value = o.h;
  const g = await api(`/api/graph?entity=${encodeURIComponent(q)}&hours=${o.h}${o.t ? "&type=" + o.t : ""}`);
  const W = 900, H = 580, cx = W / 2, cy = H / 2 - 10, pos = {};
  const center = g.nodes.find(n => n.center), ents = g.nodes.filter(n => !n.center && ["ip", "user", "host"].includes(n.type)), outer = g.nodes.filter(n => n.type === "alert" || n.type === "incident");
  if (center) pos[center.id] = [cx, cy];
  ents.sort((a, b) => a.type.localeCompare(b.type) || b.size - a.size).forEach((n, i) => { const a = (2 * Math.PI * i) / Math.max(ents.length, 1) - Math.PI / 2; pos[n.id] = [cx + 200 * Math.cos(a), cy + 165 * Math.sin(a)]; });
  outer.forEach((n, i) => { const a = (2 * Math.PI * (i + .5)) / Math.max(outer.length, 1) + Math.PI / 2; pos[n.id] = [cx + 345 * Math.cos(a), cy + 250 * Math.sin(a)]; });
  const col = n => n.type === "alert" ? SEV_COLOR[n.severity] || "#7a8aa8" : NODE_COLOR[n.type] || "#7a8aa8";
  const lines = g.edges.filter(e => pos[e.source] && pos[e.target]).map(e => {
    const [x1, y1] = pos[e.source], [x2, y2] = pos[e.target];
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${e.kind === "alert" ? "#ff9f43" : e.kind === "incident" ? "#b48cff" : "#6b7ea6"}" stroke-width="${Math.min(1 + Math.log2(e.weight + 1), 5)}" opacity=".7"/>` +
      (e.kind === "activity" ? `<text x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2}" font-size="10" text-anchor="middle" fill="currentColor" opacity=".8">${esc(e.label)}</text>` : "");
  }).join("");
  const dots = g.nodes.filter(n => pos[n.id]).map(n => {
    const [x, y] = pos[n.id], r = 9 + Math.min(n.size, 40) / 4 + (n.center ? 6 : 0), lab = String(n.label).length > 24 ? String(n.label).slice(0, 23) + "…" : n.label;
    const shape = n.type === "incident" ? `<rect x="${x - r}" y="${y - r}" width="${2 * r}" height="${2 * r}" rx="4" fill="${col(n)}"/>` : n.type === "alert" ? `<polygon points="${x},${y - r - 2} ${x + r + 2},${y + r} ${x - r - 2},${y + r}" fill="${col(n)}"/>` :
      `<circle cx="${x}" cy="${y}" r="${r}" fill="${col(n)}" ${n.center ? 'stroke="currentColor" stroke-width="3"' : ""}/>`;
    return `<g class="gn" data-t="${esc(n.type)}" data-v="${esc(n.type === "alert" || n.type === "incident" ? n.ref : n.label)}" style="cursor:pointer">${shape}<title>${esc(n.type)}: ${esc(n.title || n.label)}${n.risk ? " - risk " + esc(n.risk) : ""}</title>
      <text x="${x}" y="${y + r + 14}" font-size="11.5" text-anchor="middle" fill="currentColor">${esc(lab)}</text></g>`;
  }).join("");
  $("#gsvg").innerHTML = lines + dots;
  $("#ginfo").textContent = `${g.nodes.length} nodes, ${g.edges.length} links around ${g.entity_type} ${q} (last ${g.hours}h). Click a node to re-centre; triangles are alerts, squares are incidents.`;
  document.querySelectorAll(".gn").forEach(n => n.onclick = () => {
    const t = n.dataset.t, v = n.dataset.v;
    if (t === "alert") alertDetail(v); else if (t === "incident") location.hash = "#/incidents/" + v; else { graphView.opts = { t, h: o.h }; location.hash = "#/graph/" + encodeURIComponent(v); }
  });
}

/* ------------------------------------------------------------------ watchlists */
async function watchlists(sel) {
  const lists = await api("/api/watchlists"); sel = sel ?? watchlists.sel ?? (lists[0] && lists[0].id); watchlists.sel = sel;
  const cur = sel ? await api("/api/watchlists/" + sel) : null;
  $("#view").innerHTML = `<div class="grid g2"><div class="card"><h3>Watchlists</h3>${lists.map(w => `<p style="margin:0 0 8px"><a href="#" data-w="${w.id}"><b>${esc(w.name)}</b></a> <span class="badge info">${esc(w.count)}</span><br><span class="muted">${esc(w.description || "")}</span></p>`).join("")}
      ${can("analyst") ? `<div class="row"><input id="wn" placeholder="new_list_name"><input id="wd" placeholder="description" style="flex:1"><button id="wc" class="sm">Create</button></div>` : ""}
      <p class="muted">Use them in rules (<span class="mono">user: {watchlist: vip_users}</span>, <span class="mono">exclude: {src_ip: {watchlist: trusted_ips}}</span>), in queries (<span class="mono">_GetWatchlist("name")</span>) and in automation rules.</p></div>
    <div class="card">${cur ? `<h3>${esc(cur.name)} <small class="muted">${cur.items.length} item(s)</small></h3>${can("analyst") ? `<textarea id="wi" rows="4" placeholder="one value per line, optional note after a comma&#10;10.0.0.5, my laptop"></textarea>
      <div class="row"><label>expire after <input id="we" type="number" placeholder="hours" style="width:80px"></label><button id="wa" class="primary sm">Add items</button>${can("admin") ? `<button id="wx" class="danger sm">Delete list</button>` : ""}</div>` : ""}
      ${table(["value", "note", "added by", "expires", ""], cur.items.map(i => `<tr><td class="mono">${esc(i.value)}</td><td>${esc(i.note || "")}</td><td>${esc(i.added_by)}</td><td>${esc(i.expires_at ? fmt(i.expires_at) : "never")}</td><td>${can("analyst") ? `<button class="sm" data-x="${i.id}">remove</button>` : ""}</td></tr>`))}` : '<p class="muted">Select a watchlist.</p>'}</div></div>`;
  document.querySelectorAll("[data-w]").forEach(a => a.onclick = e => { e.preventDefault(); watchlists(+a.dataset.w); });
  if ($("#wc")) $("#wc").onclick = guard(async () => { const r = await api("/api/watchlists", { method: "POST", body: { name: $("#wn").value, description: $("#wd").value } }); watchlists(r.id); });
  if ($("#wa")) $("#wa").onclick = guard(async () => { const r = await api(`/api/watchlists/${sel}/items`, { method: "POST", body: { text: $("#wi").value, expires_hours: +$("#we").value || null } }); toast(`${r.added} added`); watchlists(sel); });
  if ($("#wx")) $("#wx").onclick = guard(async () => { if (confirm("Delete this watchlist and all its items?")) { await api("/api/watchlists/" + sel, { method: "DELETE" }); watchlists.sel = null; watchlists(); } });
  document.querySelectorAll("[data-x]").forEach(b => b.onclick = guard(async () => { await api(`/api/watchlists/${sel}/items/${b.dataset.x}`, { method: "DELETE" }); watchlists(sel); }));
}

/* ------------------------------------------------------------------ threat intelligence */
async function intel() {
  const draw = async () => {
    const [s, man] = await Promise.all([api("/api/ti/status"), api("/api/ti/indicators")]);
    $("#view").innerHTML = `<div class="card"><h3>Feeds <small class="muted">${esc(s.index_size)} indicators loaded for matching</small></h3>
      ${can("admin") ? `<div class="row"><button id="tsync" class="primary sm">Sync all feeds now</button><span class="muted">Needs internet. Only public IPs are imported; the rule <b>threat-intel-match</b> alerts when an event comes from a listed IP and raises other alerts from that IP by one severity level.</span></div>` : ""}
      ${table(["feed", "enabled", "indicators", "last sync", "status"], s.feeds.map(f => `<tr><td><b>${esc(f.name)}</b><br><span class="muted mono">${esc(f.url)}</span></td><td>${f.enabled ? "yes" : "no"}</td><td>${esc(f.count)}</td><td>${esc(f.last_sync ? fmt(f.last_sync) : "never")}</td><td>${f.last_error ? `<span style="color:var(--critical)">${esc(f.last_error)}</span>` : "ok"}</td></tr>`))}</div>
      <div class="grid g2" style="margin-top:14px"><div class="card"><h3>Check an IP</h3><div class="row"><input id="tip" placeholder="IP address"><button id="tgo" class="sm">Lookup</button></div><div id="tres" class="muted"></div></div>
      <div class="card"><h3>Your own indicators (${esc(s.manual)})</h3>${can("analyst") ? `<div class="row"><input id="tni" placeholder="public IP or CIDR"><button id="tadd" class="sm">Add</button></div>` : ""}
      ${table(["indicator", "source", ""], man.filter(i => i.source === "manual").map(i => `<tr><td class="mono">${esc(i.indicator)}</td><td>${esc(i.source)}</td><td>${can("analyst") ? `<button class="sm" data-ti="${i.id}">remove</button>` : ""}</td></tr>`))}</div></div>`;
    if ($("#tsync")) $("#tsync").onclick = guard(async () => { await api("/api/ti/sync", { method: "POST", body: {} }); toast("sync started - refresh in a minute"); });
    $("#tgo").onclick = guard(async () => { const r = await api("/api/ti/lookup?ip=" + encodeURIComponent($("#tip").value)); $("#tres").innerHTML = r.feed ? `<b style="color:var(--critical)">${esc(r.ip)} is listed by ${esc(r.feed)}</b>` : `${esc(r.ip)} is not on any loaded feed`; });
    if ($("#tadd")) $("#tadd").onclick = guard(async () => { await api("/api/ti/indicators", { method: "POST", body: { indicator: $("#tni").value } }); draw(); });
    document.querySelectorAll("[data-ti]").forEach(b => b.onclick = guard(async () => { await api("/api/ti/indicators/" + b.dataset.ti, { method: "DELETE" }); draw(); }));
  };
  await draw(); every(draw, 30000);
}

/* ------------------------------------------------------------------ automation rules */
const AUTO_TEMPLATE = { name: "Assign high alerts to on-call", enabled: true, order: 50, conditions: { severity: ["high", "critical"] },
  actions: [{ type: "assign", to: "oncall" }, { type: "add_note", text: "Auto-assigned by automation rule" }] };
async function automationView() {
  const rs = await api("/api/automation");
  $("#view").innerHTML = `<p class="muted">Rules run in order (lowest first) on every NEW alert. Conditions: rule_id, severity, entity_type, mitre_tactic, host, name_contains, entity_in_watchlist, entity_not_in_watchlist.
    Actions: assign, set_status, set_severity, add_note, block_ip, notify, stop.</p>${can("admin") ? '<div class="row"><button id="anew" class="sm">+ New automation rule</button></div>' : ""}
    <div class="card">${table(["on", "order", "rule", "when", "then", "fired", ""], rs.map(r => `<tr><td>${can("admin") ? `<input type="checkbox" data-t="${r.id}" ${r.enabled ? "checked" : ""}>` : (r.enabled ? "yes" : "no")}</td><td>${esc(r.order)}</td><td><b>${esc(r.name)}</b><br><span class="muted">${r.expires_at ? "expires " + esc(fmt(r.expires_at)) : ""}</span></td>
      <td class="mono">${esc(JSON.stringify(r.conditions))}</td><td class="mono">${esc(r.actions.map(a => a.type + (a.to ? ":" + a.to : a.status ? ":" + a.status : "")).join(", "))}</td><td>${esc(r.trigger_count)}x<br><span class="muted">${esc(r.last_triggered ? fmt(r.last_triggered) : "")}</span></td>
      <td>${can("admin") ? `<button class="sm" data-e="${r.id}">edit</button> <button class="sm danger" data-d="${r.id}">delete</button>` : ""}</td></tr>`))}</div>`;
  const edit = (r) => {
    openModal(`<h3>${r ? "Edit" : "New"} automation rule</h3><textarea id="aj" rows="16" spellcheck="false">${esc(JSON.stringify(r ? { name: r.name, enabled: r.enabled, order: r.order, conditions: r.conditions, actions: r.actions, expires_at: r.expires_at } : AUTO_TEMPLATE, null, 2))}</textarea>
      <div class="err" id="aerr"></div><button id="asv" class="primary">Save</button>`);
    $("#asv").onclick = async () => {
      let body; try { body = JSON.parse($("#aj").value); } catch (e) { $("#aerr").textContent = "not valid JSON: " + e.message; return; }
      try { await api(r ? "/api/automation/" + r.id : "/api/automation", { method: r ? "PUT" : "POST", body }); toast("saved - active within seconds"); closeModal(); automationView(); } catch (e) { $("#aerr").textContent = e.message; }
    };
  };
  if ($("#anew")) $("#anew").onclick = () => edit(null);
  document.querySelectorAll("[data-e]").forEach(b => b.onclick = () => edit(rs.find(r => r.id === +b.dataset.e)));
  document.querySelectorAll("[data-d]").forEach(b => b.onclick = guard(async () => { if (confirm("Delete this rule?")) { await api("/api/automation/" + b.dataset.d, { method: "DELETE" }); automationView(); } }));
  document.querySelectorAll("[data-t]").forEach(b => b.onchange = guard(async () => { const r = rs.find(x => x.id === +b.dataset.t); await api("/api/automation/" + r.id, { method: "PUT", body: { name: r.name, enabled: b.checked, order: r.order, conditions: r.conditions, actions: r.actions, expires_at: r.expires_at } }); toast("updated"); }));
}

/* ------------------------------------------------------------------ boot */
$("#lb").onclick = doLogin; $("#lp").onkeydown = e => { if (e.key === "Enter") doLogin(); };
$("#logout").onclick = logout; $("#mclose").onclick = closeModal; $("#modal").onclick = e => { if (e.target.id === "modal") closeModal(); };
window.addEventListener("hashchange", nav);
if (S.token) showApp();
