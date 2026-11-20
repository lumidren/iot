"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));
const TIER_LABEL = { MONITOR: "Monitor", RESTRICT: "Restrict", QUARANTINE: "Quarantine", BLOCK: "Block" };

let state = null;
let selected = null; // device id whose latest alert is shown; null = latest overall
let pinnedAlert = null;
const seenAlerts = new Set();
let selectsReady = false;

function clock(t) {
  const day = Math.floor(t / 86400) + 1;
  const h = (t % 86400) / 3600;
  const hh = String(Math.floor(h)).padStart(2, "0");
  const mm = String(Math.floor((h % 1) * 60)).padStart(2, "0");
  return `Day ${day}, ${hh}:${mm}`;
}

function deviceName(id) {
  const d = state?.devices.find((x) => x.id === id);
  return d ? d.name : id;
}

function spark(series) {
  const w = 220, h = 42, n = 90;
  const pts = series.map((v, i) => {
    const x = (i + (n - series.length)) * (w / (n - 1));
    const y = h - 2 - (Math.min(v, 100) / 100) * (h - 4);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const line = (v, c) => {
    const y = h - 2 - (v / 100) * (h - 4);
    return `<line x1="0" x2="${w}" y1="${y}" y2="${y}" stroke="${c}" stroke-dasharray="3 4" stroke-width="1" opacity=".45"/>`;
  };
  const last = series.length ? series[series.length - 1] : 0;
  const color = last >= 86 ? "var(--block)" : last >= 61 ? "var(--quarantine)" : last >= 31 ? "var(--restrict)" : "var(--accent)";
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
    ${line(31, "var(--restrict)")}${line(61, "var(--quarantine)")}${line(86, "var(--block)")}
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>
  </svg>`;
}

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

function renderDevices() {
  $("#devices").innerHTML = state.devices.map((d) => {
    const learning = d.phase !== "protected";
    const badge = learning
      ? `<span class="badge learning">${d.phase === "learning-rules" ? "Learning · rules" : "Learning · ranges"}</span>`
      : `<span class="badge ${d.tier}">${TIER_LABEL[d.tier]}</span>`;
    const release = d.tier !== "MONITOR"
      ? `<button class="ghost" data-release="${d.id}">Release</button>` : "";
    const attack = d.under_attack.length
      ? `<div class="attack">⚠ under attack: ${esc(d.under_attack.join(", "))}</div>` : "";
    const notice = d.notice ? `<div class="notice ${d.notice.level}" role="alert">
        <b>${d.notice.level === "large" ? "Big behavior change" : "Behavior change"}</b>
        <span>${esc(d.notice.question)}</span>
        <span class="muted">${Math.round(d.notice.drift * 100)}% of its traffic looked unusual · ${d.notice.new_destinations} new destination(s)</span>
        <div class="buttons">
          <button class="ghost" data-drift="${d.id}" data-accept="1">Yes, relearn it</button>
          <button class="ghost" data-drift="${d.id}" data-accept="0">No, keep watching</button>
        </div>
      </div>` : "";
    const updated = d.updated ? `<div class="meta">firmware updated (simulated)</div>` : "";
    return `<article class="device ${d.tier}" data-device="${d.id}" tabindex="0"
        aria-label="${esc(d.name)}: ${TIER_LABEL[d.tier]}, threat ${Math.round(d.threat)} of 100">
      <div class="head">
        <div><div class="name">${esc(d.name)}</div>
        <div class="meta">${esc(d.hardware)} · ${esc(d.address)}</div></div>
        ${badge}
      </div>
      <div class="threat"><b>${Math.round(d.threat)}</b><small>/100 threat</small></div>
      ${spark(d.series)}
      ${attack}${updated}${notice}
      <div class="foot"><span>${d.packets} pkts · ${fmtBytes(d.bytes)} / 10 s</span>${release}</div>
    </article>`;
  }).join("");
}

function layer(name, value) {
  return `<div class="layer">${name}<b style="float:right">${Math.round(value)}</b>
    <div class="bar"><i style="width:${Math.min(100, value)}%"></i></div></div>`;
}

function renderDetail() {
  const alerts = state.alerts;
  let a = pinnedAlert;
  if (!a) a = selected ? alerts.find((x) => x.device === selected) : alerts[0];
  if (!a || !a.explanation) {
    $("#detail-body").className = "empty";
    $("#detail-body").innerHTML = selected
      ? `${esc(deviceName(selected))} has not raised an alert. It is acting like itself.`
      : "No alerts yet. Every device is acting like itself.";
    $("#detail-time").textContent = "";
    return;
  }
  const e = a.explanation;
  const dev = state.devices.find((d) => d.id === a.device);
  const tier = a.action ? a.action.after : a.tier;
  $("#detail-time").textContent = clock(a.t);
  const reasons = e.reasons.map((r) => `<li>
      <div class="r-head"><span>${esc(r.title)}</span><span class="sev ${r.severity}">${r.severity}</span></div>
      ${(r.normal || r.observed) ? `<div class="kv">
        ${r.normal ? `<span>Normal</span><span>${esc(r.normal)}</span>` : ""}
        ${r.observed ? `<span>Detected</span><span>${esc(r.observed)}</span>` : ""}
      </div>` : ""}
      ${r.detail ? `<div class="note">${esc(r.detail)}</div>` : ""}
    </li>`).join("");
  const actions = e.actions.length
    ? `<div><b>Recommended</b><ul class="actions">${e.actions.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : "";
  const buttons = dev && dev.tier !== "MONITOR" ? `<div class="buttons">
      <button class="ghost" data-release="${a.device}" data-trust="1">That was me: release and learn</button>
      <button class="ghost" data-release="${a.device}" data-trust="0">Release, keep watching</button>
    </div>` : "";
  $("#detail-body").className = "";
  $("#detail-body").innerHTML = `<div class="alert-box">
      <div class="alert-title ${tier}">
        <div><strong>${esc(e.device)}: ${TIER_LABEL[tier] || tier}</strong>
        <div class="likely">Likely: <b>${esc(e.likely_attack)}</b></div></div>
        <div class="score">${Math.round(a.threat)}<small style="font-size:12px;color:var(--muted)">/100</small></div>
      </div>
      <div class="alert-body">
        <div class="layers">${layer("ML", a.components.ml)}${layer("Ranges", a.components.stat)}${layer("Identity", a.components.identity)}</div>
        <div><b>Why</b><ol class="reasons">${reasons}</ol></div>
        ${actions}
        ${buttons}
      </div>
    </div>`;
}

function renderFeed() {
  const items = [];
  for (const a of state.alerts) {
    items.push({ t: a.t, device: a.device, tier: a.action ? a.action.after : a.tier,
      text: a.explanation ? a.explanation.likely_attack : "", alert: a });
  }
  for (const act of state.actions) {
    if (!state.alerts.some((a) => a.action && a.t === act.t && a.device === act.device)) {
      items.push({ t: act.t, device: act.device, tier: act.after, text: act.reason });
    }
  }
  items.sort((x, y) => y.t - x.t);
  $("#feed").innerHTML = items.slice(0, 40).map((it, i) => `<li data-feed="${i}">
      <span class="when">${clock(it.t)}</span>
      <span class="what">${esc(deviceName(it.device))} → <b class="${it.tier}">${TIER_LABEL[it.tier] || it.tier}</b></span>
      <span class="muted">${esc(it.text)}</span>
    </li>`).join("") || `<li class="muted">Nothing yet.</li>`;
  $("#feed").dataset.items = JSON.stringify(items.slice(0, 40).map((x) => x.alert ? x.alert : null));
}

function renderRules() {
  const act = state.actions[0];
  $("#rules").textContent = act
    ? `# ${clock(act.t)} · ${deviceName(act.device)}: ${act.before} → ${act.after}\n# ${act.reason}\n` + act.commands.join("\n")
    : "No rules applied yet.";
}

function renderSummary() {
  const protectedN = state.devices.filter((d) => d.phase === "protected").length;
  const contained = state.devices.filter((d) => d.tier === "QUARANTINE" || d.tier === "BLOCK").length;
  state.alerts.forEach((a) => seenAlerts.add(`${a.device}:${a.t}`));
  $("#k-protected").textContent = `${protectedN}/${state.devices.length}`;
  $("#k-contained").textContent = contained;
  $("#k-alerts").textContent = seenAlerts.size;
  const status = $("#status");
  status.classList.toggle("alert", contained > 0);
  $("#status-text").textContent = contained
    ? `${contained} device${contained > 1 ? "s" : ""} contained`
    : "Every device is acting like itself";
  $("#active-attacks").innerHTML = state.attacks.map((a) =>
    `<span class="chip">${esc(a.label)} → ${esc(deviceName(a.device))}</span>`).join("");
}

function setupSelects() {
  if (selectsReady || !state.devices.length) return;
  $("#atk-device").innerHTML = state.devices.map((d) =>
    `<option value="${d.id}">${esc(d.name)} (${esc(d.hardware)})</option>`).join("");
  $("#atk-kind").innerHTML = state.attack_kinds.map((k) =>
    `<option value="${k.id}">${esc(k.label)}</option>`).join("");
  selectsReady = true;
}

function render() {
  if (!state) return;
  if (!state.ready) {
    $("#progress").textContent = state.progress;
    return;
  }
  $("#loading").hidden = true;
  $("#app").hidden = false;
  $("#clock").textContent = state.clock;
  // keep the speed buttons in step with the server (another tab may have changed it)
  document.querySelectorAll("[data-speed]").forEach((b) =>
    b.classList.toggle("on", !state.paused && Math.abs(Number(b.dataset.speed) - state.speed) < 0.5));
  $("#pause").classList.toggle("on", state.paused);
  setupSelects();
  renderSummary();
  renderDevices();
  renderDetail();
  renderFeed();
  renderRules();
}

async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  return r.json();
}

document.addEventListener("click", async (ev) => {
  const drift = ev.target.closest("[data-drift]");
  if (drift) {
    ev.stopPropagation();
    await post("/api/drift", { device: drift.dataset.drift, accept: drift.dataset.accept === "1" });
    return;
  }
  const rel = ev.target.closest("[data-release]");
  if (rel) {
    ev.stopPropagation();
    await post("/api/release", { device: rel.dataset.release, trust: rel.dataset.trust !== "0" });
    pinnedAlert = null;
    return;
  }
  const card = ev.target.closest("[data-device]");
  if (card) {
    selected = selected === card.dataset.device ? null : card.dataset.device;
    pinnedAlert = null;
    renderDetail();
    return;
  }
  const feed = ev.target.closest("[data-feed]");
  if (feed) {
    const items = JSON.parse($("#feed").dataset.items || "[]");
    pinnedAlert = items[Number(feed.dataset.feed)] || null;
    renderDetail();
  }
});

document.addEventListener("keydown", (ev) => {
  // device cards act like buttons for keyboard users
  if ((ev.key === "Enter" || ev.key === " ") && ev.target.matches("[data-device]")) {
    ev.preventDefault();
    ev.target.click();
  }
});

$("#update").addEventListener("click", async () => {
  const device = $("#atk-device").value;
  await post("/api/update", { device });
  selected = device;
});

$("#launch").addEventListener("click", async () => {
  const device = $("#atk-device").value;
  await post("/api/attack", { device, kind: $("#atk-kind").value });
  selected = device;
  pinnedAlert = null;
});

document.querySelectorAll("[data-speed]").forEach((b) => b.addEventListener("click", async () => {
  await post("/api/speed", { speed: Number(b.dataset.speed), paused: false });
  document.querySelectorAll("[data-speed]").forEach((x) => x.classList.toggle("on", x === b));
  $("#pause").classList.remove("on");
}));
$("#pause").addEventListener("click", async () => {
  const paused = !$("#pause").classList.contains("on");
  await post("/api/speed", { paused });
  $("#pause").classList.toggle("on", paused);
});

async function poll() {
  try {
    state = await (await fetch("/api/state")).json();
    render();
  } catch (e) { /* server restarting */ }
  setTimeout(poll, 1000);
}

function connect() {
  // ?poll=1 uses plain requests instead of a stream (proxies, headless capture)
  if (new URLSearchParams(location.search).has("poll") || !window.EventSource) return poll();
  const es = new EventSource("/api/stream");
  es.onmessage = (m) => { state = JSON.parse(m.data); render(); };
  es.onerror = () => { es.close(); setTimeout(connect, 1500); };
}
connect();
