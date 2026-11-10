// GoCertMITM web UI.
//
// All data rendered here (hostnames, SNI, paths, headers, bodies, log lines)
// is attacker controlled. It is only ever inserted via textContent / DOM
// APIs — never innerHTML — and the page runs under a script-src 'self' CSP.

"use strict";

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

const TEST_INFO = {
  "self-signed": {
    short: "SS",
    name: "Self-signed",
    what: "Leaf signed by the GoCertMITM CA, which the client has no reason to trust. Acceptance means the chain is not validated at all.",
  },
  "replaced-key": {
    short: "RK",
    name: "Replaced key",
    what: "The server's real certificate with its public key swapped, so the signature no longer verifies. Acceptance means signatures are not checked.",
  },
  "real-cert": {
    short: "WH",
    name: "Wrong host",
    what: "A valid, publicly trusted certificate issued for a different hostname. Acceptance means hostname verification is missing.",
  },
  "real-ca": {
    short: "LC",
    name: "Leaf as CA",
    what: "A certificate for the target signed by a valid end-entity certificate (CA:FALSE). Acceptance means basicConstraints are not enforced.",
  },
  emudhra: {
    short: "EM",
    name: "eMudhra CA",
    what: "Signed with the leaked eMudhra intermediate key, serving the chain to emSign ECC Root CA - G3 first. Acceptance means a modern trust store still trusts the compromised CA (no revocation/CT enforcement). Go 1.27+ clients hard-distrust these keys.",
  },
  "emudhra-aaa": {
    short: "EA",
    name: "eMudhra via AAA",
    what: "Same leaked key, serving the Sectigo AAA Certificate Services cross-sign first. Acceptance means an older or frozen trust store still trusts the compromised CA.",
  },
  "direct-tunnel": { short: "DT", name: "Tunnel", what: "All tests rejected; traffic is passed through without interception." },
};

const VERDICT_LABEL = { vulnerable: "Vulnerable", secure: "Secure", testing: "Testing" };
const STATE_GLYPH = { accepted: "!", rejected: "✓", current: "•", pending: "–" };
const STATE_LABEL = { accepted: "Accepted (vulnerable)", rejected: "Rejected", current: "Being tested", pending: "Not tested yet" };

const MAX_REQUESTS = 2000;
const MAX_HANDSHAKES = 1000;
const MAX_LOGS = 3000;
const MAX_FEED = 200;
const VIEW_BYTES = 256 * 1024;

/* ------------------------------------------------------------------ */
/* DOM helpers                                                        */
/* ------------------------------------------------------------------ */

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, String(v));
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  shield: ["M12 3l7 3v6c0 4.4-3 8.3-7 9-4-.7-7-4.6-7-9V6l7-3z", "M9 12l2 2 4-4"],
  refresh: ["M20 11a8 8 0 0 0-14.9-3.5L4 9", "M4 4v5h5", "M4 13a8 8 0 0 0 14.9 3.5L20 15", "M20 20v-5h-5"],
  trash: ["M4 7h16", "M9 7V4h6v3", "M6 7l1 13h10l1-13"],
  download: ["M12 4v11", "M7 10l5 5 5-5", "M5 20h14"],
  pause: ["M8 5v14", "M16 5v14"],
  play: ["M7 5l12 7-12 7z"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  lock: ["M6 11h12v9H6z", "M9 11V8a3 3 0 0 1 6 0v3"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
  moon: ["M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"],
  eraser: ["M4 20h16", "M7 16l9-9 4 4-6 6H9z"],
};

function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

/* ------------------------------------------------------------------ */
/* Formatting                                                         */
/* ------------------------------------------------------------------ */

function fmtTime(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return "";
  return d.toLocaleTimeString([], { hour12: false });
}

function fmtDateTime(ts) {
  const d = new Date(ts);
  if (isNaN(d) || d.getFullYear() < 2000) return "—";
  return d.toLocaleString([], { hour12: false });
}

function fmtRel(ts) {
  const d = new Date(ts);
  if (isNaN(d) || d.getFullYear() < 2000) return "—";
  let s = Math.round((Date.now() - d.getTime()) / 1000);
  const future = s < 0;
  s = Math.abs(s);
  let out;
  if (s < 45) out = `${s}s`;
  else if (s < 3600) out = `${Math.round(s / 60)}m`;
  else if (s < 86400) out = `${Math.round(s / 3600)}h`;
  else out = `${Math.round(s / 86400)}d`;
  return future ? `in ${out}` : `${out} ago`;
}

function fmtBytes(n) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtDuration(ms) {
  if (ms == null) return "";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtUptime(ts) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${hr}h`;
  if (hr) return `${hr}h ${m}m`;
  return `${m}m ${s % 60}s`;
}

function testName(key) {
  return (TEST_INFO[key] && TEST_INFO[key].name) || key || "—";
}

function hostOnly(host) {
  if (!host) return "";
  if (host.startsWith("[")) return host.slice(1, host.indexOf("]"));
  const i = host.lastIndexOf(":");
  return i > -1 && host.indexOf(":") === i ? host.slice(0, i) : host;
}

// Mirrors sanitizePathComponent in internal/logging/payload_logger.go
function payloadDirFor(host) {
  if (!host) return "unknown-host";
  let s = "";
  for (const ch of host) {
    const c = ch.codePointAt(0);
    s += ch === "/" || ch === "\\" || c < 32 || c === 127 ? "_" : ch;
  }
  return s === "." || s === ".." ? "unknown-host" : s;
}

function displayName(d) {
  return d.domain && d.domain !== d.key ? d.domain : d.key;
}

/* ------------------------------------------------------------------ */
/* API                                                                */
/* ------------------------------------------------------------------ */

async function api(path, opts = {}) {
  const init = { credentials: "same-origin", ...opts, headers: { ...(opts.headers || {}) } };
  if (init.method && init.method !== "GET") init.headers["X-CertMITM-CSRF"] = "1";
  const res = await fetch(path, init);
  if (res.status === 401) {
    location.href = "/login";
    throw new Error("unauthenticated");
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) { /* not JSON */ }
    throw new Error(msg);
  }
  return res;
}

const getJSON = async (path) => (await api(path)).json();

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

const state = {
  info: null,
  stats: null,
  domains: new Map(),
  requests: [],
  handshakes: [],
  logs: [],
  feed: [],
  connected: false,
  lastEventId: 0,
  flash: new Set(),
};

function pushCapped(arr, item, max) {
  arr.push(item);
  if (arr.length > max) arr.splice(0, arr.length - max);
}

function feedPush(item) {
  state.feed.unshift(item);
  if (state.feed.length > MAX_FEED) state.feed.length = MAX_FEED;
}

function applyDomain(ev, live) {
  const d = ev.data;
  const prev = state.domains.get(d.key);
  if (d.verdict === "deleted") {
    state.domains.delete(d.key);
    return;
  }
  state.domains.set(d.key, d);
  if (!live) return;
  state.flash.add(d.key);

  const name = displayName(d);
  if (!prev) {
    feedPush({ time: ev.time, tone: "info", text: [h("strong", { text: name }), " — new target, testing ", h("span", { class: "mono", text: testName(d.current_test) })] });
  } else if (prev.verdict !== d.verdict) {
    if (d.verdict === "vulnerable") {
      feedPush({ time: ev.time, tone: "danger", key: d.key, text: [h("strong", { text: name }), " accepted ", h("strong", { text: testName(d.accepted_test) }), " — client is vulnerable"] });
      toast(`${name}: accepted ${testName(d.accepted_test)}`);
    } else if (d.verdict === "secure") {
      feedPush({ time: ev.time, tone: "ok", key: d.key, text: [h("strong", { text: name }), " rejected every test — now tunnelled"] });
    } else if (d.verdict === "testing") {
      feedPush({ time: ev.time, tone: "info", key: d.key, text: [h("strong", { text: name }), " — retesting"] });
    }
  }
}

function applyHandshake(ev, live) {
  pushCapped(state.handshakes, ev, MAX_HANDSHAKES);
  if (live) {
    const d = ev.data;
    feedPush({
      time: ev.time,
      tone: "warn",
      key: d.sni,
      text: [h("strong", { text: d.sni }), " rejected ", h("span", { class: "mono", text: testName(d.test_type) }), h("div", { class: "sub", text: `${d.client_ip} · ${d.error}` })],
    });
  }
}

function applyEvent(ev, live) {
  if (ev.id > state.lastEventId) state.lastEventId = ev.id;
  switch (ev.topic) {
    case "domain": applyDomain(ev, live); break;
    case "request": pushCapped(state.requests, ev, MAX_REQUESTS); break;
    case "handshake": applyHandshake(ev, live); break;
    case "log": pushCapped(state.logs, ev, MAX_LOGS); break;
  }
}

async function loadSnapshots() {
  const [info, stats, domains, requests, handshakes, logs] = await Promise.all([
    getJSON("/api/info"),
    getJSON("/api/stats"),
    getJSON("/api/domains"),
    getJSON(`/api/events?topic=request&limit=${MAX_REQUESTS}`),
    getJSON(`/api/events?topic=handshake&limit=${MAX_HANDSHAKES}`),
    getJSON(`/api/events?topic=log&limit=${MAX_LOGS}`),
  ]);
  state.info = info;
  state.stats = stats;
  state.domains = new Map(domains.map((d) => [d.key, d]));
  state.requests = requests;
  state.handshakes = handshakes;
  state.logs = logs;
  document.getElementById("logout-form").hidden = !info.auth_enabled;

  // Seed the activity feed from history so the overview is not empty
  if (state.feed.length === 0) {
    for (const ev of handshakes.slice(-30)) applyHandshake(ev, true);
    const vulnerable = domains.filter((d) => d.verdict === "vulnerable").slice(0, 20).reverse();
    for (const d of vulnerable) {
      feedPush({ time: d.last_tested, tone: "danger", key: d.key, text: [h("strong", { text: displayName(d) }), " accepted ", h("strong", { text: testName(d.accepted_test) })] });
    }
    state.feed.sort((a, b) => new Date(b.time) - new Date(a.time));
  }
  logsView.reset();
  scheduleUpdate();
}

let source = null;
let reconnectTimer = null;

function connect() {
  if (source) source.close();
  source = new EventSource("/api/stream");
  source.onopen = () => {
    setLive(true);
  };
  source.onerror = () => {
    setLive(false);
    if (source.readyState === EventSource.CLOSED) scheduleReconnect();
  };
  for (const topic of ["domain", "request", "handshake", "log"]) {
    source.addEventListener(topic, (e) => {
      try {
        applyEvent(JSON.parse(e.data), true);
        scheduleUpdate(topic);
      } catch (_) { /* ignore malformed */ }
    });
  }
  // The server drops subscribers that fall behind; reload and reconnect
  source.addEventListener("resync", () => {
    source.close();
    scheduleReconnect(0);
  });
}

function scheduleReconnect(delay = 3000) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(async () => {
    try {
      await loadSnapshots();
    } catch (_) { /* retry below */ }
    connect();
  }, delay);
}

function setLive(on) {
  state.connected = on;
  const el = document.getElementById("live");
  el.classList.toggle("on", on);
  el.classList.toggle("off", !on);
  el.firstElementChild.textContent = on ? "Live" : "Reconnecting…";
}

async function refreshStats() {
  try {
    state.stats = await getJSON("/api/stats");
    scheduleUpdate("stats");
  } catch (_) { /* transient */ }
}

/* ------------------------------------------------------------------ */
/* Rendering scheduler                                                */
/* ------------------------------------------------------------------ */

let currentView = null;
let updatePending = false;
const dirty = new Set();
const ALL_TOPICS = ["domain", "request", "handshake", "log", "stats"];

// Views declare the topics they render; a view (and an open drawer) only
// re-renders when one of those changed, so a chatty debug log does not
// repaint the domain table or reset the drawer scroll position.
function scheduleUpdate(...topics) {
  for (const t of topics.length ? topics : ALL_TOPICS) dirty.add(t);
  if (updatePending) return;
  updatePending = true;
  requestAnimationFrame(() => {
    updatePending = false;
    const changed = new Set(dirty);
    dirty.clear();
    const touches = (list) => list.some((t) => changed.has(t));
    if (changed.has("domain")) updateNavBadge();
    if (currentView && touches(currentView.topics)) currentView.update();
    if (drawer.refresh && touches(["domain", "request", "handshake"])) {
      const body = document.getElementById("drawer-body");
      const top = body.scrollTop;
      drawer.refresh();
      body.scrollTop = top;
    }
    state.flash.clear();
  });
}

function updateNavBadge() {
  const n = [...state.domains.values()].filter((d) => d.verdict === "vulnerable").length;
  const el = document.getElementById("vuln-count");
  el.hidden = n === 0;
  el.textContent = String(n);
}

let toastTimer = null;
function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

/* ------------------------------------------------------------------ */
/* Shared components                                                  */
/* ------------------------------------------------------------------ */

function verdictBadge(v) {
  return h("span", { class: `badge ${v}`, text: VERDICT_LABEL[v] || v });
}

function testOrder() {
  return state.info ? state.info.tester.test_order.map((t) => t.key) : [];
}

function matrix(d) {
  const byKey = new Map(d.tests.map((t) => [t.key, t]));
  return h("div", { class: "matrix" }, testOrder().map((key) => {
    const t = byKey.get(key) || { state: "pending", attempts: 0 };
    const info = TEST_INFO[key] || { short: "?", name: key };
    return h("span", {
      class: `mx ${t.state}`,
      title: `${info.name}: ${STATE_LABEL[t.state]}${t.attempts ? ` (${t.attempts} attempt${t.attempts > 1 ? "s" : ""})` : ""}`,
      text: STATE_GLYPH[t.state],
    });
  }));
}

function matrixHeader() {
  return h("div", { class: "matrix" }, testOrder().map((key) => {
    const info = TEST_INFO[key] || { short: "?", name: key };
    return h("span", { class: "mx", title: info.name, text: info.short });
  }));
}

function legend() {
  return h("div", { class: "legend" },
    ["accepted", "rejected", "current", "pending"].map((s) =>
      h("span", null, h("span", { class: `mx ${s}`, text: STATE_GLYPH[s] }), STATE_LABEL[s])));
}

function statusCell(r) {
  if (r.error) return h("span", { class: "status err", title: r.error, text: "ERR" });
  return h("span", { class: `status s${String(r.status)[0]}`, text: String(r.status || "—") });
}

function emptyState(title, text) {
  return h("div", { class: "empty" }, h("strong", { text: title }), text);
}

function seg(options, value, onChange) {
  return h("div", { class: "seg", role: "group" }, options.map((o) =>
    h("button", {
      type: "button",
      "aria-pressed": String(o.value === value),
      onclick: () => onChange(o.value),
    }, o.label, o.count != null ? h("span", { class: "n", text: String(o.count) }) : null)));
}

function rowLink(onOpen, cells) {
  return h("tr", {
    class: "row-link",
    tabindex: "0",
    onclick: onOpen,
    onkeydown: (e) => { if (e.key === "Enter") onOpen(); },
  }, cells);
}

/* ------------------------------------------------------------------ */
/* Drawer                                                             */
/* ------------------------------------------------------------------ */

const drawer = {
  refresh: null,
  lastFocus: null,

  open(title, sub, body, refresh = null) {
    const el = document.getElementById("drawer");
    document.getElementById("drawer-title").textContent = title;
    document.getElementById("drawer-sub").textContent = sub || "";
    clear(document.getElementById("drawer-body")).append(body);
    this.refresh = refresh;
    if (!document.body.classList.contains("drawer-open")) this.lastFocus = document.activeElement;
    el.hidden = false;
    requestAnimationFrame(() => document.body.classList.add("drawer-open"));
    document.getElementById("drawer-close").focus();
  },

  close() {
    document.body.classList.remove("drawer-open");
    this.refresh = null;
    setTimeout(() => {
      if (!document.body.classList.contains("drawer-open")) document.getElementById("drawer").hidden = true;
    }, 200);
    if (this.lastFocus && this.lastFocus.focus) this.lastFocus.focus();
  },
};

function openDomain(key) {
  const body = h("div");
  const render = () => {
    const d = state.domains.get(key);
    clear(body);
    if (!d) {
      body.append(emptyState("Domain removed", "This domain is no longer tracked."));
      return;
    }
    document.getElementById("drawer-title").textContent = displayName(d);

    const actions = h("div", { class: "toolbar card" },
      verdictBadge(d.verdict),
      h("span", { class: "spacer" }),
      h("button", {
        class: "btn sm", type: "button", title: "Clear results and run the full test sequence again",
        onclick: async () => {
          try {
            await api(`/api/domains/${encodeURIComponent(key)}/reset`, { method: "POST" });
            toast(`Reset ${displayName(d)}`);
          } catch (e) { toast(`Reset failed: ${e.message}`); }
        },
      }, icon("refresh"), "Retest"),
      h("button", {
        class: "btn sm danger", type: "button",
        onclick: async () => {
          if (!confirm(`Forget all results for ${displayName(d)}?`)) return;
          try {
            await api(`/api/domains/${encodeURIComponent(key)}`, { method: "DELETE" });
            state.domains.delete(key);
            drawer.close();
            scheduleUpdate("domain");
            toast(`Deleted ${displayName(d)}`);
          } catch (e) { toast(`Delete failed: ${e.message}`); }
        },
      }, icon("trash"), "Forget"));

    const ips = d.ips && d.ips.length ? d.ips : d.ip ? [d.ip] : [];
    const tests = h("div", { class: "tests-list" }, testOrder().map((k) => {
      const t = d.tests.find((x) => x.key === k) || { state: "pending", attempts: 0 };
      const info = TEST_INFO[k] || { name: k, what: "" };
      return h("div", { class: "test-row" },
        h("span", { class: `mx ${t.state}`, text: STATE_GLYPH[t.state] }),
        h("div", null, h("div", { class: "name", text: info.name }), h("div", { class: "desc", text: info.what })),
        h("div", { class: "muted nowrap", text: `${STATE_LABEL[t.state]}${t.attempts ? ` · ${t.attempts}×` : ""}` }));
    }));

    const host = d.domain || d.key;
    const reqs = state.requests.filter((ev) => hostOnly(ev.data.host) === host || hostOnly(ev.data.host) === d.key).slice(-50).reverse();
    const rejections = state.handshakes.filter((ev) => ev.data.sni === host || ev.data.sni === d.key).slice(-20).reverse();

    body.append(
      actions,
      h("div", { class: "section" },
        h("h3", { text: "Target" }),
        h("dl", { class: "kv" },
          h("dt", { text: "Key" }), h("dd", { class: "mono", text: d.key }),
          h("dt", { text: "Hostname" }), h("dd", { text: d.domain || "—" }),
          h("dt", { text: "Addresses" }), h("dd", { class: "mono", text: ips.join(", ") || "—" }),
          h("dt", { text: "Accepted test" }), h("dd", { text: d.accepted_test ? testName(d.accepted_test) : "—" }),
          h("dt", { text: "Last tested" }), h("dd", { text: `${fmtDateTime(d.last_tested)} (${fmtRel(d.last_tested)})` }),
          h("dt", { text: "Automatic retest" }), h("dd", { text: `${fmtDateTime(d.retest_due)} (${fmtRel(d.retest_due)})` }))),
      h("div", { class: "section" }, h("h3", { text: "Certificate tests" }), tests),
      h("div", { class: "section" },
        h("h3", { text: `Decrypted / proxied requests (${reqs.length})` }),
        reqs.length ? h("div", { class: "card" }, requestTable(reqs, false)) : h("div", { class: "note", text: "No requests seen in this session." })),
      rejections.length ? h("div", { class: "section" },
        h("h3", { text: `TLS rejections (${rejections.length})` }),
        h("div", { class: "card" }, handshakeTable(rejections))) : null,
    );
  };
  drawer.open(key, "Domain", body, render);
  render();
}

function openExchange(host, reqId, ev) {
  const dir = payloadDirFor(host);
  const body = h("div");
  const r = ev && ev.data;

  if (r) {
    body.append(h("div", { class: "section" },
      h("h3", { text: "Request" }),
      h("dl", { class: "kv" },
        h("dt", { text: "Time" }), h("dd", { text: fmtDateTime(ev.time) }),
        h("dt", { text: "Client" }), h("dd", { class: "mono", text: r.client_ip }),
        h("dt", { text: "URL" }), h("dd", { class: "mono", text: `${r.scheme}://${r.host}${r.path}${r.query ? `?${r.query}` : ""}` }),
        h("dt", { text: "Method" }), h("dd", { class: "mono", text: r.method }),
        h("dt", { text: "Status" }), h("dd", null, statusCell(r)),
        r.error ? [h("dt", { text: "Error" }), h("dd", { class: "mono", text: r.error })] : null,
        h("dt", { text: "Accepted certificate" }), h("dd", { text: r.scheme === "https" ? testName(r.test_type) : "— (plain HTTP)" }),
        h("dt", { text: "Sizes" }), h("dd", { text: `${fmtBytes(r.req_bytes)} sent · ${fmtBytes(r.resp_bytes)} received` }),
        h("dt", { text: "Duration" }), h("dd", { text: fmtDuration(r.duration_ms) }),
        h("dt", { text: "Request ID" }), h("dd", { class: "mono", text: r.req_id }))));
  }

  const payloads = h("div", { class: "section" }, h("h3", { text: "Captured payloads" }), h("div", { class: "note", text: "Loading…" }));
  body.append(payloads);

  drawer.open(r ? `${r.method} ${hostOnly(r.host)}${r.path}` : host, reqId, body);

  if (r && !r.saved) {
    clear(payloads).append(h("h3", { text: "Captured payloads" }), h("div", { class: "note", text: "Payload saving was disabled for this request (-savepayloads=false)." }));
    return;
  }

  getJSON(`/api/payloads/${encodeURIComponent(dir)}?id=${encodeURIComponent(reqId)}`)
    .then((list) => {
      clear(payloads).append(h("h3", { text: "Captured payloads" }));
      const ex = list[0];
      if (!ex) {
        payloads.append(h("div", { class: "note", text: "No payload files found on disk for this request." }));
        return;
      }
      const parts = [
        ["Request headers", ex.request_meta],
        ["Request body", ex.request_body],
        ["Response headers", ex.response_meta],
        ["Response body", ex.response_body],
      ];
      for (const [title, f] of parts) {
        if (f) payloads.append(payloadBlock(dir, title, f));
      }
    })
    .catch((e) => {
      clear(payloads).append(h("h3", { text: "Captured payloads" }), h("div", { class: "note", text: `Could not load payloads: ${e.message}` }));
    });
}

function isBinary(text) {
  const sample = text.slice(0, 4096);
  if (sample.includes("\u0000")) return true;
  let bad = 0;
  for (const ch of sample) {
    const c = ch.codePointAt(0);
    if (c === 0xfffd || (c < 32 && c !== 9 && c !== 10 && c !== 13)) bad++;
  }
  return sample.length > 0 && bad / sample.length > 0.1;
}

function hexDump(bytes) {
  const lines = [];
  const n = Math.min(bytes.length, 8192);
  for (let off = 0; off < n; off += 16) {
    const row = bytes.slice(off, Math.min(off + 16, n));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (bytes.length > n) lines.push(`… ${bytes.length - n} more bytes`);
  return lines.join("\n");
}

function prettyMaybe(text) {
  const t = text.trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { /* not JSON */ }
  }
  return text;
}

function payloadBlock(dir, title, file) {
  const url = `/api/payloads/${encodeURIComponent(dir)}/${encodeURIComponent(file.name)}`;
  const pre = h("pre", { class: "code", text: "Loading…" });
  const note = h("span", { class: "note" });
  let mode = "text";
  let raw = null;
  let bytes = null;

  const modeBtn = h("button", { class: "btn sm", type: "button", hidden: true });
  const draw = () => {
    if (raw == null) return;
    pre.textContent = mode === "hex" ? hexDump(bytes) : prettyMaybe(raw);
    modeBtn.textContent = mode === "hex" ? "Text" : "Hex";
  };
  modeBtn.addEventListener("click", () => { mode = mode === "hex" ? "text" : "hex"; draw(); });

  api(`${url}?max=${VIEW_BYTES}`)
    .then(async (res) => {
      const truncated = res.headers.get("X-Payload-Truncated") === "1";
      bytes = new Uint8Array(await res.arrayBuffer());
      raw = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      if (file.name.endsWith(".body") && isBinary(raw)) mode = "hex";
      modeBtn.hidden = !file.name.endsWith(".body");
      note.textContent = `${fmtBytes(file.size)}${truncated ? ` · showing first ${fmtBytes(VIEW_BYTES)}` : ""}`;
      draw();
    })
    .catch((e) => { pre.textContent = `Failed to load: ${e.message}`; });

  return h("div", { class: "payload-block" },
    h("div", { class: "payload-head" },
      h("span", { class: "title", text: title }), note,
      h("span", { class: "spacer" }),
      modeBtn,
      h("a", { class: "btn sm", href: `${url}?download=1`, download: "" }, icon("download"), "Raw")),
    pre);
}

/* ------------------------------------------------------------------ */
/* Tables                                                             */
/* ------------------------------------------------------------------ */

function requestTable(events, withClient = true) {
  return h("div", { class: "table-wrap" }, h("table", null,
    h("thead", null, h("tr", null,
      h("th", { text: "Time" }),
      withClient ? h("th", { class: "hide-sm", text: "Client" }) : null,
      h("th", { text: "Request" }),
      h("th", { text: "Status" }),
      h("th", { class: "num hide-sm", text: "Size" }),
      h("th", { class: "hide-sm", text: "Certificate" }),
      h("th", { class: "num hide-sm", text: "Time" }))),
    h("tbody", null, events.map((ev) => {
      const r = ev.data;
      return rowLink(() => openExchange(r.host, r.req_id, ev), [
        h("td", { class: "nowrap muted mono", text: fmtTime(ev.time) }),
        withClient ? h("td", { class: "nowrap mono hide-sm", text: r.client_ip }) : null,
        h("td", null,
          h("div", { class: "cell-main truncate" },
            r.scheme === "https" ? h("span", { class: "lock", title: "Decrypted TLS (MITM)" }, icon("lock")) : null, " ",
            h("span", { class: "method", text: r.method }), " ", hostOnly(r.host)),
          h("div", { class: "cell-sub truncate", text: r.path + (r.query ? `?${r.query}` : "") })),
        h("td", null, statusCell(r)),
        h("td", { class: "num nowrap hide-sm", text: fmtBytes(r.resp_bytes) }),
        h("td", { class: "nowrap hide-sm" }, r.scheme === "https" ? h("span", { class: "badge vulnerable plain", text: testName(r.test_type) }) : h("span", { class: "muted", text: "plain" })),
        h("td", { class: "num nowrap muted hide-sm", text: fmtDuration(r.duration_ms) }),
      ]);
    }))));
}

function handshakeTable(events) {
  return h("div", { class: "table-wrap" }, h("table", null,
    h("thead", null, h("tr", null,
      h("th", { text: "Time" }), h("th", { text: "Client" }), h("th", { text: "SNI" }), h("th", { text: "Rejected" }), h("th", { class: "hide-sm", text: "Error" }))),
    h("tbody", null, events.map((ev) => {
      const d = ev.data;
      const known = state.domains.has(d.sni);
      const cells = [
        h("td", { class: "nowrap muted mono", text: fmtTime(ev.time) }),
        h("td", { class: "nowrap mono", text: d.client_ip }),
        h("td", { class: "cell-main", text: d.sni }),
        h("td", { class: "nowrap" }, h("span", { class: "badge secure plain", text: testName(d.test_type) })),
        h("td", { class: "muted mono truncate hide-sm", title: d.error, text: d.error }),
      ];
      return known ? rowLink(() => openDomain(d.sni), cells) : h("tr", null, cells);
    }))));
}

/* ------------------------------------------------------------------ */
/* Views                                                              */
/* ------------------------------------------------------------------ */

const overviewView = {
  topics: ["domain", "handshake", "stats"],

  mount(root) {
    this.tiles = h("div", { class: "tiles" });
    this.findings = h("div", { class: "card-body flush" });
    this.feed = h("ul", { class: "feed" });
    this.clients = h("div", { class: "card-body flush" });
    this.findingsSub = h("span", { class: "sub" });
    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Overview" }), h("p", { text: "Which clients accept forged certificates, as it happens." }))),
      this.tiles,
      h("div", { class: "grid grid-2" },
        h("div", { class: "grid" },
          h("section", { class: "card" },
            h("div", { class: "card-head" }, h("h2", { text: "Findings" }), this.findingsSub),
            this.findings),
          h("section", { class: "card" },
            h("div", { class: "card-head" }, h("h2", { text: "Active clients" })),
            this.clients)),
        h("section", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Activity" }), h("span", { class: "sub", text: "verdicts & TLS rejections" })),
          h("div", { class: "card-body flush" }, this.feed))));
  },

  update() {
    const s = state.stats;
    const domains = [...state.domains.values()];
    const count = (v) => domains.filter((d) => d.verdict === v).length;
    const vuln = count("vulnerable");

    const tile = (label, value, hint, tone) => h("div", { class: `tile ${tone || ""}` },
      h("div", { class: "label", text: label }), h("div", { class: "value", text: String(value) }), hint ? h("div", { class: "hint", text: hint }) : null);

    clear(this.tiles).append(
      tile("Vulnerable", vuln, "accepted a forged cert", vuln ? "danger" : ""),
      tile("Testing", count("testing"), "tests in progress", "warn"),
      tile("Secure", count("secure"), "rejected all · tunnelled", "ok"),
      tile("Decrypted requests", s ? s.mitm_requests : "—", s ? `${s.requests} total proxied` : ""),
      tile("TLS rejections", s ? s.handshake_failures : "—", "aborted handshakes"),
      tile("Uptime", s ? fmtUptime(s.start_time) : "—", s ? `${Object.keys(s.active_clients || {}).length} active clients` : ""));

    // Findings
    const vulnList = domains.filter((d) => d.verdict === "vulnerable");
    this.findingsSub.textContent = `${vulnList.length} vulnerable`;
    clear(this.findings);
    if (!vulnList.length) {
      this.findings.append(emptyState("No findings yet", "Domains whose clients accept a forged certificate will appear here."));
    } else {
      this.findings.append(h("ul", { class: "findings" }, vulnList.map((d) => h("li", {
        tabindex: "0",
        onclick: () => openDomain(d.key),
        onkeydown: (e) => { if (e.key === "Enter") openDomain(d.key); },
      },
      h("div", { class: "grow" },
        h("div", { class: "cell-main", text: displayName(d) }),
        h("div", { class: "cell-sub", text: (d.ips && d.ips.length ? d.ips.slice(0, 3).join(", ") : d.ip) || "" })),
      h("span", { class: "badge vulnerable", text: testName(d.accepted_test) }),
      h("span", { class: "muted nowrap", text: fmtRel(d.last_tested) })))));
    }

    // Clients
    const clients = Object.entries((s && s.active_clients) || {}).sort((a, b) => b[1] - a[1]);
    clear(this.clients).append(clients.length
      ? h("table", null, h("tbody", null, clients.map(([ip, n]) => h("tr", null,
        h("td", { class: "mono", text: ip }),
        h("td", { class: "num muted", text: `${n} open connection${n === 1 ? "" : "s"}` })))))
      : emptyState("No active clients", "Route a device through the proxy to begin."));

    // Feed
    clear(this.feed);
    if (!state.feed.length) {
      this.feed.append(h("li", { class: "empty" }, "Waiting for activity…"));
    }
    for (const item of state.feed.slice(0, 100)) {
      this.feed.append(h("li", {
        class: item.key && state.domains.has(item.key) ? "row-link" : null,
        onclick: item.key && state.domains.has(item.key) ? () => openDomain(item.key) : null,
      },
      h("span", { class: "t", text: fmtTime(item.time) }),
      h("span", { class: `dot ${item.tone}` }),
      h("div", { class: "msg" }, item.text.map((n) => (n instanceof Node ? n.cloneNode(true) : n)))));
    }
  },
};

const domainsView = {
  topics: ["domain"],
  filter: "all",
  query: "",

  mount(root) {
    this.segWrap = h("span");
    this.tbody = h("tbody");
    this.headMatrix = h("th", { class: "hide-sm" });
    this.footer = h("div", { class: "note" });
    const search = h("input", {
      type: "search", placeholder: "Filter by domain or IP…", "aria-label": "Filter domains", value: this.query,
      oninput: (e) => { this.query = e.target.value.trim().toLowerCase(); this.update(); },
    });

    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Domains" }), h("p", { text: "Per-target certificate test results. Click a row for details, traffic and controls." })),
        h("div", { class: "toolbar bare" },
          h("a", { class: "btn", href: "/api/export.csv", download: "" }, icon("download"), "CSV"),
          h("a", { class: "btn", href: "/api/export.json", download: "" }, icon("download"), "JSON"))),
      h("section", { class: "card" },
        h("div", { class: "toolbar" }, search, this.segWrap, h("span", { class: "spacer" }), legend()),
        h("div", { class: "table-wrap" }, h("table", null,
          h("thead", null, h("tr", null,
            h("th", { text: "Target" }),
            h("th", { text: "Verdict" }),
            this.headMatrix,
            h("th", { class: "hide-sm", text: "Last tested" }),
            h("th", { class: "num", text: "" }))),
          this.tbody)),
        h("div", { class: "card-body" }, this.footer)));
  },

  update() {
    const domains = [...state.domains.values()];
    const counts = { all: domains.length, vulnerable: 0, testing: 0, secure: 0 };
    for (const d of domains) counts[d.verdict] = (counts[d.verdict] || 0) + 1;

    clear(this.segWrap).append(seg([
      { value: "all", label: "All", count: counts.all },
      { value: "vulnerable", label: "Vulnerable", count: counts.vulnerable },
      { value: "testing", label: "Testing", count: counts.testing },
      { value: "secure", label: "Secure", count: counts.secure },
    ], this.filter, (v) => { this.filter = v; this.update(); }));

    clear(this.headMatrix).append(matrixHeader());

    const q = this.query;
    const rows = domains.filter((d) => {
      if (this.filter !== "all" && d.verdict !== this.filter) return false;
      if (!q) return true;
      return [d.key, d.domain, d.ip, ...(d.ips || [])].some((v) => v && v.toLowerCase().includes(q));
    });

    // Vulnerable first, then testing, then secure; newest first within each
    const rank = { vulnerable: 0, testing: 1, secure: 2 };
    rows.sort((a, b) => (rank[a.verdict] - rank[b.verdict]) || (new Date(b.last_tested) - new Date(a.last_tested)));

    clear(this.tbody);
    if (!rows.length) {
      this.tbody.append(h("tr", null, h("td", { colspan: "5" }, emptyState(domains.length ? "No matches" : "No domains yet", domains.length ? "Adjust the filter." : "Domains appear once clients connect through the proxy."))));
    }
    for (const d of rows.slice(0, 1000)) {
      const ips = d.ips && d.ips.length ? d.ips : d.ip ? [d.ip] : [];
      const tr = rowLink(() => openDomain(d.key), [
        h("td", null,
          h("div", { class: "cell-main", text: displayName(d) }),
          ips.length ? h("div", { class: "cell-sub", text: ips.slice(0, 3).join(", ") + (ips.length > 3 ? ` +${ips.length - 3}` : "") }) : null),
        h("td", { class: "nowrap" }, verdictBadge(d.verdict),
          d.accepted_test ? h("div", { class: "cell-sub", text: testName(d.accepted_test) }) : null),
        h("td", { class: "hide-sm" }, matrix(d)),
        h("td", { class: "nowrap muted hide-sm", title: fmtDateTime(d.last_tested), text: fmtRel(d.last_tested) }),
        h("td", { class: "num nowrap" },
          h("button", {
            class: "btn icon", type: "button", title: "Retest", "aria-label": `Retest ${displayName(d)}`,
            onclick: async (e) => {
              e.stopPropagation();
              try {
                await api(`/api/domains/${encodeURIComponent(d.key)}/reset`, { method: "POST" });
                toast(`Reset ${displayName(d)}`);
              } catch (err) { toast(`Reset failed: ${err.message}`); }
            },
          }, icon("refresh"))),
      ]);
      if (state.flash.has(d.key)) tr.classList.add("flash");
      this.tbody.append(tr);
    }
    this.footer.textContent = rows.length > 1000 ? `Showing 1000 of ${rows.length} matching domains.` : `${rows.length} of ${domains.length} domains.`;
  },
};

const trafficView = {
  topics: ["request", "handshake"],
  tab: "requests",
  query: "",
  mitmOnly: false,
  paused: false,
  frozen: null,

  mount(root) {
    this.segWrap = h("span");
    this.body = h("div");
    this.footer = h("div", { class: "note" });
    this.pauseBtn = h("button", { class: "btn", type: "button", onclick: () => this.togglePause() });
    const search = h("input", {
      type: "search", placeholder: "Filter host, path, client, method…", "aria-label": "Filter traffic", value: this.query,
      oninput: (e) => { this.query = e.target.value.trim().toLowerCase(); this.update(true); },
    });
    const mitm = h("label", { class: "check" },
      h("input", { type: "checkbox", checked: this.mitmOnly, onchange: (e) => { this.mitmOnly = e.target.checked; this.update(true); } }),
      "Decrypted only");

    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Traffic" }), h("p", { text: "Requests relayed by the proxy and TLS handshakes clients rejected." }))),
      h("section", { class: "card" },
        h("div", { class: "toolbar" }, this.segWrap, search, mitm, h("span", { class: "spacer" }), this.pauseBtn),
        h("div", { class: "card-body flush" }, this.body),
        h("div", { class: "card-body" }, this.footer)));
    this.drawPause();
  },

  togglePause() {
    this.paused = !this.paused;
    this.frozen = this.paused ? { requests: state.requests.slice(), handshakes: state.handshakes.slice() } : null;
    this.drawPause();
    this.update(true);
  },

  drawPause() {
    clear(this.pauseBtn).append(icon(this.paused ? "play" : "pause"), this.paused ? "Resume" : "Pause");
    this.pauseBtn.setAttribute("aria-pressed", String(this.paused));
  },

  update(force) {
    if (this.paused && !force) return;
    const src = this.frozen || state;

    clear(this.segWrap).append(seg([
      { value: "requests", label: "Requests", count: src.requests.length },
      { value: "handshakes", label: "TLS rejections", count: src.handshakes.length },
    ], this.tab, (v) => { this.tab = v; this.update(true); }));

    const q = this.query;
    clear(this.body);
    if (this.tab === "requests") {
      let rows = src.requests.slice().reverse();
      if (this.mitmOnly) rows = rows.filter((ev) => ev.data.scheme === "https");
      if (q) rows = rows.filter((ev) => {
        const r = ev.data;
        return `${r.method} ${r.host}${r.path}?${r.query || ""} ${r.client_ip} ${r.status} ${r.test_type || ""}`.toLowerCase().includes(q);
      });
      this.body.append(rows.length ? requestTable(rows.slice(0, 500)) : emptyState("No requests", src.requests.length ? "Nothing matches the filter." : "Relayed requests appear here live."));
      this.footer.textContent = `${Math.min(rows.length, 500)} shown · ${src.requests.length} retained in memory${this.paused ? " · paused" : ""}`;
    } else {
      let rows = src.handshakes.slice().reverse();
      if (q) rows = rows.filter((ev) => `${ev.data.sni} ${ev.data.client_ip} ${ev.data.test_type} ${ev.data.error}`.toLowerCase().includes(q));
      this.body.append(rows.length ? handshakeTable(rows.slice(0, 500)) : emptyState("No rejections", "Handshakes aborted by clients appear here."));
      this.footer.textContent = `${Math.min(rows.length, 500)} shown · ${src.handshakes.length} retained${this.paused ? " · paused" : ""}`;
    }
  },
};

const payloadsView = {
  topics: [],
  hosts: [],
  selected: null,
  query: "",

  mount(root) {
    this.hostList = h("div", { class: "list" });
    this.main = h("div");
    const search = h("input", {
      type: "search", placeholder: "Filter hosts…", "aria-label": "Filter hosts", value: this.query,
      oninput: (e) => { this.query = e.target.value.trim().toLowerCase(); this.drawHosts(); },
    });
    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Payloads" }), h("p", { text: "Request/response captures on disk, including earlier sessions." })),
        h("button", { class: "btn", type: "button", onclick: () => this.load() }, icon("refresh"), "Refresh")),
      h("section", { class: "card split" },
        h("div", { class: "split-side" }, h("div", { class: "toolbar" }, search), this.hostList),
        h("div", null, this.main)));
    this.load();
  },

  async load() {
    try {
      this.hosts = await getJSON("/api/payloads");
    } catch (e) {
      this.hosts = [];
      toast(`Failed to list payloads: ${e.message}`);
    }
    this.drawHosts();
    if (this.selected) this.select(this.selected);
    else clear(this.main).append(emptyState("Select a host", this.hosts.length ? "Choose a host on the left to browse its captures." : "Nothing captured yet."));
  },

  drawHosts() {
    const q = this.query;
    const hosts = q ? this.hosts.filter((x) => x.name.toLowerCase().includes(q)) : this.hosts;
    clear(this.hostList);
    if (!hosts.length) this.hostList.append(h("div", { class: "empty", text: "No hosts" }));
    for (const host of hosts) {
      this.hostList.append(h("button", {
        class: "host-item", type: "button", "aria-current": String(host.name === this.selected),
        onclick: () => this.select(host.name),
      },
      h("div", { class: "name", text: host.name }),
      h("div", { class: "meta", text: `${host.files} files · ${fmtBytes(host.bytes)} · ${fmtRel(host.modified)}` })));
    }
  },

  async select(name) {
    this.selected = name;
    this.drawHosts();
    clear(this.main).append(h("div", { class: "empty", text: "Loading…" }));
    let list;
    try {
      list = await getJSON(`/api/payloads/${encodeURIComponent(name)}`);
    } catch (e) {
      clear(this.main).append(emptyState("Failed to load", e.message));
      return;
    }
    if (this.selected !== name) return;
    clear(this.main).append(
      h("div", { class: "toolbar" }, h("strong", { class: "cell-main", text: name }), h("span", { class: "spacer" }), h("span", { class: "note", text: `${list.length} exchanges` })),
      list.length ? h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", { text: "Time" }), h("th", { text: "Request ID" }), h("th", { class: "num", text: "Request" }), h("th", { class: "num", text: "Response" }))),
        h("tbody", null, list.map((ex) => {
          const ev = state.requests.find((r) => r.data.req_id === ex.id && payloadDirFor(r.data.host) === name);
          return rowLink(() => openExchange(name, ex.id, ev), [
            h("td", { class: "nowrap mono muted", text: fmtDateTime(ex.time) }),
            h("td", { class: "mono" }, ex.id, ev ? h("div", { class: "cell-sub truncate", text: `${ev.data.method} ${ev.data.path}` }) : null),
            h("td", { class: "num muted", text: ex.request_body ? fmtBytes(ex.request_body.size) : ex.request_meta ? "headers" : "—" }),
            h("td", { class: "num muted", text: ex.response_body ? fmtBytes(ex.response_body.size) : ex.response_meta ? "headers" : "—" }),
          ]);
        })))) : emptyState("No exchanges", "No request/response files in this directory."));
  },

  update() { /* static view; refreshed on demand */ },
};

const logsView = {
  topics: ["log"],
  levels: { info: true, error: true, verbose: true, debug: true },
  query: "",
  paused: false,
  rendered: 0,
  box: null,

  reset() { this.rendered = 0; if (this.box) clear(this.box); },

  mount(root) {
    this.box = h("div", { class: "log", role: "log", "aria-live": "off" });
    this.rendered = 0;
    this.pauseBtn = h("button", { class: "btn", type: "button", onclick: () => { this.paused = !this.paused; this.drawPause(); if (!this.paused) this.update(); } });
    const checks = Object.keys(this.levels).map((lv) => h("label", { class: "check" },
      h("input", { type: "checkbox", checked: this.levels[lv], onchange: (e) => { this.levels[lv] = e.target.checked; this.reset(); this.update(); } }),
      lv));
    const search = h("input", {
      type: "search", placeholder: "Filter log lines…", "aria-label": "Filter logs", value: this.query,
      oninput: (e) => { this.query = e.target.value.trim().toLowerCase(); this.reset(); this.update(); },
    });
    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Logs" }), h("p", { text: "Live proxy log. Verbose and debug lines only appear when enabled with -verbose / -debug." }))),
      h("section", { class: "card" },
        h("div", { class: "toolbar" }, search, ...checks, h("span", { class: "spacer" }),
          this.pauseBtn,
          h("button", { class: "btn", type: "button", onclick: () => { state.logs = []; this.reset(); } }, icon("eraser"), "Clear")),
        this.box));
    this.drawPause();
  },

  drawPause() {
    clear(this.pauseBtn).append(icon(this.paused ? "play" : "pause"), this.paused ? "Resume" : "Pause");
    this.pauseBtn.setAttribute("aria-pressed", String(this.paused));
  },

  matches(ev) {
    const d = ev.data;
    if (!this.levels[d.level]) return false;
    return !this.query || `${d.req_id || ""} ${d.msg}`.toLowerCase().includes(this.query);
  },

  update() {
    if (!this.box || this.paused) return;
    // The log array is a sliding window; if it shifted under us, redraw
    if (this.rendered > state.logs.length) this.reset();
    const atBottom = this.box.scrollHeight - this.box.scrollTop - this.box.clientHeight < 40;
    const frag = document.createDocumentFragment();
    for (let i = this.rendered; i < state.logs.length; i++) {
      const ev = state.logs[i];
      if (!this.matches(ev)) continue;
      const d = ev.data;
      frag.append(h("div", { class: "log-line" },
        h("span", { class: "t", text: fmtTime(ev.time) }),
        h("span", { class: `lv ${d.level}`, text: d.level }),
        h("span", { class: "m" }, d.req_id ? h("span", { class: "rid", text: `[${d.req_id}] ` }) : null, d.msg)));
    }
    this.rendered = state.logs.length;
    this.box.append(frag);
    while (this.box.childElementCount > MAX_LOGS) this.box.firstElementChild.remove();
    if (atBottom) this.box.scrollTop = this.box.scrollHeight;
  },
};

const setupView = {
  topics: [],

  mount(root) {
    const info = state.info;
    if (!info) return;
    const ca = info.ca;
    const proxyHost = location.hostname;

    root.append(
      h("div", { class: "page-head" },
        h("div", null, h("h1", { text: "Setup" }), h("p", { text: "Running configuration, test catalogue and client setup notes." }))),
      h("div", { class: "grid grid-2" },
        h("div", { class: "grid" },
          h("section", { class: "card" },
            h("div", { class: "card-head" }, h("h2", { text: "Configuration" })),
            h("div", { class: "card-body" }, h("dl", { class: "kv" },
              h("dt", { text: "HTTP listener" }), h("dd", { class: "mono", text: info.http_addr }),
              h("dt", { text: "HTTPS listener" }), h("dd", { class: "mono", text: info.https_addr }),
              h("dt", { text: "Mode" }), h("dd", { text: info.auto_test ? "Auto-test (cycle through all tests per domain)" : `Fixed test: ${testName(info.fixed_test)}` }),
              h("dt", { text: "Test order" }), h("dd", { text: info.tester.test_order.map((t) => testName(t.key)).join(" → ") }),
              h("dt", { text: "Retest period" }), h("dd", { class: "mono", text: info.tester.retest_period }),
              h("dt", { text: "Max attempts" }), h("dd", { class: "mono", text: String(info.tester.max_attempts) }),
              h("dt", { text: "Payload capture" }), h("dd", { text: info.save_payloads ? `Enabled → ${info.payload_dir}` : "Disabled" }),
              h("dt", { text: "Web UI auth" }), h("dd", { text: info.auth_enabled ? "Token" : "Disabled (loopback / IP-literal Host only)" })))),
          h("section", { class: "card" },
            h("div", { class: "card-head" }, h("h2", { text: "GoCertMITM CA" }),
              h("a", { class: "btn sm", href: "/api/ca.pem", download: "" }, icon("download"), "ca.pem")),
            h("div", { class: "card-body" },
              ca ? h("dl", { class: "kv" },
                h("dt", { text: "Subject" }), h("dd", { class: "mono", text: ca.subject }),
                h("dt", { text: "Valid" }), h("dd", { text: `${fmtDateTime(ca.not_before)} → ${fmtDateTime(ca.not_after)}` }),
                h("dt", { text: "SHA-256" }), h("dd", { class: "mono", text: ca.sha256_fingerprint.match(/.{2}/g).join(":") })) : h("div", { class: "note", text: "No CA loaded." }),
              h("p", { class: "note", text: "This CA signs the self-signed test certificates. Do not install it on devices under test unless you deliberately want to exercise a \"user-installed CA\" scenario — doing so turns every self-signed result into a false positive." }))),
          h("section", { class: "card" },
            h("div", { class: "card-head" }, h("h2", { text: "Transparent interception" })),
            h("div", { class: "card-body" },
              h("p", { class: "note", text: "Redirect the device's traffic on the gateway (example for a client subnet on br-lan):" }),
              h("pre", { class: "code", text:
                `iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 443 -j REDIRECT --to-ports ${portOf(info.https_addr, 8443)}\n` +
                `iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 80  -j REDIRECT --to-ports ${portOf(info.http_addr, 8080)}` }),
              h("p", { class: "note", text: `Or configure the client to use ${proxyHost}:${portOf(info.http_addr, 8080)} as an explicit HTTP proxy.` })))),
        h("section", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Certificate tests" })),
          h("div", { class: "card-body test-desc" }, info.tester.test_order.map((t, i) => {
            const meta = TEST_INFO[t.key] || { name: t.name, what: "" };
            return h("div", { class: "item" },
              h("span", { class: "mx", text: meta.short || String(i) }),
              h("div", null,
                h("div", { class: "name", text: `${i + 1}. ${meta.name}` }),
                h("div", { class: "what", text: meta.what }),
                h("div", { class: "note mono", text: t.name })));
          })))));
  },
  update() {},
};

function portOf(addr, fallback) {
  const m = /:(\d+)$/.exec(addr || "");
  return m ? m[1] : String(fallback);
}

/* ------------------------------------------------------------------ */
/* Router                                                             */
/* ------------------------------------------------------------------ */

const VIEWS = { overview: overviewView, domains: domainsView, traffic: trafficView, payloads: payloadsView, logs: logsView, setup: setupView };

function route() {
  const name = (location.hash.replace(/^#\/?/, "").split("/")[0]) || "overview";
  const view = VIEWS[name] || overviewView;
  for (const a of document.querySelectorAll("#nav a")) {
    if (a.dataset.view === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  const root = clear(document.getElementById("view"));
  currentView = view;
  if (name === "logs") logsView.rendered = 0;
  view.mount(root);
  view.update(true);
}

/* ------------------------------------------------------------------ */
/* Theme                                                              */
/* ------------------------------------------------------------------ */

function storedTheme() {
  try { return localStorage.getItem("certmitm-theme"); } catch (_) { return null; }
}

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const dark = theme ? theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  clear(document.getElementById("theme-toggle")).append(icon(dark ? "sun" : "moon"));
}

function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  try { localStorage.setItem("certmitm-theme", next); } catch (_) { /* storage unavailable */ }
  applyTheme(next);
}

/* ------------------------------------------------------------------ */
/* Boot                                                               */
/* ------------------------------------------------------------------ */

async function boot() {
  document.getElementById("brand-mark").append(icon("shield"));
  document.getElementById("drawer-close").append(icon("x"));
  document.getElementById("drawer-close").addEventListener("click", () => drawer.close());
  document.getElementById("drawer-backdrop").addEventListener("click", () => drawer.close());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && document.body.classList.contains("drawer-open")) drawer.close(); });
  document.getElementById("theme-toggle").addEventListener("click", toggleTheme);
  applyTheme(storedTheme());

  try {
    await loadSnapshots();
  } catch (e) {
    clear(document.getElementById("view")).append(emptyState("Failed to load", e.message));
    scheduleReconnect();
    return;
  }

  window.addEventListener("hashchange", route);
  route();
  connect();
  setInterval(refreshStats, 5000);
  // Keep relative timestamps fresh
  setInterval(() => scheduleUpdate("domain", "stats"), 15000);
}

boot();
