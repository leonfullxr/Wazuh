"""Packaged, network-isolated MCP Apps investigation viewer."""

import base64
import hashlib

from wazuh_mcp.ui_theme import css as _ui_css
from wazuh_mcp.ui_theme import icon as _icon

URI = "ui://wazuh/agent-timeline.html"
MIME = "text/html;profile=mcp-app"

_LAYOUT = r'''
body { min-height: 0; padding: 8px; }
.frame { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
.head { padding: 16px 20px; border-bottom: 1px solid var(--line); }
.kicker { display: flex; align-items: center; gap: 6px; margin: 0 0 8px; color: var(--muted); font-size: 12px; line-height: 18px; }
.kicker svg { color: var(--accent); }
.title-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; }
.head h1 { margin: 0; font-size: 20px; line-height: 28px; }
.head .agent-id { color: var(--ink-2); }
.inline-facts { display: flex; flex-wrap: wrap; gap: 4px 20px; margin: 8px 0 0; }
.inline-facts div { display: flex; align-items: baseline; gap: 6px; }
.coverage { display: grid; gap: 4px; padding: 12px 20px; border-bottom: 1px solid var(--line); }
.coverage h2 { margin: 0 0 4px; font-size: 13px; line-height: 18px; font-weight: 500; color: var(--muted); }
.source { display: grid; grid-template-columns: 6.5rem auto 1fr; gap: 10px; align-items: center; padding: 6px 10px; background: var(--bg); border-radius: 8px; }
.source .label { font-weight: 500; }
.source .note { color: var(--ink-2); }
#status { margin: 0; padding: 8px 20px 0; min-height: 0; color: var(--muted); font-size: 12px; line-height: 18px; }
#status:empty { display: none; }
.workspace { display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 22rem; }
.events-pane { border-right: 1px solid var(--line); padding: 12px 0; min-width: 0; }
.evidence-pane { padding: 16px 20px 20px; min-width: 0; }
.events-pane h2 { margin: 0 16px 8px; font-size: 13px; line-height: 18px; font-weight: 500; color: var(--muted); }
#events { list-style: none; padding: 0; margin: 0; }
#events button {
  display: grid; gap: 2px; justify-content: stretch; justify-items: start; width: 100%; min-height: 0; margin: 0; padding: 8px 16px;
  text-align: left; border: 0; border-radius: 0; box-shadow: none; background: transparent;
  font-weight: 400; line-height: 21px;
}
#events button:hover { background: var(--hover); }
#events button[aria-selected="true"] { background: var(--accent-subtle); box-shadow: inset 3px 0 0 var(--accent); }
#events button:focus-visible { outline-offset: -2px; }
#events time { font-weight: 600; }
#events .desc { font-weight: 500; overflow-wrap: anywhere; }
#events .meta { color: var(--muted); font-size: 12px; line-height: 18px; }
.empty { margin: 0 16px; color: var(--ink-2); }
.empty strong { display: block; color: var(--ink); font-weight: 500; }
.truncated { margin: 8px 16px 0; padding: 8px 10px; border-radius: 8px; background: var(--warn-subtle); color: var(--warn); font-size: 12px; line-height: 18px; }
.ev-title { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 12px; }
.ev-title h2 { margin: 0; overflow-wrap: anywhere; }
.segmented { display: inline-flex; padding: 2px; margin: 0 0 12px; gap: 2px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; }
.segmented button { min-height: 28px; padding: 0 10px; border: 0; box-shadow: none; background: transparent; color: var(--ink-2); border-radius: 6px; font-size: 13px; }
.segmented button[aria-pressed="true"] { background: var(--panel); color: var(--ink); box-shadow: 0 1px 2px rgb(0 0 0 / 4%); }
#fields { margin: 0; }
#fields div { display: grid; grid-template-columns: 7rem 1fr; gap: 12px; padding: 6px 0; border-top: 1px solid var(--line); }
.well, #raw { margin: 12px 0 0; padding: 12px; background: var(--panel-2); border-radius: 8px; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; font-variant-numeric: tabular-nums; }
#raw { margin: 0; }
.footnote { margin: 12px 0 0; color: var(--muted); font-size: 12px; line-height: 18px; }
@media (max-width: 640px) {
  body { padding: 0; }
  .frame { border-radius: 0; border-left: 0; border-right: 0; }
  .workspace { grid-template-columns: 1fr; }
  .events-pane { border-right: 0; border-bottom: 1px solid var(--line); }
  .source { grid-template-columns: 1fr auto; }
  .source .note { grid-column: 1 / -1; }
}
'''


SCRIPT = r'''
(() => {
  "use strict";
  const host = window.parent;
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  };
  let ready = false,
    nextId = 2,
    pending = new Map(),
    current = null;
  const put = (id, value) => {
    $(id).textContent = value == null ? "Unavailable" : String(value);
  };
  const parse = (iso) => {
    const date = new Date(iso);
    return iso == null || iso === "" || Number.isNaN(date.getTime()) ? null : date;
  };
  const fmt = (date, opts) =>
    new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hourCycle: "h23", ...opts }).format(date);
  const hm = (date) => fmt(date, { hour: "2-digit", minute: "2-digit" });
  const day = (date) => fmt(date, { day: "numeric", month: "short" });
  const stamp = (iso, opts) => {
    const node = document.createElement("time");
    const date = parse(iso);
    if (!date) {
      node.textContent = iso == null || iso === "" ? "Unavailable" : String(iso);
      return node;
    }
    node.dateTime = node.title = date.toISOString();
    node.textContent = opts ? fmt(date, opts) : `${day(date)}, ${hm(date)} UTC`;
    return node;
  };
  const tag = (tone, word) => el("span", `tag ${tone}`, word);
  const source = (label, tone, word, note) => {
    const row = el("div", "source");
    row.append(el("span", "label", label), tag(tone, word), el("span", "note", note));
    return row;
  };
  const send = (message) =>
    host.postMessage({ jsonrpc: "2.0", ...message }, "*");
  const ref = (value) => {
    const chip = el("span", "chip");
    chip.title = "Evidence reference, valid for 15 minutes";
    chip.append(el("span", "pre", "ev_"), document.createTextNode(`${String(value).slice(3, 11)}...`));
    return chip;
  };
  function drawWindow(start, end) {
    const a = parse(start), b = parse(end), node = $("window");
    if (!a || !b) return node.replaceChildren(stamp(start), " to ", stamp(end));
    const head = stamp(start), tail = stamp(end, { hour: "2-digit", minute: "2-digit" });
    head.textContent = `${day(a)}, ${hm(a)}`;
    tail.textContent = day(a) === day(b) ? hm(b) : `${day(b)}, ${hm(b)}`;
    node.replaceChildren(head, " to ", tail, " UTC");
  }
  function drawSources(alerts, agent) {
    const rows = [];
    if (alerts.status === "complete")
      rows.push(source("Alerts", "ok", "Complete", `${alerts.returned ?? 0} of ${alerts.matched ?? alerts.returned ?? 0} matching alerts shown`));
    else if (alerts.status === "partial")
      rows.push(source("Alerts", "warn", "Partial", alerts.matched == null ? `Latest ${alerts.returned ?? 0} matches shown, total unknown` : `Latest ${alerts.returned ?? 0} of ${alerts.matched} matches shown`));
    else rows.push(source("Alerts", "err", "Unavailable", "The indexer didn't answer"));
    const seen = parse(agent.observed_at), word = agent.observation?.status;
    if (agent.status === "available" && word)
      rows.push(source("Agent status", "ok", "Available", `${word[0].toUpperCase()}${word.slice(1)}${seen ? ` at ${hm(seen)}` : ""}, a reading at collection time, not history`));
    else rows.push(source("Agent status", "err", "Unavailable", "The manager didn't answer, so the agent's current status is unknown"));
    $("sources").replaceChildren(...rows);
  }
  function empty(strong, text) {
    const p = el("p", "empty");
    p.append(el("strong", null, strong), document.createTextNode(text));
    return p;
  }
  function showView(raw) {
    $("view-fields").setAttribute("aria-pressed", String(!raw));
    $("view-raw").setAttribute("aria-pressed", String(raw));
    $("fields-view").hidden = raw;
    $("raw").hidden = !raw;
  }
  function drawEvidence(event) {
    const rule = event.rule || {}, agent = event.agent || {}, data = event.data || {};
    const mitre = rule.mitre?.id || rule.mitre?.technique;
    const rows = [
      ["Time", event.timestamp],
      ["Rule", rule.id],
      ["Level", rule.level],
      ["Agent", agent.name && agent.id ? `${agent.name} (${agent.id})` : agent.name || agent.id],
      ["Source IP", data.srcip],
      ["User", data.srcuser || data.dstuser],
      ["Location", event.location],
      ["MITRE", Array.isArray(mitre) ? mitre.join(", ") : mitre],
      ["Groups", Array.isArray(rule.groups) ? rule.groups.join(", ") : rule.groups],
    ];
    const list = $("fields");
    list.replaceChildren();
    for (const [label, value] of rows) {
      if (value == null || value === "") continue;
      const row = el("div");
      row.append(el("dt", null, label), el("dd", null, value));
      list.append(row);
    }
    const log = $("full-log");
    log.hidden = !event.full_log;
    log.replaceChildren();
    if (event.full_log) log.append(el("dt", null, "Full log"), el("dd", "well", event.full_log));
    $("raw").textContent = JSON.stringify(event, null, 2);
    $("ev-heading").textContent = rule.description || `Rule ${rule.id ?? "unavailable"}`;
    $("ev-body").hidden = false;
    put("detail", "");
  }
  function draw(data) {
    if (
      !data ||
      !Array.isArray(data.events) ||
      typeof data.cluster !== "string"
    ) {
      put("status", "Timeline data is unavailable.");
      return;
    }
    current = data;
    $("agent-name").textContent = data.agent_name || `Agent ${data.agent_id ?? "unavailable"}`;
    $("agent-id").textContent = data.agent_name ? `Agent ${data.agent_id}` : "";
    put("cluster", data.cluster);
    drawWindow(data.window?.from, data.window?.to);
    $("collected").replaceChildren(stamp(data.collected_at));
    const alerts = data.sources?.alerts || {},
      agent = data.sources?.agent_status || {};
    drawSources(alerts, agent);
    put("status", "");
    const list = $("events"), pane = $("events-pane");
    list.replaceChildren();
    for (const node of pane.querySelectorAll(".empty, .truncated")) node.remove();
    const items = data.events.filter((item) => item && typeof item.evidence_ref === "string");
    $("events-heading").textContent = `${items.length} ${items.length === 1 ? "event" : "events"}, oldest first`;
    if (!items.length) {
      if (alerts.status === "complete" && alerts.matched === 0)
        pane.append(empty("No alerts in this window.", ` The indexer answered and found nothing for this agent between ${$("window").textContent}. That is a real empty result, not missing data.`));
      else if (alerts.status !== "complete" && alerts.status !== "partial")
        pane.append(empty("Alerts couldn't be checked.", " The indexer was unreachable, so this is not evidence that nothing happened."));
      else pane.append(empty("No events returned.", " Check source coverage before drawing conclusions."));
    }
    if (alerts.truncated === true)
      pane.append(el("p", "truncated", alerts.matched == null
        ? `Showing the latest ${alerts.returned ?? items.length} matches. Narrow the window to see earlier ones.`
        : `Showing the latest ${alerts.returned ?? items.length} of ${alerts.matched} matches. Narrow the window to see earlier ones.`));
    const choose = (button) => {
      for (const other of list.querySelectorAll("button")) {
        other.setAttribute("aria-selected", "false");
        other.tabIndex = -1;
      }
      button.setAttribute("aria-selected", "true");
      button.tabIndex = 0;
      button.focus();
      $("ev-body").hidden = true;
      $("ev-heading").textContent = button.dataset.title;
      $("ev-ref").replaceChildren(ref(button.dataset.ref));
      put("detail", "Retrieving evidence...");
      const id = nextId++;
      pending.clear();
      pending.set(id, true);
      send({
        id,
        method: "tools/call",
        params: {
          name: "get_investigation_evidence",
          arguments: {
            evidence_ref: button.dataset.ref,
            cluster_id: current.cluster,
          },
        },
      });
    };
    let first = true;
    for (const item of items) {
      const li = document.createElement("li"),
        button = document.createElement("button");
      li.setAttribute("role", "none");
      button.type = "button";
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", "false");
      button.tabIndex = first ? 0 : -1;
      first = false;
      button.dataset.ref = item.evidence_ref;
      const title = item.description || `Rule ${item.rule_id ?? "unavailable"}`;
      button.dataset.title = title;
      button.append(stamp(item.at, { hour: "2-digit", minute: "2-digit", second: "2-digit" }), el("span", "desc", title));
      if (item.description || item.level != null)
        button.append(el("span", "meta", `Rule ${item.rule_id ?? "unavailable"}${item.level != null ? `, level ${item.level}` : ""}`));
      button.addEventListener("click", () => choose(button));
      li.append(button);
      list.append(li);
    }
    list.onkeydown = (event) => {
      const buttons = [...list.querySelectorAll("button")];
      if (!buttons.length) return;
      const focused = buttons.indexOf(document.activeElement);
      const selected = buttons.findIndex((button) => button.getAttribute("aria-selected") === "true");
      const from = focused >= 0 ? focused : Math.max(selected, 0);
      let next = from;
      if (event.key === "ArrowDown") next = selected < 0 ? from : Math.min(buttons.length - 1, from + 1);
      else if (event.key === "ArrowUp") next = selected < 0 ? from : Math.max(0, from - 1);
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = buttons.length - 1;
      else return;
      event.preventDefault();
      choose(buttons[next]);
    };
  }
  $("view-fields").addEventListener("click", () => showView(false));
  $("view-raw").addEventListener("click", () => showView(true));
  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (event.source !== host || !msg || msg.jsonrpc !== "2.0") return;
    if (
      !ready &&
      msg.id === 1 &&
      msg.result?.protocolVersion === "2026-01-26"
    ) {
      ready = true;
      send({ method: "ui/notifications/initialized" });
      return;
    }
    if (!ready) return;
    if (msg.method === "ui/notifications/tool-result") {
      let data = msg.params?.structuredContent;
      if (!data) {
        try {
          data = JSON.parse(
            msg.params?.content?.find(
              (part) => part.type === "text" && part.text?.startsWith("{"),
            )?.text,
          );
        } catch (_) {}
      }
      draw(data);
      return;
    }
    if (pending.has(msg.id)) {
      pending.delete(msg.id);
      const result = msg.result?.structuredContent;
      if (
        msg.error ||
        msg.result?.isError ||
        !result ||
        result.status !== "available" ||
        !result.event ||
        typeof result.event !== "object"
      )
        put("detail", "Evidence unavailable or access has changed.");
      else drawEvidence(result.event);
    }
    if (msg.method === "ui/resource-teardown" && msg.id != null)
      send({ id: msg.id, result: {} });
  });
  send({
    id: 1,
    method: "ui/initialize",
    params: {
      appInfo: { name: "Wazuh investigation timeline", version: "1.0.0" },
      appCapabilities: {},
      protocolVersion: "2026-01-26",
    },
  });
})();
'''

# Hashes authorize only these bundled blocks, including in hosts that enforce CSP.
def _hash(value: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()


def html() -> str:
    style = _ui_css() + _LAYOUT
    csp = (
        "default-src 'none'; script-src '" + _hash(SCRIPT) + "'; style-src '" + _hash(style)
        + "'; font-src data:; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'"
    )
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <title>Investigation timeline</title>
  <style>{style}</style>
</head>
<body>
  <main id="main" class="frame">
    <header class="head">
      <p class="kicker">{_icon("shield", 14)}Wazuh MCP / Investigation timeline</p>
      <div class="title-row"><h1 id="agent-name">Agent timeline</h1><span class="agent-id" id="agent-id"></span></div>
      <dl class="inline-facts">
        <div><dt>Cluster</dt><dd id="cluster">Unavailable</dd></div>
        <div><dt>Window</dt><dd id="window">Unavailable</dd></div>
        <div><dt>Collected</dt><dd id="collected">Unavailable</dd></div>
      </dl>
    </header>
    <section class="coverage" aria-labelledby="coverage-heading">
      <h2 id="coverage-heading">Source coverage</h2>
      <div id="sources"><p class="secondary">Waiting for timeline data.</p></div>
    </section>
    <p id="status" role="status">Connecting to host...</p>
    <div class="workspace">
      <section class="events-pane" id="events-pane" aria-labelledby="events-heading">
        <h2 id="events-heading">Events</h2>
        <ul id="events" role="listbox" aria-labelledby="events-heading"></ul>
      </section>
      <section class="evidence-pane" aria-labelledby="ev-heading">
        <div class="ev-title"><h2 id="ev-heading">Evidence</h2><span id="ev-ref"></span></div>
        <p id="detail" role="status">Select an event to view its record.</p>
        <div id="ev-body" hidden>
          <div class="segmented" role="group" aria-label="Evidence view">
            <button type="button" id="view-fields" aria-pressed="true">Fields</button>
            <button type="button" id="view-raw" aria-pressed="false">Raw record</button>
          </div>
          <div id="fields-view"><dl id="fields"></dl><dl id="full-log" hidden></dl></div>
          <pre id="raw" hidden></pre>
          <p class="footnote">Fetched again when you select it, with your current access. Values are shown as plain text.</p>
        </div>
      </section>
    </div>
  </main>
  <script>{SCRIPT}</script>
</body>
</html>'''
