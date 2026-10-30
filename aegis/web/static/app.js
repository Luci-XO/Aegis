"use strict";

// Small DOM helpers. All text goes through textContent, so content from
// emails, file bodies or tool arguments can never inject markup.
function el(tag, props, children) {
  const n = document.createElement(tag);
  if (props) for (const k in props) {
    if (k === "class") n.className = props[k];
    else if (k === "title") n.title = props[k];
    else if (k === "text") n.textContent = props[k];
    else if (k === "html") throw new Error("innerHTML is not allowed");
    else n.setAttribute(k, props[k]);
  }
  for (const c of children || []) if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return n;
}
const $ = (id) => document.getElementById(id);

async function api(path, body) {
  const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
                     : {};
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

let META = null;
let STATE = null;

// ---- navigation ----
$("tabs").addEventListener("click", (e) => {
  const v = e.target.dataset.view;
  if (!v) return;
  for (const b of $("tabs").children) b.classList.toggle("active", b.dataset.view === v);
  for (const s of document.querySelectorAll(".view")) s.classList.toggle("active", s.id === "view-" + v);
  if (v === "benchmark" && !$("benchmark").dataset.loaded) loadBenchmark();
});

// ---- setup ----
async function init() {
  META = await api("/api/meta");
  const sc = $("sel-scenario");
  for (const split of Object.keys(META.splits)) {
    const group = el("optgroup", { label: split });
    for (const s of META.splits[split]) {
      const tag = s.label === "attack" ? "[attack] " : "[benign] ";
      group.appendChild(el("option", { value: s.id, text: tag + s.id }));
    }
    sc.appendChild(group);
  }
  for (const c of META.configs) $("sel-config").appendChild(el("option", { value: c, text: c }));
  for (const a of META.approvers) $("sel-approver").appendChild(el("option", { value: a, text: a }));
  $("sel-config").value = "D_aegis";
  $("sel-approver").value = "manual";
  // Default to the headline attack if present.
  const preferred = ["dev-02-payroll-summarize", "held-06-paraphrased-override"];
  for (const p of preferred) if ([...sc.options].some((o) => o.value === p)) { sc.value = p; break; }
  updateDesc();
  sc.addEventListener("change", updateDesc);
  $("btn-run").addEventListener("click", run);
}

function currentScenario() {
  const id = $("sel-scenario").value;
  for (const split of Object.keys(META.splits))
    for (const s of META.splits[split]) if (s.id === id) return s;
  return null;
}
function updateDesc() {
  const s = currentScenario();
  const d = $("scenario-desc");
  d.textContent = "";
  if (s) d.append(el("span", { class: "badge lbl-" + s.label, text: s.label }), " ",
                  el("span", { text: s.category + (s.description ? " - " + s.description : "") }));
}

async function run() {
  $("btn-run").disabled = true;
  $("run-note").textContent = "running...";
  try {
    const s = currentScenario();
    STATE = await api("/api/session", { scenario_id: s.id, config: $("sel-config").value, approver: $("sel-approver").value });
    render();
  } catch (e) { $("run-note").textContent = "error: " + e.message; }
  finally { $("btn-run").disabled = false; }
}

async function decide(requestId, approve) {
  $("run-note").textContent = approve ? "approving..." : "rejecting...";
  try { STATE = await api("/api/session/decide", { session_id: STATE.session_id, request_id: requestId, approve }); render(); }
  catch (e) { $("run-note").textContent = "error: " + e.message; }
}

// ---- rendering ----
function render() {
  const s = STATE;
  $("run-note").textContent = "";
  renderSummary(s);
  renderPending(s);
  renderInbox(s);
  renderFiles(s);
  renderTask(s);
  renderSteps(s);
  renderOutbox(s);
  renderClaim(s);
  renderAudit(s);
}

function renderSummary(s) {
  const strip = $("summary-strip");
  strip.hidden = false;
  strip.textContent = "";
  const ex = s.steps.filter((x) => x.executed).length;
  const blocked = s.steps.filter((x) => ["denied", "rejected_by_user", "failed"].includes(x.status)).length;
  const items = [
    ["Config", s.config], ["Approver", s.approver], ["Status", s.status + " (" + s.stop_reason + ")"],
    ["Executed", String(ex)], ["Blocked", String(blocked)], ["Left the system", String(s.outbox.length)],
    ["Detector", s.detector || "none"],
  ];
  for (const [k, v] of items) strip.append(el("span", {}, [el("span", { class: "muted", text: k + ": " }), el("b", { text: v })]));
}

function renderPending(s) {
  const b = $("pending-banner");
  if (!s.pending) { b.hidden = true; b.textContent = ""; return; }
  b.hidden = false; b.textContent = "";
  const p = s.pending;
  b.append(el("h3", { text: "Approval required - review the exact action" }));
  b.append(el("div", { class: "step wait" }, [
    el("div", { class: "tool", text: p.display.tool }),
    el("div", { class: "args", text: JSON.stringify(p.display.args, null, 1) }),
    el("div", { class: "rules" }, p.reasons.map((r) => el("span", { class: "rule " + r.verdict, title: r.message, text: r.rule_id }))),
  ]));
  b.append(el("div", { class: "actions" }, [
    el("button", { class: "btn-approve", text: "Approve this exact action" }),
    el("button", { class: "btn-reject", text: "Reject" }),
  ]));
  b.querySelector(".btn-approve").addEventListener("click", () => decide(p.request_id, true));
  b.querySelector(".btn-reject").addEventListener("click", () => decide(p.request_id, false));
}

function renderInbox(s) {
  const box = $("inbox"); box.textContent = "";
  for (const m of s.inbox) {
    const card = el("div", { class: "mail" }, [
      el("div", { class: "row1" }, [el("span", { class: "subj", text: m.subject }), el("span", { class: "badge s-" + m.sensitivity, text: m.sensitivity })]),
      el("div", { class: "from", text: m.from + "  -  " + m.id }),
      el("div", { class: "body", text: m.body }),
    ]);
    card.addEventListener("click", () => card.classList.toggle("open"));
    box.appendChild(card);
  }
}

function renderFiles(s) {
  const box = $("files"); box.textContent = "";
  for (const f of s.files)
    box.appendChild(el("span", { class: "chip", title: f.tags.join(", ") }, [
      f.id + " " + f.name + " ", el("span", { class: "badge s-" + f.sensitivity, text: f.sensitivity })]));
}

function renderTask(s) {
  $("task-template").textContent = s.task.template;
  const d = $("task-desc"); d.textContent = "";
  d.append(el("div", { text: s.task.description }));
  const g = s.task.grant;
  d.append(el("div", { class: "muted", text:
    "grant: tools=[" + g.tools.join(",") + "] recipients=[" + g.recipients.join(",") +
    "] files=[" + g.files.join(",") + "] clearance=" + g.max_read_sensitivity }));
}

function renderSteps(s) {
  const box = $("steps"); box.textContent = "";
  if (!s.steps.length) { box.appendChild(el("div", { class: "empty", text: "No steps yet." })); return; }
  for (const st of s.steps) {
    const cls = st.status === "executed" ? "ok" : st.status === "pending_approval" ? "wait"
              : st.status === "failed" ? "fail" : "blocked";
    const card = el("div", { class: "step " + cls });
    card.append(el("div", { class: "row1" }, [
      el("span", { class: "tool", text: (st.tool || "<invalid>") }),
      el("span", { class: "status st-" + st.status, text: st.status + (st.approval ? " / " + st.approval : "") }),
    ]));
    if (st.args) card.append(el("div", { class: "args", text: JSON.stringify(st.args) }));
    if (st.reasons.length)
      card.append(el("div", { class: "rules" }, st.reasons.map((r) =>
        el("span", { class: "rule " + r.verdict, title: r.message, text: r.rule_id }))));
    if (st.risk_score != null) {
      const hi = st.risk_score >= 0.5;
      card.append(el("div", { class: "risk" }, ["detector risk applied: ", el("b", { class: hi ? "hi" : "lo", text: st.risk_score.toFixed(2) })]));
    }
    box.appendChild(card);
  }
}

function renderOutbox(s) {
  const box = $("outbox"); box.textContent = "";
  if (!s.outbox.length) { box.appendChild(el("div", { class: "empty", text: "Nothing has left the system." })); return; }
  for (const m of s.outbox)
    box.appendChild(el("div", { class: "msg" }, [
      el("div", {}, [el("span", { class: "to", text: m.to.join(", ") })]),
      el("div", { text: m.subject }),
      m.attachments.length ? el("div", { class: "muted", text: "attachments: " + m.attachments.join(", ") }) : null,
    ]));
}

function renderClaim(s) {
  const w = $("claim-wrap");
  if (!s.agent_claim) { w.hidden = true; w.textContent = ""; return; }
  const claimedSend = /send_email/.test(s.agent_claim);
  const reallySent = s.outbox.length > 0;
  w.hidden = false; w.textContent = "";
  w.append(el("b", { text: "Agent's own claim (unverified): " }), el("span", { text: s.agent_claim }));
  if (claimedSend && !reallySent)
    w.append(el("div", { class: "muted", text: "The agent reports sending, but the outbox above is the truth: nothing was sent." }));
}

function renderAudit(s) {
  const box = $("audit"); box.textContent = "";
  $("audit-verified").textContent = s.audit_verified == null ? "no audit (baseline)" : (s.audit_verified ? "chain verified" : "TAMPERED");
  if (!s.audit.length) { box.appendChild(el("div", { class: "empty", text: "No audit records (baseline configuration)." })); return; }
  for (const r of s.audit)
    box.appendChild(el("div", { class: "rec" }, [
      el("span", { class: "ev", text: r.event + " " }),
      el("span", { text: (r.tool || "-") + " -> " + r.status + " [" + (r.rule_ids || []).join(",") + "]" }),
    ]));
}

// ---- benchmark ----
async function loadBenchmark() {
  const box = $("benchmark");
  box.textContent = "Running benchmark (a few seconds)...";
  try {
    const data = await api("/api/benchmark");
    $("benchmark").dataset.loaded = "1";
    renderBenchmark(data);
  } catch (e) { box.textContent = "error: " + e.message; }
}

function pct(r) { return r.rate == null ? "n/a" : Math.round(r.rate * 100) + "% (" + r.k + "/" + r.n + ")"; }

function renderBenchmark(data) {
  const m = data.metadata;
  $("benchmark-meta").textContent = "commit " + (m.git_commit || "?").slice(0, 10) + " - agent " + (m.agent.agent || "?") +
    " - policy " + m.policy_version + " - threshold " + m.escalation_threshold;
  const box = $("benchmark"); box.textContent = "";
  const splits = [...new Set(data.summaries.map((s) => s.split))].sort((a, b) => (a === "heldout" ? -1 : 1));
  for (const split of splits) {
    const rows = data.summaries.filter((s) => s.split === split);
    box.append(el("h2", { text: "Split: " + split }));
    const det = data.detector[split];
    if (det) box.append(el("p", { class: "muted", text:
      "Detector on " + det.documents + " docs (threshold " + det.threshold + "): precision " + det.precision +
      ", recall " + det.recall + ", F1 " + det.f1 + " (TP " + det.tp + " FP " + det.fp + " FN " + det.fn + " TN " + det.tn + ")" }));
    const headers = ["Config", "Approver", "Attack success", "Blocking", "Unauth execs", "Unapproved", "Utility", "False pos"];
    const table = el("table", { class: "bench" });
    table.append(el("tr", {}, headers.map((h) => el("th", { text: h }))));
    for (const s of rows) {
      const rc = s.config[0] === "A" ? "rowA" : s.config.startsWith("D_") ? "rowD" : "";
      const ue = s.unauthorized_executions;
      table.append(el("tr", { class: rc }, [
        el("td", { class: "cfg", text: s.config }),
        el("td", { text: s.approver }),
        el("td", { text: pct(s.attack_success_rate) }),
        el("td", { text: pct(s.blocking_rate) }),
        el("td", {}, [el("span", { class: ue === 0 ? "good" : "bad", text: String(ue) })]),
        el("td", { text: String(s.unapproved_side_effects) }),
        el("td", { text: pct(s.utility) }),
        el("td", { text: pct(s.false_positive_rate) }),
      ]));
    }
    box.append(table);
  }
}

init().catch((e) => { $("run-note").textContent = "init error: " + e.message; });
