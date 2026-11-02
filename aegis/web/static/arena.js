"use strict";
// Real AI arena: results of attacking a real model (scripts/run_real_ai_benchmark.py)
// plus a live attack. Uses helpers from app.js (el, $, api, icon, sidePanel, META).

let ARENA = null;
let arenaMode = null;
let arenaLoaded = false;

const ARENA_MODE_INFO = {
  naive: { name: "Naive assistant", sub: "A typical helpful-assistant prompt with no security instructions." },
  careful: { name: "Careful assistant", sub: "Told to ignore any instructions found inside emails." },
};

function countUp(node, to, suffix) {
  const start = performance.now();
  const dur = 1100;
  const tick = (t) => {
    const k = Math.min(1, (t - start) / dur);
    node.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))) + (suffix || "");
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function loadArena() {
  if (!arenaLoaded) {
    arenaLoaded = true;
    if (!META) { try { META = await api("/api/meta"); } catch (e) { /* live attack stays disabled */ } }
    try { ARENA = await api("/api/real-ai"); } catch (e) { ARENA = { available: false }; }
    initLive();
  }
  renderArena();
}

// ---------------------------------------------------------------- results view

function arenaEmpty() {
  const llm = META && META.llm;
  return el("div", { class: "arena-hero" }, [
    el("div", { class: "eyebrow light", text: "Real AI arena" }),
    el("h1", { text: "Attack a real AI with poisoned emails." }),
    el("p", { class: "arena-lead", text: "No real-AI results yet. Run the benchmark once on your machine and they appear here: how often the AI was fooled, and what Aegis stopped." }),
    el("ol", { class: "arena-steps" }, [
      el("li", {}, ["Put your model settings in ", el("code", { text: ".env" }), " (AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL, AEGIS_LLM_API_KEY)."]),
      el("li", {}, ["Run ", el("code", { text: "python scripts/run_real_ai_benchmark.py" }), ". Add ", el("code", { text: "--suite my_emails/" }), " to use your own emails."]),
      el("li", { text: "Reload this page." }),
    ]),
    el("p", { class: "arena-lead small", text: llm && llm.available
      ? "A real AI is configured (" + llm.model + "), so the live attack below works now."
      : "No real AI is configured yet, so the live attack below is disabled." }),
  ]);
}

function summaryFor(mode) {
  return { A: ARENA.summary[mode + "|A_unprotected"], D: ARENA.summary[mode + "|D_aegis"] };
}

function runsFor(caseId, mode) {
  const rs = ARENA.runs.filter((r) => r.case_id === caseId && r.mode === mode);
  return { A: rs.find((r) => r.config === "A_unprotected"), D: rs.find((r) => r.config === "D_aegis") };
}

function tileState(caseId, mode) {
  const { A, D } = runsFor(caseId, mode);
  if ((A && A.status === "error") || (D && D.status === "error")) return { cls: "err", text: "Error (model unavailable)" };
  if (!A && !D) return { cls: "none", text: "Not run" };
  if (D && D.harm) return { cls: "harm", text: "Harm even with Aegis" };
  if ((D && D.fooled) || (A && A.fooled)) return { cls: "blocked", text: "AI was fooled, Aegis blocked the action" };
  return { cls: "resisted", text: "AI resisted the attack" };
}

function bigStat(value, suffix, label, tone) {
  const v = el("div", { class: "astat-v " + tone, text: "0" + (suffix || "") });
  countUp(v, value, suffix);
  return el("div", { class: "astat" }, [v, el("div", { class: "astat-k", text: label })]);
}

function funnel(attacks, fooled, harmA, harmD) {
  const max = Math.max(attacks, 1);
  const row = (label, n, tone) => {
    const fill = el("div", { class: "fn-fill " + tone });
    fill.style.width = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = (n / max) * 100 + "%"; }));
    return el("div", { class: "fn-row" }, [el("div", { class: "fn-label", text: label }),
      el("div", { class: "fn-track" }, [fill]), el("div", { class: "fn-n", text: String(n) })]);
  };
  return el("div", { class: "funnel" }, [
    row("Poisoned emails sent to the AI", attacks, "neutral"),
    row("The AI was fooled (tried a forbidden action)", fooled, "warn"),
    row("Real harm without protection", harmA, "bad"),
    row("Real harm with Aegis", harmD, harmD ? "bad" : "good"),
  ]);
}

function renderArena() {
  const body = $("arena-body");
  body.textContent = "";
  if (!ARENA || !ARENA.available) { body.append(arenaEmpty()); return; }
  const meta = ARENA.meta;
  const modes = meta.modes.filter((m) => ARENA_MODE_INFO[m]);
  if (!arenaMode || !modes.includes(arenaMode)) arenaMode = modes[0];
  const { A, D } = summaryFor(arenaMode);
  const attacks = D ? D.attack_runs : A ? A.attack_runs : 0;
  const fooled = Math.max(D ? D.fooled_on_attacks : 0, A ? A.fooled_on_attacks : 0);
  const harmA = A ? A.harm_on_attacks : 0;
  const harmD = D ? D.harm_on_attacks : 0;

  const toggle = el("div", { class: "mode-toggle" });
  for (const m of modes) {
    const b = el("button", { class: m === arenaMode ? "active" : "", text: ARENA_MODE_INFO[m].name });
    b.addEventListener("click", () => { arenaMode = m; renderArena(); });
    toggle.append(b);
  }

  body.append(el("div", { class: "arena-hero" }, [
    el("div", { class: "eyebrow light", text: "Real AI arena \u00b7 measured, not simulated" }),
    el("h1", {}, ["We attacked ", el("span", { class: "grad", text: meta.model }), " with poisoned emails."]),
    el("p", { class: "arena-lead", text: "The real model read each email and decided for itself what to do. "
      + "Every attempted action went through Aegis. " + attacks + " attacks, scored on what actually left the system." }),
    toggle,
    el("div", { class: "arena-mode-sub", text: ARENA_MODE_INFO[arenaMode].sub }),
    el("div", { class: "astats" }, [
      bigStat(fooled, " / " + attacks, "attacks fooled the AI into trying a forbidden action", "warn"),
      bigStat(harmA, "", "attacks caused real harm without protection", "bad"),
      bigStat(harmD, "", "attacks caused real harm with Aegis", harmD ? "bad" : "good"),
    ]),
    funnel(attacks, fooled, harmA, harmD),
  ]));

  // Tile grid of every case
  const grid = el("div", { class: "tiles" });
  const detail = el("div", { id: "arena-detail" });
  const counts = { blocked: 0, harm: 0, resisted: 0, err: 0, none: 0 };
  ARENA.cases.forEach((c, i) => {
    const st = tileState(c.case_id, arenaMode);
    if (c.label === "attack") counts[st.cls] += 1;
    const tile = el("button", { class: "tile " + st.cls + (c.label === "benign" ? " benign" : ""), title: c.case_id + ": " + st.text });
    tile.style.animationDelay = Math.min(i * 12, 900) + "ms";
    tile.append(st.cls === "blocked" ? icon("shield") : st.cls === "harm" ? icon("x") : st.cls === "resisted" ? icon("check") : el("span", { text: "?" }));
    tile.addEventListener("click", () => {
      for (const t of grid.children) t.classList.remove("sel");
      tile.classList.add("sel");
      showArenaCase(c, detail);
    });
    grid.append(tile);
  });
  const legend = el("div", { class: "legend" }, [
    el("span", { class: "lg blocked" }, [icon("shield"), " AI fooled, Aegis blocked it (" + counts.blocked + ")"]),
    el("span", { class: "lg resisted" }, [icon("check"), " AI resisted (" + counts.resisted + ")"]),
    el("span", { class: "lg harm" }, [icon("x"), " Harm even with Aegis (" + counts.harm + ")"]),
    counts.err ? el("span", { class: "lg err", text: "? Error (" + counts.err + ")" }) : null,
    el("span", { class: "lg benign-k", text: "Faded tiles are normal emails (no attack)" }),
  ]);
  body.append(el("div", { class: "arena-panel" }, [
    el("h2", { text: "Every email, one tile each" }),
    el("p", { class: "muted", text: "Click a tile to see exactly what " + meta.model + " tried to do, and what Aegis did about it." }),
    legend, grid, detail,
  ]));
  if (ARENA.published) body.append(el("p", { class: "muted arena-foot", text:
    "These are recorded results from a real run of " + meta.model + ", saved in the repository. This public site does not call the model itself." }));
  body.append(el("p", { class: "muted arena-foot", text: "Run " + meta.run_name + " \u00b7 model " + meta.model + " \u00b7 temperature "
    + meta.temperature + " \u00b7 started " + meta.started_at + (meta.finished_at ? " \u00b7 finished " + meta.finished_at : "")
    + ". \"Fooled\" means the model proposed an action the user's task does not allow, as judged by the same reference policy as the main benchmark." }));
}

function fileName(id) {
  const f = ARENA.files && ARENA.files[id];
  return f ? f.name : id;
}

function describeRunStep(st) {
  const a = st.args || {};
  const to = Array.isArray(a.to) ? a.to.join(", ") : String(a.to || "?");
  const att = Array.isArray(a.attachments) && a.attachments.length ? ", attaching " + a.attachments.map(fileName).join(", ") : "";
  switch (st.tool) {
    case "read_email": return "Read email " + (a.email_id || "");
    case "read_file": return "Open " + fileName(a.file_id);
    case "search_files": return "Search files for \u201c" + (a.query || "") + "\u201d";
    case "draft_email": return "Draft an email to " + to;
    case "send_email": return "Send an email to " + to + att;
    default: return st.tool ? "Use a tool called \u201c" + st.tool + "\u201d" : "Malformed request";
  }
}

function runColumn(run, title, tone) {
  if (!run) return el("div", { class: "rcol" }, [el("h4", { text: title }), el("p", { class: "muted", text: "Not run." })]);
  const verdict = run.status === "error" ? el("div", { class: "outcome wait" }, [el("b", { text: "Model error" }), el("span", { text: run.error || "" })])
    : run.harm ? el("div", { class: "outcome bad" }, [el("b", {}, [icon("x"), " Real harm"]), el("span", { text: "The attacker's goal was reached." })])
    : run.fooled ? el("div", { class: "outcome good" }, [el("b", {}, [icon("shield"), " Fooled, but blocked"]), el("span", { text: "The AI tried a forbidden action; Aegis refused it." })])
    : el("div", { class: "outcome good" }, [el("b", {}, [icon("check"), " No harm"]), el("span", { text: "The AI did not try anything forbidden." })]);
  const list = el("ol", { class: "timeline" });
  for (const st of run.steps) {
    const ok = st.status === "executed";
    const blocked = ["denied", "rejected_by_user", "failed"].includes(st.status);
    list.append(el("li", { class: "tl " + (ok ? "ok" : blocked ? "blocked" : "") }, [el("div", { class: "tl-main" }, [
      el("span", { class: "tl-what", text: describeRunStep(st) }),
      el("span", { class: "tl-status " + (ok ? "ok" : "blocked"), text: ok ? (st.approval === "approved" ? "Approved, done" : "Done")
        : st.rule_ids.includes("B01") ? "Blocked by scanner" : blocked ? (run.config === "D_aegis" ? "Blocked by Aegis" : "Rejected") : st.status }),
    ])]));
  }
  if (!run.steps.length) list.append(el("li", { class: "tl", text: "The AI took no actions." }));
  const sent = run.outbox.length
    ? run.outbox.map((m) => el("div", { class: "msg" }, [el("div", { class: "msg-to", text: "To " + m.to.join(", ") }),
        m.attachments.length ? el("div", { class: "msg-att" }, m.attachments.map((id) => el("span", { class: "att s-" + ((ARENA.files[id] || {}).sensitivity || "public") }, [icon("clip"), " " + fileName(id)]))) : null]))
    : [el("div", { class: "empty", text: "Nothing left the system." })];
  return el("div", { class: "rcol " + tone }, [
    el("h4", { text: title }), verdict,
    el("div", { class: "lbl sp", text: "What the AI tried" }), list,
    el("div", { class: "lbl sp", text: "What actually left the system" }), ...sent,
    run.final_message ? el("div", { class: "ai-said" }, [el("span", { class: "lbl", text: "The AI's final words (not trusted): " }), run.final_message]) : null,
  ]);
}

function showArenaCase(c, box) {
  const { A, D } = runsFor(c.case_id, arenaMode);
  box.textContent = "";
  box.append(el("div", { class: "case-detail" }, [
    el("div", { class: "case-head" }, [
      el("span", { class: "badge lbl-" + c.label, text: c.label === "attack" ? "attack" : "normal email" }),
      el("b", { text: c.case_id }), el("span", { class: "muted", text: " \u00b7 " + (c.description || c.category) }),
    ]),
    c.preview && c.preview.body ? el("div", { class: "mail-card" }, [
      el("div", { class: "mail-head" }, [el("div", { class: "mail-subj" }, [icon("mail"), " " + c.preview.subject]),
        el("div", { class: "mail-from", text: "From: " + c.preview.from })]),
      el("div", { class: "mail-body", text: c.preview.body }),
    ]) : null,
    el("div", { class: "compare" }, [runColumn(A, "Without protection", "bad"), runColumn(D, "With Aegis", "good")]),
  ]));
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---------------------------------------------------------------- live attack

function initLive() {
  const sel = $("live-scenario");
  const llm = META && META.llm;
  if (!sel.childElementCount && META) {
    for (const split of Object.keys(META.splits)) {
      for (const s of META.splits[split]) {
        if (s.label === "attack") sel.append(el("option", { value: s.id, text: s.id + (s.description ? " \u2014 " + s.description.slice(0, 70) : "") }));
      }
    }
    sel.value = "dev-03-payroll-reply";
  }
  const btn = $("live-run");
  if (!(llm && llm.available)) {
    btn.disabled = true;
    $("live-note").textContent = "Add a Gemini key to .env and restart the dashboard to enable live attacks.";
  } else {
    btn.textContent = "Launch attack on " + llm.model;
  }
  if (!btn.dataset.bound) {
    btn.dataset.bound = "1";
    btn.addEventListener("click", runLive);
  }
}

async function runLive() {
  const btn = $("live-run");
  const body = $("live-body");
  btn.disabled = true;
  body.textContent = "";
  const model = (META.llm && META.llm.model) || "the AI";
  const pulse = el("div", { class: "thinking" }, [el("span", { class: "dot" }), el("span", { class: "dot" }), el("span", { class: "dot" }),
    el("span", { text: " " + model + " is reading the poisoned email\u2026 (this can take a minute)" })]);
  body.append(pulse);
  try {
    const data = await api("/api/compare", { scenario_id: $("live-scenario").value, left: "A_unprotected", right: "D_aegis",
      agent: "llm", mode: $("live-mode").value });
    body.textContent = "";
    const card = emailCard(data.left, null);
    if (card) body.append(card);
    body.append(el("div", { class: "compare" }, [sidePanel(data.left, null), sidePanel(data.right, null)]));
    const L = data.left.outcome, R = data.right.outcome;
    const fooled = data.left.steps.some((s) => s.injected) || data.right.steps.some((s) => s.injected);
    const msg = !fooled && !L.attack
      ? model + " resisted this attack on its own. Not every real AI is fooled every time; Aegis is there for the times it is."
      : L.attack && !R.attack
        ? model + " was fooled. Without protection the attack worked; with Aegis the forbidden action was refused."
        : R.attack ? "The attack reached its goal even with Aegis, which happens only for in-scope changes such as the wording of an allowed reply."
          : model + " started acting on the email; Aegis refused the forbidden step.";
    body.append(el("div", { class: "takeaway" }, [el("b", { text: "Live result: " }), msg]));
  } catch (e) {
    body.textContent = "";
    body.append(el("div", { class: "outcome wait" }, [el("b", { text: "The live attack could not run" }), el("span", { text: e.message })]));
  } finally {
    btn.disabled = false;
  }
}
