// Scoreboard: how your AI does on one email corpus, scored honestly.
// Reads results written by `python scripts/scoreboard.py --json results/scoreboard.json`.
// Uses helpers from app.js (el, $, api, icon).

let SCORE = null;
let scoreLoaded = false;

async function loadScoreboard() {
  if (!scoreLoaded) {
    scoreLoaded = true;
    try { SCORE = await api("/api/scoreboard"); } catch (e) { SCORE = { available: false }; }
  }
  renderScoreboard();
}

function scoreEmpty() {
  return el("div", { class: "sb-empty" }, [
    el("div", { class: "eyebrow light", text: "Scoreboard" }),
    el("h1", { text: "Your AI, on the same emails every time." }),
    el("p", { class: "sb-empty-lead", text: "No scoreboard yet. Run it once on your machine and the whole corpus is scored in one go \u2014 how many attacks the filter stopped, how many got through, and how often it false-alarms on real email." }),
    el("ol", { class: "sb-empty-steps" }, [
      el("li", {}, ["Build the corpus: ", el("code", { text: "python scripts/build_corpus_500.py" }), "."]),
      el("li", {}, ["Run ", el("code", { text: "python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json --json results/scoreboard.json" }), "."]),
      el("li", { text: "Reload this page." }),
    ]),
    el("p", { class: "sb-empty-lead small", text: "Everything runs offline, no API keys needed." }),
  ]);
}

// A labelled bar. good=true means higher is better (green); false means lower is better (red scale).
function bar(label, a, good) {
  const row = el("div", { class: "sb-row" }, [el("div", { class: "sb-label", text: label })]);
  const sides = el("div", { class: "sb-bars" });
  const c = a;
  if (c) {
    const cls = good ? (c.pctNum >= 90 ? "good" : c.pctNum >= 70 ? "mid" : "bad")
      : (c.pctNum <= 10 ? "good" : c.pctNum <= 25 ? "mid" : "bad");
    const fill = el("div", { class: "sb-fill " + cls });
    fill.style.width = "0%";
    requestAnimationFrame(() => { fill.style.width = Math.max(2, c.pctNum) + "%"; });
    sides.append(el("div", { class: "sb-sys" }, [
      el("div", { class: "sb-sys-name", text: c.sys }),
      el("div", { class: "sb-track" }, [fill]),
      el("div", { class: "sb-num", text: c.text }),
    ]));
  }
  row.append(sides);
  return row;
}

function cell(sys, num, den) {
  const p = den ? Math.round((100 * num) / den) : 0;
  return { sys, pctNum: p, text: den ? num + " / " + den + "  (" + p + "%)" : "n/a" };
}

function renderScoreboard() {
  const host = $("scoreboard-body");
  host.textContent = "";
  if (!SCORE || !SCORE.available) { host.append(scoreEmpty()); return; }

  const you = SCORE.your_ai;
  host.append(el("div", { class: "page-intro" }, [
    el("h2", { text: "Scoreboard \u2014 your AI on the corpus" }),
    el("p", {}, [
      "On ", el("b", { text: String(SCORE.total) }), " emails (", String(SCORE.malicious),
      " malicious, ", String(SCORE.legit), " legit). Your AI is scored with grouped cross-validation (tested only on templates it never trained on).",
    ]),
  ]));

  const names = el("div", { class: "sb-head" }, [
    el("div", { class: "sb-label" }),
    el("div", { class: "sb-bars" }, [
      el("div", { class: "sb-sys-name strong", text: you.name }),
    ]),
  ]);
  host.append(names);

  host.append(el("div", { class: "sb-grid" }, [
    bar("Attacks stopped", cell(you.name, you.stopped, you.malicious), true),
    bar("Attacks that got through", cell(you.name, you.got_through, you.malicious), false),
    bar("Hard phishing caught", cell(you.name, you.hard_stopped, you.hard_total), true),
    bar("False alarms on real email", cell(you.name, you.false_alarms, you.legit), false),
    bar("Overall accuracy", pctCell(you.name, you.accuracy), true),
  ]));

  host.append(el("p", { class: "muted small", text:
    "The classifier is a bonus signal \u2014 not the security boundary. Even a perfect detector doesn't stop an agent from acting; Aegis's policy gateway does (see the Guided demo)." }));
}

function pctCell(sys, acc) {
  const p = Math.round(100 * (acc || 0));
  return { sys, pctNum: p, text: p + "%" };
}
