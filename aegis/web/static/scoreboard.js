// Head-to-head scoreboard: your AI vs a real AI (Gemini) on one email corpus.
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
  return el("div", { class: "arena-hero" }, [
    el("div", { class: "eyebrow light", text: "Scoreboard" }),
    el("h1", { text: "Your AI vs a real AI, on the same emails." }),
    el("p", { class: "arena-lead", text: "No scoreboard yet. Run it once on your machine and the whole corpus is scored in one go \u2014 how many attacks each side stopped, how many got through, and how often each false-alarms on real email." }),
    el("ol", { class: "arena-steps" }, [
      el("li", {}, ["Build the corpus: ", el("code", { text: "python scripts/build_corpus_500.py" }), "."]),
      el("li", {}, ["Run ", el("code", { text: "python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json --llm --batch 25 --delay 4 --json results/scoreboard.json" }), "."]),
      el("li", { text: "Reload this page." }),
    ]),
    el("p", { class: "arena-lead small", text: "Without --llm it still writes your AI's column; add --llm (with .env set) for the Gemini side." }),
  ]);
}

// A labelled comparison bar. good=true means higher is better (green); false means lower is better (red scale).
function bar(label, a, b, good) {
  const row = el("div", { class: "sb-row" }, [el("div", { class: "sb-label", text: label })]);
  const sides = el("div", { class: "sb-bars" });
  for (const c of (b === null ? [a] : [a, b])) {
    if (!c) continue;
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

  const you = SCORE.your_ai, gem = SCORE.gemini || null;
  host.append(el("div", { class: "page-intro" }, [
    el("h2", { text: "Scoreboard \u2014 your AI vs a real AI" }),
    el("p", {}, [
      "On ", el("b", { text: String(SCORE.total) }), " emails (", String(SCORE.malicious),
      " malicious, ", String(SCORE.legit), " legit). Your AI is scored with grouped cross-validation (tested only on templates it never trained on); ",
      gem ? gem.name : "Gemini", " is zero-shot.",
    ]),
  ]));

  const names = el("div", { class: "sb-head" }, [
    el("div", { class: "sb-label" }),
    el("div", { class: "sb-bars" }, [
      el("div", { class: "sb-sys-name strong", text: you.name }),
      gem ? el("div", { class: "sb-sys-name strong", text: gem.name }) : null,
    ]),
  ]);
  host.append(names);

  const g = (f) => (gem ? f(gem) : null);
  host.append(el("div", { class: "sb-grid" }, [
    bar("Attacks stopped", cell(you.name, you.stopped, you.malicious), g((x) => cell(x.name, x.stopped, x.malicious)), true),
    bar("Attacks that got through", cell(you.name, you.got_through, you.malicious), g((x) => cell(x.name, x.got_through, x.malicious)), false),
    bar("Hard phishing caught", cell(you.name, you.hard_stopped, you.hard_total), g((x) => cell(x.name, x.hard_stopped, x.hard_total)), true),
    bar("False alarms on real email", cell(you.name, you.false_alarms, you.legit), g((x) => cell(x.name, x.false_alarms, x.legit)), false),
    bar("Overall accuracy", pctCell(you.name, you.accuracy), g((x) => pctCell(x.name, x.accuracy)), true),
  ]));

  if (gem && gem.unparsed) {
    host.append(el("p", { class: "muted", text:
      "Note: " + gem.name + " did not return a usable answer for " + gem.unparsed +
      " emails; those are counted as flagged, which inflates both its 'stopped' and its 'false alarms'. "
      + "Rerun with gemini-2.5-flash and a smaller --batch for a clean full comparison." }));
  }
  host.append(el("p", { class: "muted small", text:
    "The classifier is a bonus signal \u2014 not the security boundary. Even a perfect detector doesn't stop an agent from acting; Aegis's policy gateway does (see the Guided demo)." }));
}

function pctCell(sys, acc) {
  const p = Math.round(100 * (acc || 0));
  return { sys, pctNum: p, text: p + "%" };
}
