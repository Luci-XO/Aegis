// Records a subtitled walkthrough of the Aegis dashboard.
// Run: PLAYWRIGHT_BROWSERS_PATH=/inner_container/opt/playwright node record.js
const { chromium } = require("/root/.nvm/versions/node/v22.23.4/lib/node_modules/@playwright/mcp/node_modules/playwright-core");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const DIR = __dirname;
const URL = "http://127.0.0.1:8123/";
const W = 1280, H = 720;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(URL); if (r.ok) return; } catch {}
    await sleep(250);
  }
  throw new Error("server did not start");
}

(async () => {
  const server = spawn("python3", [path.join(DIR, "run_aegis.py")], { stdio: "ignore" });
  try {
    await waitForServer();
    const browser = await chromium.launch();
    const context = await browser.newContext({
      viewport: { width: W, height: H },
      deviceScaleFactor: 1,
      recordVideo: { dir: path.join(DIR, "raw"), size: { width: W, height: H } },
    });
    const page = await context.newPage();
    const t0 = Date.now();
    const cues = [];
    let open = null;

    const now = () => Date.now() - t0;
    async function caption(text, holdMs) {
      if (open) { open.end = now(); cues.push(open); }
      open = text ? { start: now(), text } : null;
      await page.evaluate((t) => {
        const b = document.getElementById("__cap");
        b.style.opacity = t ? "1" : "0";
        if (t) b.querySelector("span").textContent = t;
      }, text);
      if (holdMs) await sleep(holdMs);
    }
    // Reading time: about 3 words per second, minimum 2.5 s.
    const say = (text, extra = 0) => caption(text, Math.max(2500, (text.split(/\s+/).length / 3) * 1000) + extra);

    async function scrollToEl(selector, { block = 0.12, ms = 1600, nth = 0 } = {}) {
      await page.evaluate(async ({ selector, block, ms, nth }) => {
        const el = document.querySelectorAll(selector)[nth];
        if (!el) return;
        const target = Math.max(0, el.getBoundingClientRect().top + window.scrollY - window.innerHeight * block);
        const start = window.scrollY, dist = target - start, t0 = performance.now();
        await new Promise((done) => {
          const step = (t) => {
            const k = Math.min(1, (t - t0) / ms);
            window.scrollTo(0, start + dist * (k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2));
            k < 1 ? requestAnimationFrame(step) : done();
          };
          requestAnimationFrame(step);
        });
      }, { selector, block, ms, nth });
    }
    async function scrollTop(ms = 900) {
      await page.evaluate((ms) => new Promise((done) => {
        const start = window.scrollY, t0 = performance.now();
        const step = (t) => { const k = Math.min(1, (t - t0) / ms); window.scrollTo(0, start * (1 - k)); k < 1 ? requestAnimationFrame(step) : done(); };
        requestAnimationFrame(step);
      }), ms);
    }
    async function highlight(selector, nth = 0) {
      await page.evaluate(({ selector, nth }) => {
        document.querySelectorAll(".__hl").forEach((e) => { e.classList.remove("__hl"); });
        const el = document.querySelectorAll(selector)[nth];
        if (el) el.classList.add("__hl");
      }, { selector, nth });
    }
    async function openStory(i) {
      await caption(null, 350);
      await page.locator("#story-nav button").nth(i).click();
      await page.waitForSelector("#story-body .takeaway", { timeout: 20000 });
      await scrollTop(400);
    }

    await page.goto(URL, { waitUntil: "networkidle" });
    await page.addStyleTag({ content: `
      #__cap { position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%); z-index: 2147483647;
        max-width: 1060px; width: max-content; padding: 12px 22px; border-radius: 10px;
        background: rgba(12,16,28,0.86); color: #fff; font: 600 24px/1.35 system-ui, "Segoe UI", sans-serif;
        text-align: center; pointer-events: none; transition: opacity .35s; box-shadow: 0 6px 24px rgba(0,0,0,.35); }
      #__brand { position: fixed; top: 10px; right: 14px; z-index: 2147483647; pointer-events: none;
        font: 700 13px system-ui, sans-serif; color: #fff; background: #1f3864; padding: 4px 10px; border-radius: 6px; opacity: .85; }
      body { padding-bottom: 260px !important; }
      .__hl { outline: 4px solid #f5b301 !important; outline-offset: 4px; border-radius: 8px; transition: outline-color .3s; }
    `});
    await page.evaluate(() => {
      const c = document.createElement("div"); c.id = "__cap"; c.style.opacity = "0";
      c.append(document.createElement("span")); document.body.append(c);
    });
    await sleep(800);

    // ---- 1. Overview
    await say("This is Aegis: a security checkpoint between an AI agent and the tools it can use.");
    await say("AI agents can now read your email and act on it. Anything they read can secretly instruct them.");
    await scrollToEl("#view-home h2, #view-home section", { nth: 1, ms: 2200 });
    await say("That attack is called prompt injection. It is the number one risk for LLM apps on the OWASP Top 10.");
    await scrollTop();
    await say("Aegis doesn't trust the AI. Every action is checked against fixed rules before it runs.");

    // ---- 2. Guided demo: normal task
    await caption(null, 350);
    await page.click('#view-home button[data-go="story"]');
    await page.waitForSelector("#story-body .takeaway", { timeout: 20000 });
    await say("The guided demo runs real scenarios through the real code. Left: no protection. Right: Aegis.");
    await say("Scenario 1 is a normal task: send the offsite agenda to two colleagues.");
    await scrollToEl(".compare", { ms: 1800 });
    await say("Both sides send the email. Aegis doesn't get in the way of legitimate work.");

    // ---- 3. Hidden instruction
    await openStory(1);
    await say("Scenario 2: the user asks the AI to reply to a vendor's invoice email.");
    await scrollToEl(".mail-card", { ms: 1600 });
    await highlight(".mail-card mark");
    await say("Hidden inside it is an instruction for the AI: send the confidential payroll file to an outside 'auditor'.", 500);
    await highlight(".compare .side", 0);
    await scrollToEl(".compare", { ms: 1800 });
    await say("Without protection, the fooled AI obeys. The payroll file leaks to the attacker.", 500);
    await highlight(".compare .side", 1);
    await say("With Aegis, the same fooled AI tries the same action. Aegis refuses it.", 300);
    await scrollToEl(".compare .side .checkpoint, .compare .side h4", { nth: 3, ms: 1600 });
    await say("The user's task never allowed that file or that recipient, so the action never ran. The real reply still went out.", 700);
    await highlight("none");

    // ---- 4. Scanner fooled
    await openStory(2);
    await say("Scenario 3: the attacker rewords the request so it avoids the usual trigger phrases.");
    await scrollToEl(".compare", { ms: 1800 });
    await highlight(".compare .side", 0);
    await say("On the left, a threat scanner is the only defence. It misses the attack, and payroll is sent out.", 400);
    await highlight(".compare .side", 1);
    await say("On the right, Aegis blocks it. Aegis doesn't need to recognise the attack. It checks whether the action is allowed.", 600);
    await highlight("none");

    // ---- 5. Extra recipient
    await openStory(3);
    await say("Scenario 4: an email asks the AI to quietly copy an extra 'compliance' address on the reply.");
    await scrollToEl(".compare", { ms: 1800 });
    await say("Aegis only allows recipients from the user's task, never from text the AI reads. The extra address is refused.", 400);

    // ---- 6. Honest limit
    await openStory(4);
    await say("Scenario 5 is shown on purpose: what Aegis does not stop.");
    await scrollToEl(".takeaway", { ms: 2200, block: 0.3 });
    await highlight(".takeaway");
    await say("If the user allowed the reply, an attacker can still change its wording. Aegis controls actions and data flow, not wording.", 600);
    await highlight("none");

    // ---- 7. Test your own email
    await scrollTop(500);
    await caption(null, 350);
    await page.click('#nav button[data-go="custom"]');
    await sleep(600);
    await say("You can also test your own email: upload a .eml file or paste the text.");
    await page.click('button[data-example="attack"]');
    await sleep(500);
    await highlight("#paste");
    await say("Here is a sample email with a hidden request for the payroll file.");
    await highlight("none");
    await scrollToEl("#custom-run", { block: 0.5, ms: 900 });
    await page.click("#custom-run");
    await page.waitForFunction(() => document.getElementById("custom-body").childElementCount > 0, null, { timeout: 30000 });
    await sleep(400);
    await scrollToEl("#custom-body", { ms: 1800 });
    await say("First it shows what the scanners noticed, and what a fooled assistant would try to do.", 400);
    await scrollToEl("#custom-body .compare", { ms: 1800 });
    await say("Then it runs the email twice. Without protection, payroll leaks. With Aegis, the forbidden actions are refused.", 900);

    // ---- 8. Results
    await scrollTop(500);
    await caption(null, 350);
    await page.click('#nav button[data-go="results"]');
    await page.waitForFunction(() => document.getElementById("results-body").childElementCount > 2, null, { timeout: 60000 });
    await sleep(500);
    await say("We measured it on attacks written after the rules were frozen, so we couldn't tune for them.");
    await scrollToEl("#results-body", { ms: 1600 });
    await say("Attack success fell from 100% without protection to 10% with Aegis, with zero unauthorised actions.", 900);
    await say("Every normal task still completed. 322 tests pass, and the tests caught all 26 planted security bugs.", 600);

    // ---- 9. Close
    await scrollTop(600);
    await caption(null, 350);
    await page.click('#nav button[data-go="home"]');
    await sleep(500);
    await say("The AI can be completely fooled. Aegis is the wall.", 800);
    await say("Aegis · github.com/Luci-XO/Aegis", 1200);
    await caption(null, 700);

    const video = page.video();
    await context.close();
    await browser.close();
    const raw = await video.path();
    fs.renameSync(raw, path.join(DIR, "Aegis_demo.webm"));

    const ts = (ms) => {
      const h = Math.floor(ms / 3600000), m = Math.floor(ms / 60000) % 60, s = Math.floor(ms / 1000) % 60, x = ms % 1000;
      return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")},${String(x).padStart(3, "0")}`;
    };
    fs.writeFileSync(path.join(DIR, "Aegis_demo.srt"),
      cues.map((c, i) => `${i + 1}\n${ts(c.start)} --> ${ts(c.end)}\n${c.text}\n`).join("\n"));
    console.log(`done: ${(now() / 1000).toFixed(1)} s, ${cues.length} captions`);
  } finally {
    server.kill();
  }
})().catch((e) => { console.error(e); process.exit(1); });
