# Email threat classifier (scikit-learn optional) and Gemini judge

This adds an ML detector for **phishing and spam emails**, trained and
evaluated on the 100-email "Gmail Security Agent - Test Corpus" (E001 to E100,
48 legit / 52 malicious). It is a different task from the prompt-injection
detector (`rules-v1`): that one looks for instructions aimed at an AI agent,
this one looks for emails that try to scam a person.

| File | Purpose |
|---|---|
| `aegis/data/email_corpus.json` | The corpus as structured data (built by `scripts/build_email_corpus.py`) |
| `aegis/detect/email_classifier.py` | TF-IDF + logistic regression, `stdlib` or `sklearn` backend, red-flag explanations, Aegis detector adapter |
| `aegis/eval/email_eval.py` | Metrics, grouped cross-validation, rule baselines, LLM judge |
| `scripts/eval_email_classifier.py` | One command that prints the comparison table |

## Run it in VS Code (your machine)

1. Open the repo folder in VS Code: **File > Open Folder > Aegis**.
2. Open a terminal: **Terminal > New Terminal**.
3. Create a virtual environment and install scikit-learn:

   ```bash
   python -m venv .venv
   # Windows:      .venv\Scripts\activate
   # macOS/Linux:  source .venv/bin/activate
   pip install scikit-learn pytest
   ```

   In VS Code, also pick that interpreter: **Ctrl+Shift+P > Python: Select
   Interpreter > .venv**.
4. Run the evaluation with the scikit-learn backend:

   ```bash
   python scripts/eval_email_classifier.py --backend sklearn
   python -m pytest tests/test_email_classifier.py
   ```

Without scikit-learn installed, `--backend auto` (the default) falls back to
the built-in pure-Python model, so everything still runs.

## Gemini as an LLM judge (optional)

1. Get a **new** key at <https://aistudio.google.com/apikey>. Gemini API keys
   normally begin with `AIza`.
2. Copy `.env.example` to `.env` (already git-ignored) and set:

   ```
   AEGIS_LLM_PROVIDER=gemini
   AEGIS_LLM_MODEL=gemini-2.5-flash
   AEGIS_LLM_API_KEY=your-new-key
   ```

3. Run `python scripts/eval_email_classifier.py --llm --delay 4`. The delay
   keeps you under free-tier rate limits. A bad key shows as `HTTP 401` or
   `HTTP 403`, a wrong model name as `HTTP 404` or `400`.

The same `.env` also drives the agent benchmark with a real model:
`python -m aegis.eval --agent llm` and `python scripts/run_scenarios.py --agent llm`.

Aegis talks to Gemini through Google's
[OpenAI-compatible endpoint](https://ai.google.dev/gemini-api/docs/openai)
(`https://generativelanguage.googleapis.com/v1beta/openai`), using only the
standard library. Email text is sent between `<email>` tags with an
instruction to ignore anything inside them; an unparseable reply is counted as
flagged, never as safe.

## Results (built-in backend, measured in the build sandbox)

| Detector | Evaluation | Precision | Recall | F1 | FPR legit | FPR tricky-legit | FP / FN |
|---|---|---|---|---|---|---|---|
| auth-header rule (SPF/DMARC not pass) | all 100 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0 / 0 |
| red-flag rules (text only) | all 100 | 0.96 | 0.98 | 0.97 | 0.04 | 0.20 | 2 / 1 |
| prompt-injection rules-v1 | all 100 | n/a | 0.00 | n/a | 0.00 | 0.00 | 0 / 52 |
| classifier, text | 5-fold **random** | 1.00 | 0.98 | 0.99 | 0.00 | 0.00 | 0 / 1 |
| classifier, text | 5-fold **grouped by template** | 1.00 | 0.83 | 0.91 | 0.00 | 0.00 | 0 / 9 |
| classifier, text + headers | 5-fold random | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 0 / 0 |
| classifier, text + headers | 5-fold grouped by template | 1.00 | 0.94 | 0.97 | 0.00 | 0.00 | 0 / 3 |

"Malicious" means PHISHING or SPAM. Rates are on 100 emails, so one email
moves recall by about 2 points.

## What the results mean

1. **Random cross-validation overstates the model.** Many emails share a
   template (14 credential-phishing emails differ only in brand and session
   id). Shuffling them into folds lets the model see the same template in
   training and test, giving F1 0.99. Holding out whole template families
   gives **F1 0.91**: the model misses 9 of 52 malicious emails it had no
   template for (utility-bill callback scams, fake voicemails, the `.iso`
   invoice, the wire-fraud email). The grouped number is the one to report.
2. **The corpus is fully separable by email authentication headers.** Every
   legit email passes SPF/DKIM/DMARC and every malicious one fails, so a
   one-line rule scores F1 1.00. That is a property of this synthetic corpus,
   not of real email: real phishing often passes authentication (compromised
   or look-alike domains with valid records). Treat the text-only grouped
   result as the meaningful ML measurement.
3. **The prompt-injection detector catches none of these** (recall 0.00),
   which is expected: phishing targets the human, not an AI agent's
   instructions. The two detectors cover different threats.
4. **Explanations.** Every verdict lists the strongest words and heuristic red
   flags (authentication failure, Reply-To mismatch, risky attachment type,
   urgency, credential or PIN request, macro lure, payment-detail change,
   secrecy), matching the categories in the corpus answer key.

## Honest limitations

- 100 emails and 36 templates is small; confidence intervals are wide.
- The red-flag rules were written while reading this corpus, so their score
  is a development measurement, not a held-out result.
- The scikit-learn backend and the live Gemini judge have **not** been run in
  the build sandbox (no package downloads or outbound network there). They
  are covered by tests that skip without scikit-learn and by a fake LLM
  client. Run them on your machine to get those numbers.
- The classifier is not part of the frozen agent benchmark, so the published
  Aegis benchmark numbers are unchanged. `ClassifierDetector` lets you plug it
  into the gateway as a risk signal, which (like any detector) can only
  escalate a decision, never permit a denied action.
