# Email threat classifier (scikit-learn optional)

This adds an ML detector for **phishing and spam emails**, trained and
evaluated on the 100-email "Gmail Security Agent - Test Corpus" (E001 to E100,
48 legit / 52 malicious). It is a different task from the prompt-injection
detector (`rules-v1`): that one looks for instructions aimed at an AI agent,
this one looks for emails that try to scam a person.

| File | Purpose |
|---|---|
| `aegis/data/email_corpus.json` | The corpus as structured data (built by `scripts/build_email_corpus.py`) |
| `aegis/detect/email_classifier.py` | TF-IDF + logistic regression, `stdlib` or `sklearn` backend, red-flag explanations, Aegis detector adapter |
| `aegis/eval/email_eval.py` | Metrics, grouped cross-validation, rule baselines |
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

## Plugging in a real model (optional)

The same `.env` drives the agent benchmark with a real model:
`python -m aegis.eval --agent llm` and `python scripts/run_scenarios.py --agent llm`.
Set `AEGIS_LLM_PROVIDER` to `openai` (hosted) or `ollama` (local), plus
`AEGIS_LLM_MODEL` and, for hosted APIs, `AEGIS_LLM_API_KEY`. Any
OpenAI-compatible API works by setting `AEGIS_LLM_BASE_URL` explicitly. Aegis
talks to it using only the standard library.

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
| **hybrid, text + rules** | 5-fold **grouped by template** | 1.00 | 0.96 | **0.98** | 0.00 | 0.00 | 0 / 2 |

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
   The **hybrid** (`use_rules=True`) recovers most of that gap: it keeps the
   model's call unless it says "legit" while **two or more independent text
   red flags** fire, in which case it trusts the rules. On the same grouped
   split that lifts recall to 0.96 and **F1 to 0.98 with zero false alarms**
   (0/2), because the held-out families it missed — urgent billing threats,
   macro lures, wire-fraud secrecy — each trip several text flags at once. The
   threshold of two is deliberate: single flags also appear on genuine urgent
   or billing mail, so requiring two keeps precision at 1.00. Crucially these
   are **text** flags (subject + body), not the authentication-header signal
   below, so the lift is honest and not a repeat of the corpus artifact.
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
   flags (authentication failure, Reply-To mismatch, **lookalike sender domain**,
   risky attachment type, urgency, credential or PIN request, macro lure,
   payment-detail change, secrecy), matching the categories in the corpus
   answer key. The lookalike check flags digit-for-letter fakes such as
   `paypa1` or `amaz0n` while leaving real domains with numbers (`office365`,
   `s3`) alone; it helps most on the 500-email corpus's Hard split and does not
   change the 100-email numbers above (whose domains use no such tricks).

## Honest limitations

- 100 emails and 36 templates is small; confidence intervals are wide.
- The red-flag rules were written while reading this corpus, so their score
  is a development measurement, not a held-out result.
- The scikit-learn backend has **not** been run in the build sandbox (no
  package downloads there). It is covered by tests that skip without
  scikit-learn. Run it on your machine to get those numbers.
- The classifier is not part of the frozen agent benchmark, so the published
  Aegis benchmark numbers are unchanged. `ClassifierDetector` lets you plug it
  into the gateway as a risk signal, which (like any detector) can only
  escalate a decision, never permit a denied action.

## A larger, harder corpus (500 emails)

A second evaluation set of **500 synthetic emails** (325 phishing / 140 legit /
35 spam, graded Easy/Medium/Hard) is available. Build it with
`python scripts/build_corpus_500.py` and evaluate with
`python scripts/eval_email_classifier.py --corpus aegis/data/email_corpus_500.json`.
Its Hard split (lookalike domains, conversation hijacking, low-urgency BEC,
hard-negative legitimate mail) is where a classifier and a real model diverge
most. See [docs/corpus_500.md](corpus_500.md).
