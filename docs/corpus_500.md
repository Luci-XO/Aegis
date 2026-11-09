# 500-email adversarial corpus

A second, larger evaluation set: **500 synthetic emails (E0001–E0500)** supplied
by the project owner as a PDF plus a companion labels CSV. Every address and
link uses the reserved `.example` TLD, so nothing here resolves or reaches a
real person.

| | |
|---|---|
| Size | 500 emails |
| By label | PHISHING 325, LEGIT 140, SPAM 35 |
| By difficulty | Hard 161, Medium 204, Easy 135 |
| Hard adversarial techniques | lookalike/homoglyph domains, conversation hijacking off a fabricated prior thread, low-urgency BEC, quiet CFO impersonation, OAuth-consent and e-signature clones, calendar-invite phishing |

This complements the built-in 100-email corpus. Its value for a demo is the
**Hard** split: hard-negative legitimate email (marketing, internal notices,
security alerts that are genuinely benign) and hard adversarial phishing that
reads clean. That gap — false positives on hard negatives, recall on hard
phishing — is where a classifier and a real model such as Gemini differ most.

## Why this isn't committed in full

The labels CSV and the corpus JSON built from it are **git-ignored** (see
`.gitignore`); only `aegis/data/email_corpus_500.sample.csv` (the first 30
rows) is committed, so the format and the build are visible and tested in CI
without shipping a 500-row generated file. Regenerate the full corpus locally
from your copy of the CSV.

## Build it

1. Save the companion labels CSV as `aegis/data/email_corpus_500.csv`.
2. Build the corpus JSON:

   ```bash
   python scripts/build_corpus_500.py
   # wrote aegis/data/email_corpus_500.json
   #   500 emails, N template families
   #   by label: LEGIT=140, PHISHING=325, SPAM=35
   #   hard-negative LEGIT (tricky): ...
   ```

### Bodies are reconstructed, and that is honest

The CSV carries every structured field (id, label, difficulty, category,
sender, Reply-To, subject, SPF/DKIM/DMARC, attachments, notes) but **not** the
body text, which lives only in the PDF. Each category/subject in this corpus
maps to one fixed body template, so `build_corpus_500.py` reconstructs the body
from those templates.

This is **feature-equivalent** for the TF-IDF classifier: its tokenizer
collapses every number to `<num>` and every long hex id to `<hex>`, so
per-email amounts, order numbers and session tokens never enter the feature
space. What does matter — the template wording, the subject, the attachment
extension, and the SPF/DKIM/DMARC and Reply-To headers — comes straight from
the CSV or the fixed template and matches the PDF exactly. The reconstruction
is noted in the corpus JSON's `source` field so the provenance is never hidden.

## Evaluate the classifier on it

```bash
python scripts/eval_email_classifier.py --corpus aegis/data/email_corpus_500.json
# add --backend sklearn to use scikit-learn, --llm --delay 4 to add a Gemini judge
```

Read the **5-fold grouped-by-template** row as the honest number for the
learned model: whole template families are held out, so the model is scored on
templates it never trained on. The random-CV row leaks near-duplicate
templates across folds and reads higher; it is shown only as a contrast. Watch
`FPR tricky` (false positives on the Hard-negative legitimate set) — the
single most informative column on this corpus.

## Head-to-head scoreboard: your AI vs Gemini

One command, the whole corpus, one table — how many attacks each system
**stopped**, how many **got through**, and how many legit emails each one
false-alarmed on:

```bash
python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json            # your AI only (offline)
python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json --llm --batch 25 --delay 4 --json results/scoreboard.json
```

Add `--json results/scoreboard.json` and the dashboard shows it live: start
`python -m aegis.web`, open http://127.0.0.1:8000, and click **Scoreboard** for
an animated your-AI-vs-Gemini view (stopped / got through / hard phishing /
false alarms / accuracy). The CLI also prints an Easy/Medium/Hard breakdown of
attacks stopped.

```
                                   Your AI (sklearn)  Gemini (gemini-3.6-flash)
ATTACKS (phishing + spam)
  stopped by the filter                 ... / 360          ... / 360
  GOT THROUGH (missed)                  ... / 360          ... / 360
  of those, Hard phishing caught        ... / 161          ... / 161
LEGITIMATE email
  kept (correct)                        ... / 140          ... / 140
  false alarms                          ... / 140          ... / 140
OVERALL accuracy                            ...%               ...%
```

"Your AI" is the Aegis classifier scored with 5-fold grouped-by-template
cross-validation (tested only on templates it never trained on — its honest
number). Gemini is zero-shot. With `--llm`, Gemini classifies the corpus in
**batches of `--batch` emails per call**, so 500 emails is about 20 calls, not
500 — fast and under free-tier limits. An answer the model fails to return is
counted as *flagged*, never as safe.

Gemini calls and `pip install` only work on your own machine — this build
sandbox has no outbound network — so run the `--llm` step locally and send back
the result table or a screenshot.
