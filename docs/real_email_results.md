# Email classifier on real email

The synthetic corpora in this repository show how the classifier is built and
scored. This page shows how it does on **real email**.

## Data

The public Kaggle dataset
[phishing-email-dataset-nazario-5-and-trec07](https://www.kaggle.com/datasets/rohansood98/phishing-email-dataset-nazario-5-and-trec07):

| Source | Emails (after removing exact duplicates) | Content |
|---|---|---|
| Nazario_5 | 3,063 | Real phishing (Nazario corpus) and real legitimate business email (Enron) |
| TREC 2007 | 53,648 | Real spam and real legitimate email from the TREC 2007 public spam track |

The emails are real, so they are **not committed** to this repository.
`scripts/eval_real_emails.py` reads them from the local download.

## Method

- Each source is shuffled with a fixed seed and split 70% train / 30% test.
  Every number below is on the **test** emails, which the model never saw.
- The legit half of Nazario_5 is Enron mail. Email addresses and Enron-specific
  words (`enron`, `ect`, `hou`, `corp`) are masked, so the model can't score
  well just by learning "mentions Enron means legit". Masking moved F1 by less
  than half a point, so the model was not leaning on that shortcut.
- No SPF/DKIM/DMARC headers are used, so the authentication-header artifact of
  the synthetic corpus plays no part.
- Backend: scikit-learn TF-IDF + logistic regression, words seen in fewer than
  two training emails dropped. One run took 69 seconds on a laptop.

## Results

| Model | Real phishing (Nazario, 919 test emails) | Real spam (TREC, 16,095 test emails) |
|---|---|---|
| Trained on 100 synthetic emails only | 75.2% stopped, 29.5% false alarms, F1 0.740 | 26.0% stopped, 13.9% false alarms, F1 0.380 |
| **Trained on real email** | **97.7% stopped (461/472), 4.9% false alarms (22/447), F1 0.965** | **99.7% stopped (8,995/9,026), 1.0% false alarms (69/7,069), F1 0.994** |

Cross-source transfer (train on one source, test on the other):

| Trained on | Tested on | Result |
|---|---|---|
| TREC spam only | Nazario phishing | 98.9% stopped, but 39.4% false alarms |
| Nazario phishing only | TREC spam | 13.1% stopped, 0.7% false alarms |

## What this shows

1. **Synthetic training does not transfer to real email.** The model trained
   on 100 synthetic emails missed 74% of real spam. Real training data is what
   makes the classifier useful.
2. **Phishing and spam are different problems.** A model trained on one does
   badly on the other, so both kinds of training data are needed.
3. **False alarms on legitimate business email are the number to watch.**
   4.9% of real Enron business emails were flagged. That is the main thing to
   improve before relying on the classifier for filtering.
4. **The TREC figure is probably a little optimistic.** Exact duplicates were
   removed, but TREC contains many near-identical spam campaigns, and the split
   is random rather than grouped by campaign. The Nazario figure is the more
   conservative one.

The classifier is an advisory signal. In Aegis it can only make a decision
stricter; the deterministic policy gateway, not the classifier, is what stops
an agent from leaking data.

## Reproduce

```bash
pip install kagglehub scikit-learn
python -c "import kagglehub; print(kagglehub.dataset_download('rohansood98/phishing-email-dataset-nazario-5-and-trec07'))"
python scripts/eval_real_emails.py
```
