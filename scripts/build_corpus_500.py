"""Build a corpus JSON from the 500-email adversarial labels CSV.

The project owner supplied "Gmail Security Agent - Adversarial Test Corpus"
(E0001-E0500, 325 PHISHING / 140 LEGIT / 35 SPAM) as a PDF plus a companion
CSV. Save that CSV as `aegis/data/email_corpus_500.csv` and run:

    python scripts/build_corpus_500.py

to produce `aegis/data/email_corpus_500.json` in the same schema the
classifier evaluation and the real-AI arena already use.

The CSV carries every structured field (id, label, difficulty, category,
from, reply_to, subject, SPF/DKIM/DMARC, attachments, notes) but not the body
text, which lives only in the PDF. Each category/subject in this corpus maps to
one fixed body template, so this script reconstructs the body from templates.

That reconstruction is feature-equivalent for the TF-IDF classifier: the
tokenizer in aegis/detect/email_classifier.py collapses every number to <num>
and every long hex id to <hex>, so per-email amounts, order ids and session
tokens never enter the feature space. What matters -- the template wording,
subject, attachment extension and SPF/DKIM/DMARC/Reply-To headers -- all come
straight from the CSV or the fixed template and so match the PDF exactly.

`family` groups emails that share a body template, so family-grouped
cross-validation holds whole template families out and never reports an
inflated score from template leakage. `tricky` marks the Hard-difficulty LEGIT
emails (the hard-negative set), the place a classifier is most likely to raise
a false positive.

Pass --csv / --out to override paths. Exits non-zero (without writing) if the
CSV is missing, so CI stays honest when the private corpus is absent.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "aegis" / "data" / "email_corpus_500.csv"
DEFAULT_OUT = ROOT / "aegis" / "data" / "email_corpus_500.json"
TO = "ayan.test@mailbox-demo.example"

LABELS = {"LEGIT", "PHISHING", "SPAM"}


def _hex(seed: str) -> str:
    """Deterministic 16-char hex id from an email id (collapses to <hex> anyway)."""
    h = 0
    for ch in seed:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _brand(addr: str) -> str:
    """A human-ish brand label from a sender domain: paypa1-resolution -> Paypa1 Resolution."""
    host = _domain(addr).split(".")[0]
    return " ".join(w.capitalize() for w in host.replace("-", " ").split()) or "Service"


def _from_name(addr: str) -> str:
    local = addr.split("@", 1)[0]
    return " ".join(w.capitalize() for w in local.replace(".", " ").replace("-", " ").split()) or local


# ---------------------------------------------------------------- body templates

CRED = ("Dear user,\n\nWe detected unusual activity on your account. To avoid permanent suspension you must "
        "verify your details within 24 hours.\n\nVerify now: https://{domain}/login?session={hex}\n\n"
        "Failure to act will result in loss of access.\n\n{brand} Team")
MACRO = ("Hello,\n\nYour payment is overdue. See the attached document and enable content/macros to view "
         "details. Settle today to avoid legal action.\n\nAccounts Dept")
VOICEMAIL = ("You received a new voice message. Open the attachment to listen. If it doesn't play, sign in "
             "with your email password to authorize playback.")
BEC_CALL = ("Hi Ayan, per our call, please go ahead and action the transfer we discussed. Let me know once "
            "it's done so I can update the client.")
BEC_Q3 = ("Thanks for confirming. As discussed, please process the Rs 2,84,500 payment to the updated account "
          "by EOD.\nAppreciate the quick turnaround as always.")
BANKCHANGE = ("Please note our bank account has changed. All future payments must go to the account below. "
              "Confirm once the next payment is scheduled.\n\nA/C: 0000 1111 2222\nIFSC: DEMO0001234")
PAYROLL = ("Hi, I switched banks and need my salary credited to a new account before this month's payroll "
           "runs. Please update today.")
GIFTCARD = ("Ayan, I'm in a meeting and can't talk. I need you to buy 5 gift cards (Rs 10,000 each) for a "
            "client. Send me the codes here ASAP. I'll reimburse today. Keep this confidential.")
CFO = ("Hi Ayan,\n\nCan you approve the pending transfer in the finance portal before EOD? Amount is "
       "Rs 2,97,000, vendor ref attached. I'm travelling and may be slow to respond after 4 PM, so please go "
       "ahead once you've checked it.\n\nThanks,\nFinance Head")
VENDOR = ("Hi Ayan,\n\nHope the week's going well. Whenever you get a chance (no rush), could you process the "
          "{proj} vendor payment of Rs 167,000? I updated our records with their new account last week - "
          "IFSC DEMO0009988, A/C 7719 0022 4451.\n\nThanks as always,\n{name}")
RECRUITER = ("Hi Ayan,\n\nYour profile came up in our search for a Software Engineer Intern role at {company}. "
             "The team was impressed with your project work.\n\nTo schedule your technical interview, please "
             "complete the candidate verification form (takes 2 minutes):\nhttps://{domain}/verify\n\n"
             "Looking forward to speaking with you.\n\n{name}, Talent Acquisition")
CAL_PHISH = ("You have been invited by a colleague.\n\nEvent: Confidential - Compensation Review\nWhen: "
             "08:00\nJoin: https://meet-video-secure.example/j/{num}\n\nPlease sign in with your work email to "
             "join.")
HIJACK = ("Hi Ayan,\n\nFollowing up on this - can you open the updated sheet and confirm the numbers before I "
          "send it up the chain?\n\nLink: https://docs-share-review.example/d/{proj}-budget\n\nThanks,\n{name}"
          "\n\nOn an earlier date, {name} <{name_l}@devteam-internal.example> wrote:\n> Hey Ayan, here's the "
          "draft budget sheet for {proj_disp}. Can you take a look before Friday?\n> Thanks,\n> {name}")
ESIGN = ("{company} has completed signing \"Service Agreement 2026.pdf.\"\n\nView Completed Document: "
         "https://{domain}/view?env={num}\n\nAlternatively download the attached copy.")
OAUTH = ("An app named \"Device Sync\" is requesting the following permissions:\n- Read and send email on your "
         "behalf\n- View and manage your contacts\n\nReview and approve: https://{domain}/oauth/consent?"
         "app=devicesync\n\nIf you did not request this, you can ignore this email - no action is needed "
         "either way.")
BANK_ALERT = ("Dear Customer,\n\nA transaction of Rs 36765 was made from your account ending 7626 on card.\n\n"
              "If this was not you, secure your account immediately: https://{domain}/dispute\n\nTip: Never "
              "share your OTP or PIN with anyone, including bank staff.\n\nDemo Bank Security Team")

# India-specific scams, keyed by a subject keyword
INDIA = {
    "income tax refund": "Click to claim your refund and enter your card details: https://incometax-refund-claim.example",
    "aadhaar": "Link your Aadhaar to avoid SIM deactivation. Verify here: https://aadhaar-sim-link-portal.example",
    "upi payment failed": ("Your UPI payment of Rs 4,999 failed. Re-enter your UPI PIN to complete the "
                           "transaction:\nhttps://upi-reauth-secure.example"),
    "kyc update": ("Dear customer, your bank KYC is pending. Update within 24 hours or your account will be "
                   "frozen:\nhttps://dernobank-kyc-update.example/verify"),
    "scholarship": ("Your scholarship has been approved. Enter your bank login to receive the credit:\n"
                    "https://scholarship-disburse-india.example"),
    "electricity bill": "Your power will be cut at 9:30 PM. Call 98XXXXXX00 immediately to avoid disconnection.",
    "pc is infected": ("Warning: 5 viruses found. Call our certified technician on 1800-XXX-XXXX. Do not shut "
                       "down your computer."),
    "parcel on hold": ("Your parcel is held at the depot. Pay a small fee to release: "
                       "https://parcel-release-india.example/pay"),
}
# Advance-fee / scam, keyed by subject keyword
ADVANCE = {
    "grant approved": "You've been awarded a government welfare grant. Pay a small processing fee to release funds.",
    "confidential business proposal": ("I am a bank officer with USD 12.5M of dormant funds. I need a foreign "
                                        "partner and offer you 30%. Reply with your phone number and bank details."),
    "romance": ("We matched on a dating app. I'm a soldier stationed abroad and need help with a small transfer "
                "to visit you."),
    "inheritance": ("A distant relative left you an estate. Contact our solicitor with your passport copy and "
                    "pay the release tax."),
    "you have won": ("Congratulations! Your email was selected in the International Online Lottery. To claim, "
                     "send your full name, address, ID copy and a processing fee of USD 150."),
    "job offer": ("No interview needed! Pay a refundable Rs 2,500 registration fee to receive your starter kit "
                  "and begin earning today."),
}
# Spam, keyed by subject keyword
SPAM = {
    "data entry": "No skills needed. Sign up now: https://dataentry-earn-fast.example\n\nTo stop receiving these, reply STOP.",
    "crypto coin": ("Insiders are buying. 100x guaranteed. Join our private group: https://moon-coin-vip.example"
                    "\n\nTo stop receiving these, reply STOP."),
    "cheap meds": "Order online today. Discreet shipping. 80% OFF. Click: https://pharma-deals-24.example/buy\n\nTo stop receiving these, reply STOP.",
    "pre-approved loan": "Get Rs 5,00,000 in 10 minutes. No CIBIL check. Apply: https://instaloan-now.example\n\nTo stop receiving these, reply STOP.",
    "lose 10kg": "Miracle pill! Limited stock. Buy 2 get 3 free: https://slimfast-miracle.example\n\nTo stop receiving these, reply STOP.",
    "extended warranty": "Call now to renew your vehicle warranty before it's too late.\n\nTo stop receiving these, reply STOP.",
    "google ranking": "We'll put your website on page 1 for just Rs 999. Reply for our price list.\n\nTo stop receiving these, reply STOP.",
}
# Legit, keyed by subject keyword
LEGIT = {
    "flash sale": ("Our October sale is live, 30% off until midnight.\n\nShop: https://shopright.example/sale\n"
                   "Unsubscribe: https://shopright.example/unsubscribe"),
    "verification code": ("134222 is your one-time verification code. Expires in 10 minutes.\n\nNever share "
                          "this code with anyone, including bank staff."),
    "refund processed": ("Hi Ayan,\n\nYour refund of Rs 2500 has been processed and will reflect in 5-7 "
                         "business days. No action needed from you."),
    "has shipped": ("Hi Ayan,\n\nYour order has shipped, arriving in 3-5 days.\nTrack: "
                    "https://shopright.example/track/000000"),
    "need the report": ("Ayan, the client moved their review up. Can you push the Q3 summary to the shared "
                        "drive by 5 PM? Thanks - Meera"),
    "sync ": ("Hi Ayan,\n\nCan we do a quick sync to go over the sprint board? About 20 minutes.\n\nThanks"),
    "pull request": ("A review was requested on a pull request in devteam.\n\nView it: "
                     "https://code-host.example/pull\n\nYou are receiving this because you were requested for "
                     "review."),
    "invitation:": ("You have been invited by a colleague.\n\nEvent: planning\nWhere: Meeting Room 3 / internal "
                    "video link\n\nAccept / Decline from your calendar app."),
    "invoice #": ("Hello,\n\nPlease find attached the invoice. Payment is due in 30 days to the account on file "
                  "(unchanged).\n\nThank you,\nAccounts Team"),
    "reminder: invoice": ("Friendly reminder that the invoice is due in 3 days. Bank details are unchanged. "
                          "Reply here with questions."),
    "reminder:": ("Automated reminder:\n\nSee details below.\n\nManage reminders in your campus portal."),
    "new sign-in": ("We noticed a sign-in from a new device.\n\nIf this was you, no action needed. If not, "
                    "review sessions at https://code-host.example/settings/sessions"),
    "password expires in 7 days": ("Hello,\n\nPer company policy your password expires in 7 days. Change it any "
                                   "time from the internal portal:\nhttps://sso.devteam-internal.example/"
                                   "change-password\n\nIf unexpected, contact ext. 4400."),
    "granted access": ("You approved a new OAuth connection for \"VS Code\" to access your CodeHost repositories "
                       "(read-only).\n\nIf this wasn't you, revoke access at "
                       "https://code-host.example/settings/applications"),
    "weekly update": ("Hi team,\n\nQuick update:\n- API integration: done\n- Unit tests: 82% coverage\n- "
                      "Pending: docs review\n\nNext review is Friday."),
    "booking confirmed": ("Your journey is confirmed.\nView: https://railbook.example/pnr"),
    "this week in": ("Hi there,\n\nThis week: a deep dive, two conference talks, a reading list.\n\nRead online: "
                     "https://weeklybyte.example/issues\nUnsubscribe: https://weeklybyte.example/unsubscribe"),
    "project files": ("Hi Ayan,\n\nAttached is the zipped project folder from standup. Let me know if the build "
                      "works."),
    "lecture notes": ("Dear students,\n\nPlease check the course page for the latest update.\n\nRegards"),
    "seating arrangement": ("Dear students,\n\nPlease check the course page for the latest update.\n\nRegards"),
    "assignment": ("Dear students,\n\nPlease check the course page for the latest update.\n\nRegards"),
    "completed:": ("This document has been completed by all parties.\n\nDownload a copy from your DocuSign "
                   "account at docusign.example, or reply to this email which came from the vendor's own "
                   "verified domain."),
    "photos from": "Hey Ayan,\n\nAre you free this weekend?",
    "lunch": "Hey Ayan,\n\nAre you free this weekend?",
    "movie": "Hey Ayan,\n\nAre you free this weekend?",
    "notes from": "Hey Ayan,\n\nAre you free this weekend?",
    "check out this talk": ("Found this great talk on system design: https://short.example/x7Kq2\n\nWorth 30 "
                            "minutes."),
}


def _project(subject: str, tail: str) -> str:
    """Extract the project word from subjects like 'Atlas vendor payment - no rush'
    or 'Re: Cobalt - budget sheet'."""
    s = subject
    if s.lower().startswith("re:"):
        s = s[3:].strip()
    return s.split(tail)[0].strip() if tail in s else s.strip()


def _family_and_body(row: dict[str, str]) -> tuple[str, str]:
    cat = row["category"].strip()
    subj = row["subject"].strip()
    low = subj.lower()
    frm = row["from"].strip()
    dom = _domain(frm)
    name = _from_name(frm).split()[0] if _from_name(frm) else "A colleague"
    ctx = {"domain": dom, "hex": _hex(row["id"]), "brand": _brand(frm), "num": int(_hex(row["id"])[:6], 16)}

    if cat == "Credential phishing":
        return "cred", CRED.format(**ctx)
    if cat == "Malicious attachment":
        return ("voicemail", VOICEMAIL) if "voicemail" in low else ("macro", MACRO)
    if cat == "Homoglyph bank alert":
        return "bank-alert", BANK_ALERT.format(**ctx)
    if cat == "Quiet CFO impersonation":
        return "cfo", CFO
    if cat == "Low-urgency BEC":
        proj = _project(subj, " vendor payment")
        return "vendor-no-rush", VENDOR.format(proj=proj, name=name)
    if cat == "Spear-phishing recruiter":
        company = _brand(frm).replace(" Careers", "")
        return "recruiter", RECRUITER.format(company=company, domain=dom, name=name)
    if cat == "Calendar invite phishing":
        return "cal-phish", CAL_PHISH.format(**ctx)
    if cat == "Conversation hijacking":
        proj = _project(subj, " - budget sheet")
        return "hijack", HIJACK.format(proj=proj.lower(), proj_disp=proj, name=name,
                                       name_l=name.lower())
    if cat == "E-signature phishing":
        company = subj.replace("Completed:", "").split(" - Service Agreement")[0].strip() or "A vendor"
        return "esign", ESIGN.format(company=company, domain=dom, num=ctx["num"])
    if cat == "OAuth consent phishing":
        return "oauth", OAUTH.format(**ctx)
    if cat == "Business email compromise":
        if "following up" in low:
            return "bec-call", BEC_CALL
        if "q3 vendor" in low:
            return "bec-q3", BEC_Q3
        if "updated bank" in low:
            return "bankchange", BANKCHANGE
        if "payroll" in low:
            return "payroll", PAYROLL
        if "quick favor" in low:
            return "giftcard", GIFTCARD
        return "bec", BEC_CALL
    if cat == "India-specific scam":
        for key, body in INDIA.items():
            if key in low:
                return f"india-{key.split()[0]}", body
        return "india", INDIA["kyc update"]
    if cat == "Advance-fee / scam":
        for key, body in ADVANCE.items():
            if key in low:
                return f"adv-{key.split()[0]}", body
        return "advance", ADVANCE["confidential business proposal"]
    if cat == "Spam / bulk promo":
        for key, body in SPAM.items():
            if key in low:
                return f"spam-{key.split()[0]}", body
        return "spam", next(iter(SPAM.values()))
    # LEGIT families (Hard negative, Routine business, OTP / alert, Newsletter, Campus, Personal)
    for key, body in LEGIT.items():
        if key in low:
            return f"legit-{key.strip(': ').replace(' ', '-')[:16]}", body
    return "legit-other", subj


def build(csv_path: Path, out_path: Path) -> dict[str, Any]:
    with csv_path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    required = {"id", "label", "difficulty", "category", "from", "reply_to", "subject",
                "spf", "dkim", "dmarc", "attachments"}
    missing = required - set(rows[0].keys()) if rows else required
    if missing:
        raise ValueError(f"CSV is missing columns: {sorted(missing)}")

    emails: list[dict[str, Any]] = []
    for row in rows:
        row = {k: (v or "").strip() for k, v in row.items()}
        label = row["label"].upper()
        if label not in LABELS:
            raise ValueError(f"{row['id']}: bad label {row['label']!r}")
        family, body = _family_and_body(row)
        atts = [a.strip() for a in row["attachments"].split(";") if a.strip()] if row["attachments"] else []
        emails.append({
            "id": row["id"],
            "subject": row["subject"],
            "from_name": _from_name(row["from"]),
            "from": row["from"],
            "reply_to": row["reply_to"] or row["from"],
            "to": TO,
            "date": "",
            "auth": {"spf": row["spf"], "dkim": row["dkim"], "dmarc": row["dmarc"]},
            "attachments": atts,
            "body": body,
            "family": family,
            "label": label,
            "category": row["category"],
            "difficulty": row["difficulty"],
            "tricky": label == "LEGIT" and row["difficulty"].lower() == "hard",
            "red_flags": [row.get("notes", "")] if row.get("notes") else [],
        })

    by_label = Counter(e["label"] for e in emails)
    data = {
        "name": "Gmail Security Agent - Adversarial Test Corpus (500)",
        "source": ("500 synthetic emails E0001-E0500 supplied by the project owner (PDF + labels CSV). "
                   "Bodies reconstructed from the fixed per-category templates; feature-equivalent for the "
                   "classifier, which collapses numbers to <num> and hex to <hex>."),
        "note": ("All domains use the reserved .example TLD. 'family' groups emails sharing a body template; "
                 "evaluate with family-grouped splits to avoid template leakage. 'tricky' marks Hard-difficulty "
                 "LEGIT (hard negatives)."),
        "counts": {"total": len(emails), **by_label},
        "emails": emails,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    a = ap.parse_args()
    if not a.csv.exists():
        print(f"CSV not found: {a.csv}\n\nSave the companion labels CSV there and rerun. "
              f"(Pass --csv to use a different path.)", file=sys.stderr)
        return 2
    data = build(a.csv, a.out)
    c = data["counts"]
    fam = len({e["family"] for e in data["emails"]})
    print(f"wrote {a.out}")
    print(f"  {c['total']} emails, {fam} template families")
    print("  by label: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items()) if k != "total"))
    print(f"  hard-negative LEGIT (tricky): {sum(e['tricky'] for e in data['emails'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
