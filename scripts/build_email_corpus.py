"""Build aegis/data/email_corpus.json from the "Gmail Security Agent - Test Corpus".

Transcribed from the 100-email PDF supplied by the project owner (E001-E100,
answer key in its appendix). All addresses use the reserved .example TLD.

Many emails in the corpus share an identical body template (for example 14
credential-phishing emails differ only in brand, domain and session id). Each
email records its template "family" so evaluation can keep near-duplicates
together on one side of a train/test split. Splitting them randomly would let
a classifier memorise the template and report an inflated score.

Run: python scripts/build_email_corpus.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "aegis" / "data" / "email_corpus.json"
TO = "ayan.test@mailbox-demo.example"
AUTH = {
    "P": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    "F": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    "N": {"spf": "fail", "dkim": "none", "dmarc": "none"},
    "S": {"spf": "softfail", "dkim": "fail", "dmarc": "fail"},
}

# ---------------------------------------------------------------- templates

def PR(repo, n):
    return (f"A new review was requested on pull request #{n} in devteam/{repo}.\n"
            f"View it on CodeHost: https://code-host.example/{repo}/pull/{n}\n"
            "You are receiving this because you were requested for review.")


def CRED(domain, session, team):
    return ("Dear user,\nWe detected unusual activity on your account. To avoid permanent suspension you "
            "must verify your details within 24 hours.\n"
            f"Verify now: https://{domain}/login?session={session}\n"
            f"Failure to act will result in loss of access.\n{team} Team")


UTIL = "Your power will be cut at 9:30 PM. Call 98XXXXXX00 immediately to avoid disconnection."


def FRIEND(name):
    return ("Hey Ayan,\nAre you free this weekend? Thinking of grabbing food near campus and going over "
            f"the DSA notes.\n{name}")


MACRO = ("Hello,\nYour payment is overdue. Please see the attached document and enable content/macros to "
         "view the details. Settle today to avoid legal action.\nRegards,\nAccounts Dept")
PHARMA = ("Order online today. Discreet shipping. 80% OFF. Click: https://pharma-deals-24.example/buy\n"
          "To stop receiving these, reply STOP.")
LOAN = ("Get Rs 5,00,000 in 10 minutes. No CIBIL check. Apply: https://instaloan-now.example\n"
        "To stop receiving these, reply STOP.")


def SHIP(item, order):
    return (f"Hi Ayan,\nYour {item} has shipped and should arrive in 3-5 days.\nOrder #{order}\n"
            f"Track: https://shopright.example/track/{order}\nThanks for shopping with us.")


def PROJ(name, proj):
    return (f"Hi team,\nQuick update on Project {proj}:\n- API integration: done\n- Unit tests: 82% coverage\n"
            f"- Pending: docs review\nNext review is Friday. Shout if anything is blocking you.\n{name}")


def SYNC(time, board, name):
    return (f"Hi Ayan,\nCan we do a quick sync tomorrow at {time} to go over the {board} sprint board? "
            f"About 20 minutes.\nThanks,\n{name}")


def OTP(code):
    return (f"{code} is your one-time verification code. It expires in 10 minutes.\n"
            "Never share this code with anyone, including bank staff. We will never call to ask for it.")


PWD7 = ("Hello,\nPer company policy your password expires in 7 days. Change it any time from the internal "
        "portal:\nhttps://sso.devteam-internal.example/change-password\n"
        "If you did not expect this email, contact the helpdesk on ext. 4400.")
KYC = ("Dear customer, your bank KYC is pending. Update within 24 hours or your account will be frozen:\n"
       "https://demobank-kyc-update.example/verify")


def FACULTY(prof):
    return ("Dear students,\nPlease check the course page for the latest update. The submission window is "
            f"extended by two days.\nRegards,\n{prof}")


PAYROLL = ("Hi, I changed banks and need my salary credited to a new account before this month's payroll. "
           "Please update today. Details attached.")
BANKCHANGE = ("Please note our bank account has changed. All future payments must go to the new account below. "
              "Kindly confirm once the next payment is scheduled.\nA/C: 0000 1111 2222\nIFSC: DEMO0001234")


def PNR(pnr, date):
    return (f"Your journey is confirmed.\nPNR: {pnr}\nDate: {date}\n"
            f"View ticket: https://railbook.example/pnr/{pnr}")


def NEWS(topic, issue):
    return (f"Hi there,\nThis week: a deep dive on {topic}, two conference talk recordings, and a reading list.\n"
            f"Read online: https://weeklybyte.example/issues/{issue}\n"
            "You subscribed at weeklybyte.example. Unsubscribe: https://weeklybyte.example/unsubscribe")


def INVOICE(n, team):
    return (f"Hello,\nPlease find attached invoice #{n} for October services. Payment is due in 30 days to the "
            "account on file (unchanged from previous invoices).\nThank you for your business.\n"
            f"{team} Accounts Team")


VOICEMAIL = ("You received a new voice message. Open the attachment to listen. If it does not play, sign in "
             "with your email password to authorize playback.")
LOTTERY = ("Congratulations! Your email was selected in the International Online Lottery. To claim, send your "
           "full name, address, ID copy and a processing fee of USD 150.")
ADVFEE = ("I am a bank officer with USD 12.5M of dormant funds. I need a foreign partner and offer you 30%. "
          "Reply with your phone number and bank details.")
SIGNIN = ("We noticed a sign-in to your account from a new device.\nIf this was you, no action is needed. "
          "If not, review your sessions at https://code-host.example/settings/sessions")


def REMINDER(event, date):
    return (f"This is an automated reminder:\n{event}\nDate: {date}\n"
            "Manage reminders in your campus portal settings.")


def ZIPFILES(name):
    return ("Hi Ayan,\nAttached is the zipped project folder we discussed in standup. Let me know if the "
            f"build works on your side.\n{name}")


# ---------------------------------------------------------------- answer key flags

F_CRED = "Lookalike domain; urgency + threat; Reply-To mismatch; SPF/DMARC fail; generic greeting"
F_UTIL = "Utility scam; phone callback"
F_KYC = "Fake KYC; urgency; lookalike domain"
F_PAYROLL = "Payroll diversion; urgency; free-mail sender"
F_BANK = "Vendor bank-detail change; no verification channel"
F_VM = "HTML attachment; credential request inside; unknown sender"
F_LOTTO = "Lottery scam; fee request; PII harvesting"
F_ADV = "Advance-fee fraud; PII harvesting"
F_NORMAL = "Normal, expected sender/context"


def F_MACRO(ext):
    return f"Risky attachment type ({ext}); macro/enable-content lure; unknown sender; pressure"


def F_SPAM(kind):
    return f"{kind} spam; no sender legitimacy; unsolicited"


C_CRED, C_INDIA, C_ATT, C_BEC, C_ADV, C_SPAM = (
    "Credential phishing", "India-specific scam", "Malicious attachment / fake invoice",
    "Business email compromise (BEC)", "Advance-fee / scam", "Spam / bulk promo")
C_VM = "Malicious attachment / fake voicemail"
L, PH, SP = "LEGIT", "PHISHING", "SPAM"

CH = ("CodeHost Notifications", "notifications@code-host.example")
SHOP = ("ShopRight", "orders@shopright.example")
BANK = ("Demo Bank Alerts", "alerts@demobank.example")
RAIL = ("RailBook", "tickets@railbook.example")
BYTE = ("The Weekly Byte", "hello@weeklybyte.example")
CAL = ("Campus Calendar", "calendar@usict-campus.example")
HELP = ("IT Helpdesk", "helpdesk@devteam-internal.example")
MH, SN = "support-desk@mail-helper.example", "support-desk@secure-notify.example"
CEOP, MJW = "ceo.private@secure-mailer.example", "m.joshi.work@secure-mailer.example"

# (id, subject, (from_name, from_addr), reply_to or None (= same as from), date,
#  auth code, attachments, body, family, label, category, red_flags)
E = [
    ("E001", "[cobalt] Pull request #444: fix pagination bug", CH, None, "Thu, 01 Oct 2026 18:51 +0530", "P", [], PR("cobalt", 444), "pr", L, "Legitimate", F_NORMAL),
    ("E002", "Password expires today - keep your access", ("Netflix Billing", "no-reply@netflix-billing-update.example"), SN, "Fri, 02 Oct 2026 03:32 +0530", "F", [], CRED("netflix-billing-update.example", "2492e46f4a919478", "Netflix Billing"), "cred", PH, C_CRED, F_CRED),
    ("E003", "Electricity bill unpaid - disconnection tonight", ("Power Supply Alert", "notice@secure-alerts-in.example"), None, "Fri, 02 Oct 2026 08:23 +0530", "F", [], UTIL, "util", PH, C_INDIA, F_UTIL),
    ("E004", "Photos from the trip", ("Isha Reddy", "isha.reddy@mailbox-demo.example"), None, "Fri, 02 Oct 2026 17:13 +0530", "P", [], FRIEND("Isha"), "friend", L, "Legitimate", F_NORMAL),
    ("E005", "Payment confirmation #31475", ("Remittance Advice", "accounts@remit-advice-center.example"), None, "Fri, 02 Oct 2026 23:17 +0530", "S", ["Invoice_31475.xlsm"], MACRO, "macro", PH, C_ATT, F_MACRO(".xlsm")),
    ("E006", "Cheap meds, no prescription!!!", ("Special Offers", "deals@mega-promos.example"), None, "Sat, 03 Oct 2026 14:06 +0530", "N", [], PHARMA, "pharma", SP, C_SPAM, F_SPAM("Pharma")),
    ("E007", "[falcon] Pull request #169: fix pagination bug", CH, None, "Sat, 03 Oct 2026 18:52 +0530", "P", [], PR("falcon", 169), "pr", L, "Legitimate", F_NORMAL),
    ("E008", "Your order #602467 has shipped", SHOP, None, "Sat, 03 Oct 2026 19:59 +0530", "P", [], SHIP("USB-C hub", 602467), "ship", L, "Legitimate", F_NORMAL),
    ("E009", "We could not process your last payment", ("Amazon Orders", "no-reply@amazon-order-help.example"), MH, "Sun, 04 Oct 2026 07:28 +0530", "F", [], CRED("amazon-order-help.example", "ab1f277ca7f46d3e", "Amazon Orders"), "cred", PH, C_CRED, F_CRED),
    ("E010", "Pre-approved loan - no documents needed", ("Special Offers", "deals@hot-deals.example"), None, "Sun, 04 Oct 2026 16:19 +0530", "N", [], LOAN, "loan", SP, C_SPAM, F_SPAM("Loan")),
    ("E011", "Project files as discussed", ("Neha Kapoor", "neha.kapoor@devteam-internal.example"), None, "Sun, 04 Oct 2026 19:05 +0530", "P", ["project_files.zip"], ZIPFILES("Neha"), "zipfiles", L, "Legit - Tricky (zip attachment)", "Legit: known sender, context match, auth pass"),
    ("E012", "Sync tomorrow at 16:30?", ("Rahul Verma", "rahul.verma@devteam-internal.example"), None, "Sun, 04 Oct 2026 19:57 +0530", "P", [], SYNC("16:30", "Echo", "Rahul"), "sync", L, "Legitimate", F_NORMAL),
    ("E013", "Cheap meds, no prescription!!!", ("Special Offers", "deals@hot-deals.example"), None, "Mon, 05 Oct 2026 04:39 +0530", "N", [], PHARMA, "pharma", SP, C_SPAM, F_SPAM("Pharma")),
    ("E014", "Your verification code", BANK, None, "Mon, 05 Oct 2026 18:57 +0530", "P", [], OTP(703472), "otp", L, "Legitimate - OTP", F_NORMAL),
    ("E015", "Password expires in 7 days", HELP, None, "Tue, 06 Oct 2026 01:41 +0530", "P", [], PWD7, "pwd7", L, "Legit - Tricky (urgent tone)", "Legit: internal domain, auth pass, no threats"),
    ("E016", "Password expires today - keep your access", ("Google Security", "no-reply@accounts-google-verify.example"), MH, "Tue, 06 Oct 2026 06:30 +0530", "F", [], CRED("accounts-google-verify.example", "b1273dba2e6fa438", "Google Security"), "cred", PH, C_CRED, F_CRED),
    ("E017", "Electricity bill unpaid - disconnection tonight", ("Courier Desk", "pay@quickservice-mail.example"), None, "Tue, 06 Oct 2026 21:16 +0530", "F", [], UTIL, "util", PH, C_INDIA, F_UTIL),
    ("E018", "Action required: verify your identity within 24 hours", ("Microsoft 365 Support", "no-reply@microsoft365-login-secure.example"), MH, "Wed, 07 Oct 2026 10:39 +0530", "F", [], CRED("microsoft365-login-secure.example", "2a4c48a7414a4d88", "Microsoft 365 Support"), "cred", PH, C_CRED, F_CRED),
    ("E019", "We could not process your last payment", ("LinkedIn Security", "no-reply@linkedin-verifyid.example"), MH, "Wed, 07 Oct 2026 19:06 +0530", "F", [], CRED("linkedin-verifyid.example", "b0860abab438f634", "LinkedIn Security"), "cred", PH, C_CRED, F_CRED),
    ("E020", "Lunch Saturday?", ("Rahul Verma", "rahul.verma@mailbox-demo.example"), None, "Wed, 07 Oct 2026 22:59 +0530", "P", [], FRIEND("Rahul"), "friend", L, "Legitimate", F_NORMAL),
    ("E021", "KYC update required - account will be blocked", ("Payments Team", "pay@secure-alerts-in.example"), None, "Thu, 08 Oct 2026 05:45 +0530", "F", [], KYC, "kyc", PH, C_INDIA, F_KYC),
    ("E022", "Mid-term seating arrangement", ("Prof. R. Khanna", "faculty@usict-campus.example"), None, "Thu, 08 Oct 2026 10:55 +0530", "P", [], FACULTY("Prof. R. Khanna"), "faculty", L, "Legitimate", F_NORMAL),
    ("E023", "Your verification code", BANK, None, "Thu, 08 Oct 2026 20:09 +0530", "P", [], OTP(887507), "otp", L, "Legitimate - OTP", F_NORMAL),
    ("E024", "Job offer - Work from home, Rs 50,000/week", ("Mr. Daniel Okoro", "daniel.okoro@mailbox-free.example"), None, "Fri, 09 Oct 2026 11:01 +0530", "N", [], "No interview needed! Pay a refundable Rs 2,500 registration fee to receive your starter kit and begin earning today.", "E024", PH, C_ADV, "Fake job; upfront fee"),
    ("E025", "Payroll direct deposit update", ("Meera Joshi", "director.desk@mailbox-free.example"), CEOP, "Sat, 10 Oct 2026 00:00 +0530", "F", ["details.pdf"], PAYROLL, "payroll", PH, C_BEC, F_PAYROLL),
    ("E026", "Booking confirmed - PNR KDA6RL", RAIL, None, "Sat, 10 Oct 2026 07:19 +0530", "P", ["ticket_KDA6RL.pdf"], PNR("KDA6RL", "18 Oct 2026"), "pnr", L, "Legitimate", F_NORMAL),
    ("E027", "This week in Open Source: 5 links worth your time", BYTE, None, "Sat, 10 Oct 2026 13:00 +0530", "P", [], NEWS("Open Source", 207), "news", L, "Legitimate - Newsletter", F_NORMAL),
    ("E028", "[echo] Pull request #330: fix pagination bug", CH, None, "Sat, 10 Oct 2026 17:13 +0530", "P", [], PR("echo", 330), "pr", L, "Legitimate", F_NORMAL),
    ("E029", "Payroll direct deposit update", ("Director Office", "ceo.office@mailbox-free.example"), CEOP, "Sun, 11 Oct 2026 03:38 +0530", "F", ["details.pdf"], PAYROLL, "payroll", PH, C_BEC, F_PAYROLL),
    ("E030", "Invoice #78767 for October", ("Cloudnine Software Billing", "billing@cloudnine.example"), None, "Sun, 11 Oct 2026 05:03 +0530", "P", ["Invoice_78767.pdf"], INVOICE(78767, "Cloudnine Software"), "invoice", L, "Legitimate", F_NORMAL),
    ("E031", "Pre-approved loan - no documents needed", ("Special Offers", "deals@mega-promos.example"), None, "Sun, 11 Oct 2026 19:27 +0530", "N", [], LOAN, "loan", SP, C_SPAM, F_SPAM("Loan")),
    ("E032", "Updated bank details for payment", ("Meera Joshi", "meera.joshi@mailbox-free.example"), CEOP, "Mon, 12 Oct 2026 02:57 +0530", "F", [], BANKCHANGE, "bankchange", PH, C_BEC, F_BANK),
    ("E033", "Your order #921426 has shipped", SHOP, None, "Mon, 12 Oct 2026 04:33 +0530", "P", [], SHIP("laptop stand", 921426), "ship", L, "Legitimate", F_NORMAL),
    ("E034", "Weekly update: Project Delta-Sync", ("Rohan Das", "rohan.das@devteam-internal.example"), None, "Mon, 12 Oct 2026 17:26 +0530", "P", [], PROJ("Rohan", "Delta-Sync"), "proj", L, "Legitimate", F_NORMAL),
    ("E035", "Payment confirmation #63136", ("Remittance Advice", "accounts@invoice-portal-dept.example"), None, "Tue, 13 Oct 2026 06:15 +0530", "S", ["Invoice_63136.zip"], MACRO, "macro", PH, C_ATT, F_MACRO(".zip")),
    ("E036", "Booking confirmed - PNR DVRRH6", RAIL, None, "Tue, 13 Oct 2026 17:45 +0530", "P", ["ticket_DVRRH6.pdf"], PNR("DVRRH6", "26 Oct 2026"), "pnr", L, "Legitimate", F_NORMAL),
    ("E037", "Cheap meds, no prescription!!!", ("Special Offers", "deals@mega-promos.example"), None, "Wed, 14 Oct 2026 05:32 +0530", "N", [], PHARMA, "pharma", SP, C_SPAM, F_SPAM("Pharma")),
    ("E038", "Invoice #93586 for October", ("Greenleaf Stationers Billing", "billing@greenleaf.example"), None, "Wed, 14 Oct 2026 14:43 +0530", "P", ["Invoice_93586.pdf"], INVOICE(93586, "Greenleaf Stationers"), "invoice", L, "Legitimate", F_NORMAL),
    ("E039", "Weekly update: Project Falcon", ("Isha Reddy", "isha.reddy@devteam-internal.example"), None, "Thu, 15 Oct 2026 02:51 +0530", "P", [], PROJ("Isha", "Falcon"), "proj", L, "Legitimate", F_NORMAL),
    ("E040", "Notes from yesterday's lecture", ("Rohan Das", "rohan.das@mailbox-demo.example"), None, "Thu, 15 Oct 2026 12:26 +0530", "P", [], FRIEND("Rohan"), "friend", L, "Legitimate", F_NORMAL),
    ("E041", "Your account will be suspended", ("LinkedIn Security", "no-reply@linkedin-verifyid.example"), SN, "Fri, 16 Oct 2026 02:00 +0530", "F", [], CRED("linkedin-verifyid.example", "6f82f25b3bcf44a3", "LinkedIn Security"), "cred", PH, C_CRED, F_CRED),
    ("E042", "You have 1 new voicemail (45 sec)", ("Voice Message Service", "vm@voice-msg-delivery.example"), None, "Fri, 16 Oct 2026 07:35 +0530", "F", ["VM_playback.html"], VOICEMAIL, "voicemail", PH, C_VM, F_VM),
    ("E043", "Electricity bill unpaid - disconnection tonight", ("Tax Dept Notice", "notice@govt-notice-india.example"), None, "Fri, 16 Oct 2026 16:19 +0530", "F", [], UTIL, "util", PH, C_INDIA, F_UTIL),
    ("E044", "[atlas] Pull request #382: fix pagination bug", CH, None, "Sat, 17 Oct 2026 03:20 +0530", "P", [], PR("atlas", 382), "pr", L, "Legitimate", F_NORMAL),
    ("E045", "You have won USD 1,500,000!", ("Barrister Collins", "collins.law@quick-mails.example"), None, "Sat, 17 Oct 2026 05:22 +0530", "N", [], LOTTERY, "lottery", PH, C_ADV, F_LOTTO),
    ("E046", "Action required: verify your identity within 24 hours", ("University IT", "no-reply@usict-campus-portal-login.example"), MH, "Sat, 17 Oct 2026 14:33 +0530", "F", [], CRED("usict-campus-portal-login.example", "0646ca52286da209", "University IT"), "cred", PH, C_CRED, F_CRED),
    ("E047", "You have 1 new voicemail (32 sec)", ("Voice Message Service", "vm@voice-msg-delivery.example"), None, "Sat, 17 Oct 2026 23:57 +0530", "F", ["VM_playback.html"], VOICEMAIL, "voicemail", PH, C_VM, F_VM),
    ("E048", "Security alert: unusual sign-in to your account", ("University IT", "no-reply@usict-campus-portal-login.example"), SN, "Sun, 18 Oct 2026 10:37 +0530", "F", [], CRED("usict-campus-portal-login.example", "d7ac8968fd516104", "University IT"), "cred", PH, C_CRED, F_CRED),
    ("E049", "Mid-term seating arrangement", ("Prof. A. Banerjee", "faculty@usict-campus.example"), None, "Sun, 18 Oct 2026 16:39 +0530", "P", [], FACULTY("Prof. A. Banerjee"), "faculty", L, "Legitimate", F_NORMAL),
    ("E050", "Action required: verify your identity within 24 hours", ("Instagram Support", "no-reply@instagram-appeal-center.example"), SN, "Mon, 19 Oct 2026 01:29 +0530", "F", [], CRED("instagram-appeal-center.example", "16159e8c05948fd7", "Instagram Support"), "cred", PH, C_CRED, F_CRED),
    ("E051", "Payment confirmation #69580", ("Order Desk", "accounts@invoice-portal-dept.example"), None, "Mon, 19 Oct 2026 07:24 +0530", "S", ["Invoice_69580.zip"], MACRO, "macro", PH, C_ATT, F_MACRO(".zip")),
    ("E052", "New sign-in from Chrome on Windows", ("CodeHost Security", "security@code-host.example"), None, "Mon, 19 Oct 2026 19:10 +0530", "P", [], SIGNIN, "signin", L, "Legit - Tricky (security alert)", "Legit: own domain link, auth pass, no pressure"),
    ("E053", "Need the report by 5 PM today", ("Meera Joshi (Manager)", "meera.joshi@devteam-internal.example"), None, "Tue, 20 Oct 2026 01:27 +0530", "P", [], "Ayan, the client moved their review up. Can you push the Q3 summary to the shared drive by 5 PM today? Thanks - Meera", "E053", L, "Legit - Tricky (urgent from manager)", "Legit: internal sender, normal ask, no money/credentials"),
    ("E054", "Turn Rs 5,000 into Rs 5 lakh with this crypto coin", ("Special Offers", "deals@bulk-offers.example"), None, "Tue, 20 Oct 2026 08:05 +0530", "N", [], "Insiders are buying. 100x guaranteed. Join our private group now: https://moon-coin-vip.example\nTo stop receiving these, reply STOP.", "E054", SP, C_SPAM, F_SPAM("Crypto pump")),
    ("E055", "Booking confirmed - PNR AYMPNU", RAIL, None, "Tue, 20 Oct 2026 11:40 +0530", "P", ["ticket_AYMPNU.pdf"], PNR("AYMPNU", "21 Oct 2026"), "pnr", L, "Legitimate", F_NORMAL),
    ("E056", "Mid-term seating arrangement", ("Prof. A. Banerjee", "faculty@usict-campus.example"), None, "Tue, 20 Oct 2026 13:29 +0530", "P", [], FACULTY("Prof. A. Banerjee"), "faculty", L, "Legitimate", F_NORMAL),
    ("E057", "Your order #684529 has shipped", SHOP, None, "Tue, 20 Oct 2026 23:34 +0530", "P", [], SHIP("notebook set", 684529), "ship", L, "Legitimate", F_NORMAL),
    ("E058", "Flash sale: 30% off, ends tonight", ("ShopRight Deals", "offers@shopright.example"), None, "Wed, 21 Oct 2026 13:41 +0530", "P", [], "Our October sale is live. 30% off selected items until midnight.\nShop: https://shopright.example/sale\nUnsubscribe: https://shopright.example/unsubscribe", "E058", L, "Legit - Tricky (marketing)", "Legit marketing: real domain, unsubscribe, auth pass"),
    ("E059", "Invoice #62701 for October", ("Greenleaf Stationers Billing", "billing@greenleaf.example"), None, "Wed, 21 Oct 2026 17:09 +0530", "P", ["Invoice_62701.pdf"], INVOICE(62701, "Greenleaf Stationers"), "invoice", L, "Legitimate", F_NORMAL),
    ("E060", "Your verification code", BANK, None, "Thu, 22 Oct 2026 06:36 +0530", "P", [], OTP(401572), "otp", L, "Legitimate - OTP", F_NORMAL),
    ("E061", "Sync tomorrow at 15:00?", ("Rahul Verma", "rahul.verma@devteam-internal.example"), None, "Thu, 22 Oct 2026 11:29 +0530", "P", [], SYNC("15:00", "Echo", "Rahul"), "sync", L, "Legitimate", F_NORMAL),
    ("E062", "Sync tomorrow at 15:00?", ("Sneha Iyer", "sneha.iyer@devteam-internal.example"), None, "Thu, 22 Oct 2026 20:59 +0530", "P", [], SYNC("15:00", "Cobalt", "Sneha"), "sync", L, "Legitimate", F_NORMAL),
    ("E063", "New sign-in from Chrome on Windows", ("CodeHost Security", "security@code-host.example"), None, "Fri, 23 Oct 2026 06:22 +0530", "P", [], SIGNIN, "signin", L, "Legit - Tricky (security alert)", "Legit: own domain link, auth pass, no pressure"),
    ("E064", "Confidential business proposal", ("Claims Dept", "daniel.okoro@quick-mails.example"), None, "Fri, 23 Oct 2026 13:24 +0530", "N", [], ADVFEE, "advfee", PH, C_ADV, F_ADV),
    ("E065", "Reminder: Workshop: Intro to Docker", CAL, None, "Sat, 24 Oct 2026 00:39 +0530", "P", [], REMINDER("Workshop: Intro to Docker", "10 Oct 2026"), "reminder", L, "Legitimate", F_NORMAL),
    ("E066", "Updated bank details for payment", ("CEO Office", "ceo.office@mailbox-free.example"), MJW, "Sat, 24 Oct 2026 02:57 +0530", "F", [], BANKCHANGE, "bankchange", PH, C_BEC, F_BANK),
    ("E067", "Password expires in 7 days", HELP, None, "Sat, 24 Oct 2026 13:50 +0530", "P", [], PWD7, "pwd7", L, "Legit - Tricky (urgent tone)", "Legit: internal domain, auth pass, no threats"),
    ("E068", "Security alert: unusual sign-in to your account", ("Netflix Billing", "no-reply@netflix-billing-update.example"), MH, "Sat, 24 Oct 2026 17:59 +0530", "F", [], CRED("netflix-billing-update.example", "000befe1601f1b66", "Netflix Billing"), "cred", PH, C_CRED, F_CRED),
    ("E069", "This week in Web Performance: 5 links worth your time", BYTE, None, "Sat, 24 Oct 2026 18:58 +0530", "P", [], NEWS("Web Performance", 244), "news", L, "Legitimate - Newsletter", F_NORMAL),
    ("E070", "OVERDUE: Invoice 83315 - final notice", ("Billing", "accounts@remit-advice-center.example"), None, "Sun, 25 Oct 2026 03:22 +0530", "S", ["Invoice_83315.iso"], MACRO, "macro", PH, C_ATT, F_MACRO(".iso")),
    ("E071", "Electricity bill unpaid - disconnection tonight", ("Courier Desk", "pay@govt-notice-india.example"), None, "Sun, 25 Oct 2026 07:58 +0530", "F", [], UTIL, "util", PH, C_INDIA, F_UTIL),
    ("E072", "Remittance advice", ("Order Desk", "accounts@orderdesk-docs.example"), None, "Sun, 25 Oct 2026 12:02 +0530", "S", ["Invoice_50116.docm"], MACRO, "macro", PH, C_ATT, F_MACRO(".docm")),
    ("E073", "Weekly update: Project Falcon", ("Neha Kapoor", "neha.kapoor@devteam-internal.example"), None, "Sun, 25 Oct 2026 19:51 +0530", "P", [], PROJ("Neha", "Falcon"), "proj", L, "Legitimate", F_NORMAL),
    ("E074", "Check out this talk", ("Arjun Nair", "arjun.nair@mailbox-demo.example"), None, "Mon, 26 Oct 2026 05:01 +0530", "P", [], "Found this great talk on system design: https://short.example/x7Kq2\nWorth the 30 minutes.\nArjun", "E074", L, "Legit - Tricky (short link)", "Legit: friend, benign link (shortener is a weak signal only)"),
    ("E075", "Password expires today - keep your access", ("Google Security", "no-reply@accounts-google-verify.example"), MH, "Mon, 26 Oct 2026 14:30 +0530", "F", [], CRED("accounts-google-verify.example", "7489a1418113c3d3", "Google Security"), "cred", PH, C_CRED, F_CRED),
    ("E076", "Pre-approved loan - no documents needed", ("Special Offers", "deals@hot-deals.example"), None, "Mon, 26 Oct 2026 17:09 +0530", "N", [], LOAN, "loan", SP, C_SPAM, F_SPAM("Loan")),
    ("E077", "Updated bank details for payment", ("Meera Joshi", "meera.joshi@mailbox-free.example"), CEOP, "Tue, 27 Oct 2026 02:25 +0530", "F", [], BANKCHANGE, "bankchange", PH, C_BEC, F_BANK),
    ("E078", "Invoice #39266 for October", ("Bluepeak Hosting Billing", "billing@bluepeak.example"), None, "Tue, 27 Oct 2026 06:31 +0530", "P", ["Invoice_39266.pdf"], INVOICE(39266, "Bluepeak Hosting"), "invoice", L, "Legitimate", F_NORMAL),
    ("E079", "Confidential business proposal", ("Mr. Daniel Okoro", "claims@mailbox-free.example"), None, "Tue, 27 Oct 2026 20:31 +0530", "N", [], ADVFEE, "advfee", PH, C_ADV, F_ADV),
    ("E080", "Password expires today - keep your access", ("Amazon Orders", "no-reply@amazon-order-help.example"), MH, "Wed, 28 Oct 2026 01:38 +0530", "F", [], CRED("amazon-order-help.example", "1c35e0cc6320c609", "Amazon Orders"), "cred", PH, C_CRED, F_CRED),
    ("E081", "Your account will be suspended", ("University IT", "no-reply@usict-campus-portal-login.example"), MH, "Wed, 28 Oct 2026 15:22 +0530", "F", [], CRED("usict-campus-portal-login.example", "fd198474809f50a5", "University IT"), "cred", PH, C_CRED, F_CRED),
    ("E082", "Urgent wire transfer", ("CEO Office", "director.desk@mailbox-free.example"), MJW, "Thu, 29 Oct 2026 04:05 +0530", "F", [], "I need an urgent wire for a confidential acquisition. I'll send details shortly. Do not discuss with anyone and reply only to this email.", "E082", PH, C_BEC, "Wire fraud; secrecy; Reply-To differs"),
    ("E083", "This week in Open Source: 5 links worth your time", BYTE, None, "Thu, 29 Oct 2026 12:55 +0530", "P", [], NEWS("Open Source", 265), "news", L, "Legitimate - Newsletter", F_NORMAL),
    ("E084", "Boost your Google ranking in 24h", ("Special Offers", "deals@mega-promos.example"), None, "Thu, 29 Oct 2026 15:44 +0530", "N", [], "We'll put your website on page 1 for just Rs 999. Reply for our price list.\nTo stop receiving these, reply STOP.", "E084", SP, C_SPAM, F_SPAM("SEO")),
    ("E085", "Income Tax Refund of Rs 24,590 approved", ("Power Supply Alert", "alerts@govt-notice-india.example"), None, "Fri, 30 Oct 2026 01:46 +0530", "F", [], "Click to claim your refund and enter your card details: https://incometax-refund-claim.example", "E085", PH, C_INDIA, "Tax refund lure; card data request"),
    ("E086", "Payroll direct deposit update", ("Meera Joshi", "ceo.office@mailbox-free.example"), MJW, "Fri, 30 Oct 2026 13:50 +0530", "F", ["details.pdf"], PAYROLL, "payroll", PH, C_BEC, F_PAYROLL),
    ("E087", "KYC update required - account will be blocked", ("Customer Care", "care@govt-notice-india.example"), None, "Sat, 31 Oct 2026 04:40 +0530", "F", [], KYC, "kyc", PH, C_INDIA, F_KYC),
    ("E088", "UPI payment failed - re-authorise", ("Courier Desk", "notice@secure-alerts-in.example"), None, "Sat, 31 Oct 2026 10:43 +0530", "F", [], "Your UPI payment of Rs 4,999 failed. Re-enter your UPI PIN to complete the transaction:\nhttps://upi-reauth-secure.example", "E088", PH, C_INDIA, "Asks for UPI PIN"),
    ("E089", "Reminder: Library book return", CAL, None, "Sat, 31 Oct 2026 17:25 +0530", "P", [], REMINDER("Library book return", "07 Oct 2026"), "reminder", L, "Legitimate", F_NORMAL),
    ("E090", "Electricity bill unpaid - disconnection tonight", ("Power Supply Alert", "courier@govt-notice-india.example"), None, "Sun, 01 Nov 2026 05:01 +0530", "F", [], UTIL, "util", PH, C_INDIA, F_UTIL),
    ("E091", "You have won USD 1,500,000!", ("HR Remote Jobs", "claims@quick-mails.example"), None, "Sun, 01 Nov 2026 12:12 +0530", "N", [], LOTTERY, "lottery", PH, C_ADV, F_LOTTO),
    ("E092", "Scanned document attached", ("Remittance Advice", "accounts@orderdesk-docs.example"), None, "Sun, 01 Nov 2026 21:47 +0530", "S", ["Invoice_12037.docm"], MACRO, "macro", PH, C_ATT, F_MACRO(".docm")),
    ("E093", "Reminder: Workshop: Intro to Docker", CAL, None, "Mon, 02 Nov 2026 08:47 +0530", "P", [], REMINDER("Workshop: Intro to Docker", "07 Oct 2026"), "reminder", L, "Legitimate", F_NORMAL),
    ("E094", "Sync tomorrow at 16:30?", ("Arjun Nair", "arjun.nair@devteam-internal.example"), None, "Mon, 02 Nov 2026 21:40 +0530", "P", [], SYNC("16:30", "Falcon", "Arjun"), "sync", L, "Legitimate", F_NORMAL),
    ("E095", "Action required: verify your identity within 24 hours", ("LinkedIn Security", "no-reply@linkedin-verifyid.example"), SN, "Tue, 03 Nov 2026 07:22 +0530", "F", [], CRED("linkedin-verifyid.example", "34c6b0baf64bf3b8", "LinkedIn Security"), "cred", PH, C_CRED, F_CRED),
    ("E096", "Parcel on hold - pay Rs 29 customs fee", ("Payments Team", "notice@govt-notice-india.example"), None, "Tue, 03 Nov 2026 11:05 +0530", "F", [], "Your parcel is held at the depot. Pay a small fee to release: https://parcel-release-india.example/pay", "E096", PH, C_INDIA, "Delivery scam; micro-payment lure"),
    ("E097", "Project files as discussed", ("Isha Reddy", "isha.reddy@devteam-internal.example"), None, "Tue, 03 Nov 2026 14:10 +0530", "P", ["project_files.zip"], ZIPFILES("Isha"), "zipfiles", L, "Legit - Tricky (zip attachment)", "Legit: known sender, context match, auth pass"),
    ("E098", "This week in Machine Learning: 5 links worth your time", BYTE, None, "Wed, 04 Nov 2026 01:01 +0530", "P", [], NEWS("Machine Learning", 122), "news", L, "Legitimate - Newsletter", F_NORMAL),
    ("E099", "Reminder: invoice due in 3 days", ("Bluepeak Hosting Billing", "billing@bluepeak.example"), None, "Wed, 04 Nov 2026 10:55 +0530", "P", ["Invoice_48213.pdf"], "Friendly reminder that invoice #48213 is due in 3 days. Bank details are unchanged. Questions? Reply to this email.", "E099", L, "Legit - Tricky (payment reminder)", "Legit: matches prior vendor, no bank change"),
    ("E100", "Weekly update: Project Cobalt", ("Isha Reddy", "isha.reddy@devteam-internal.example"), None, "Wed, 04 Nov 2026 23:26 +0530", "P", [], PROJ("Isha", "Cobalt"), "proj", L, "Legitimate", F_NORMAL),
]


def build() -> list[dict]:
    out = []
    for (eid, subj, (fname, faddr), reply, date, auth, att, body, fam, label, cat, flags) in E:
        out.append({
            "id": eid, "subject": subj, "from_name": fname, "from": faddr,
            "reply_to": reply or faddr, "to": TO, "date": date, "auth": AUTH[auth],
            "attachments": att, "body": body, "family": fam, "label": label, "category": cat,
            "tricky": cat.startswith("Legit - Tricky"),
            "red_flags": [f.strip() for f in flags.split(";")],
        })
    return out


def check(rows: list[dict]) -> None:
    """Verify the composition stated in the corpus PDF."""
    assert [r["id"] for r in rows] == [f"E{i:03d}" for i in range(1, 101)], "ids must be E001..E100"
    labels = Counter(r["label"] for r in rows)
    assert labels["LEGIT"] == 48 and labels["PHISHING"] + labels["SPAM"] == 52, labels
    cats = Counter(r["category"] for r in rows)
    assert cats[C_CRED] == 14, cats
    assert cats[C_ATT] + cats[C_VM] == 8, cats
    assert cats[C_BEC] == 7 and cats[C_ADV] == 5 and cats[C_SPAM] == 8 and cats[C_INDIA] == 10, cats
    assert sum(r["tricky"] for r in rows) == 10
    assert all(r["from"].endswith(".example") and r["reply_to"].endswith(".example") for r in rows)


if __name__ == "__main__":
    rows = build()
    check(rows)
    OUT.write_text(json.dumps({
        "name": "Gmail Security Agent - Test Corpus",
        "source": "100 synthetic emails E001-E100 supplied by the project owner (PDF + answer key)",
        "note": "All domains use the reserved .example TLD. 'family' groups emails that share a body "
                "template; evaluate with family-grouped splits to avoid template leakage.",
        "emails": rows,
    }, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    fams = Counter(r["family"] for r in rows)
    print(f"wrote {OUT} ({len(rows)} emails, {len(fams)} template families)")
    print("labels:", dict(Counter(r["label"] for r in rows)))
