# Three-minute live demo script

Start the dashboard before you present:

```bash
python -m aegis.web      # open http://127.0.0.1:8000
```

The dashboard explains itself, so the script below just walks through it. Every
scenario actually runs the code when you open it; nothing is pre-recorded.

## 0:00 Overview tab (30 s)

Read the headline, then point at the three cards:

- **The problem:** an attacker hides an instruction in an ordinary email; the AI can't tell it apart from the user's request.
- **Why scanning isn't enough:** our text scanner caught only 3 of 10 new attacks.
- **What Aegis does:** it checks the *action*, not the text.

Point at the "Where Aegis sits" diagram: the gateway is not an AI, so it can't be talked into anything.

Click **Start the guided demo**.

## 0:30 Scenario 1, a normal task (20 s)

"First, Aegis must not break normal work." Both sides show **Task completed**.
The only difference is one approval for sending.

## 0:50 Scenario 2, the hidden instruction (50 s)

- Point at the email. The red highlight is the attacker's instruction.
- **Left (without protection):** "Attack succeeded", and payroll appears in *What actually left the system*, to an address the user never approved.
- **Right (with Aegis):** the same AI step shows **Blocked by Aegis**. Walk down the checkpoint: the file and the recipient were never allowed by the user's task. The normal reply still went out.

Line to say: "The AI was fooled in both cases. Aegis didn't need to detect the attack; it refused an action the user never allowed."

## 1:40 Scenario 3, the scanner is fooled (40 s)

- **Left (scanner only):** the reworded attack gets past the scanner, and payroll leaks.
- **Right (Aegis):** blocked.

Line to say: "This attack was written after our rules were frozen, and a test enforces that."

## 2:20 Scenario 5, the honest limit (15 s)

Both sides fail. "If the user already allowed a reply, an attacker can change its wording. We show this on purpose; the person approving the send is the defence here."

## 2:35 Results tab (25 s)

Point at the four cards: **100% to 10%** of attacks succeeding, **18 to 0** forbidden actions run, **100%** of normal tasks still completed, and the scanner alone catching **3 of 10**.

Close: "Small, dependency-free, reproducible, and honest about its limits."

## If the judges want to try it

Use **Try it yourself**, choose *You decide* as the approver, and let them approve or reject the email themselves.

## Fallback if the browser fails

```bash
python scripts/demo_core.py
python scripts/demo_dashboard_flow.py
python -m aegis.eval --split heldout
```
