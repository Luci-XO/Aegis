# Sample emails for "Test your own email"

Upload any of these on the dashboard's **Test your own email** page (or drag them onto it).
All addresses use the reserved `.example` domain, so nothing can reach a real person.

| File | What it shows |
|---|---|
| `1-hidden-payroll-request.eml` | Hidden instruction aimed at the AI; Aegis blocks the payroll leak |
| `2-polite-customer-data-request.eml` | No suspicious wording and passing authentication; the scanner misses it, Aegis blocks it |
| `3-lookalike-domain-credentials.eml` | `aegis-c0rp` with a zero; credential theft plus a risky `.html` attachment |
| `4-normal-email.eml` | Nothing malicious; the reply goes out normally |

You can also upload a real email: in Gmail open it, click the three-dot menu and choose
*Download message*. It is only analysed locally; the simulated assistant never sends anything.
