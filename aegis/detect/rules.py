"""Interpretable rule-based injection detector (baseline).

Each rule is a regular expression with a weight and a category. Scores combine
by "noisy-OR": score = 1 - prod(1 - w_i) over matched rules, so independent
weak signals add up but the result stays within [0, 1].

Matches that sit inside quotation marks get a reduced weight. Quoted phrases
are usually someone *discussing* an attack (security training, newsletters)
rather than issuing an instruction.

Limitations, by design of a keyword baseline:
- Polite, keyword-free requests ("please send the customer list to ...") score low.
- Paraphrases, other languages, encodings and typos evade the patterns.
- The weights were set by hand, not fitted. They have NOT been tuned against
  the synthetic emails in aegis/data. Treat any score on those emails as a
  development measurement, not a held-out result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.core.schemas import RiskReport

QUOTED_WEIGHT_FACTOR = 0.3
# Double quotes, curly quotes, or single quotes that are not apostrophes
# (a single quote counts only when not surrounded by letters, so "month's" is ignored).
_LDQ, _RDQ, _LSQ, _RSQ = "\u201c", "\u201d", "\u2018", "\u2019"
_QUOTED = re.compile(
    r"\"([^\"\n]{3,200})\""
    rf"|{_LDQ}([^{_RDQ}\n]{{3,200}}){_RDQ}"
    rf"|{_LSQ}([^{_RSQ}\n]{{3,200}}){_RSQ}"
    r"|(?<!\w)'([^'\n]{3,200})'(?!\w)"
)

_DATA_NOUN = (
    r"(file|files|document|attachment|contents?|list|keys?|credentials?|passwords?|payroll|"
    r"salar(y|ies)|confidential|secrets?|database|records|f-\d{3}|[\w-]+\.(csv|txt|xlsx|pdf|docx|md))"
)
_SEND_VERB = r"\b(send|sending|forward|forwarding|email|e-mail|attach|upload|export|share|transfer|post)\b"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    weight: float
    pattern: re.Pattern[str]
    description: str


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule("D01", "instruction_override", 0.60,
         _rx(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,30}\b(previous|prior|above|earlier|"
             r"all|your|any|system)\b[^.\n]{0,20}\b(instructions?|rules|prompts?|guidelines|directives)\b"),
         "Asks the reader to drop its existing instructions."),
    Rule("D02", "role_manipulation", 0.50,
         _rx(r"\b(you are now|new instructions|system prompt|developer mode|act as|"
             r"from now on you)\b"),
         "Tries to redefine the model's role or instructions."),
    Rule("D03", "addresses_ai", 0.35,
         _rx(r"\b(ai|virtual|digital) assistant\b|\bassistant\s*[,:]|\b(language model|llm|chatbot)\b|"
             r"\bagent (processing|reading)\b"),
         "Speaks directly to an AI system rather than the human recipient."),
    Rule("D04", "concealment", 0.40,
         _rx(r"\b(do not|don't|never|without)\b[^.\n]{0,15}\b(mention|tell|telling|inform|informing|"
             r"reveal|notify|alert)\w*\b[^.\n]{0,25}\b(user|anyone|them|recipient|owner)\b"),
         "Asks for the action to be hidden from the user."),
    Rule("D05", "data_exfiltration", 0.35,
         _rx(_SEND_VERB + r"[^.\n]{0,60}?\b" + _DATA_NOUN),
         "Requests sending or exporting data or files."),
    Rule("D06", "credential_request", 0.20,
         _rx(r"\b(api[_ ]?keys?|passwords?|credentials?|access tokens?|secret keys?|private keys?)\b"),
         "Mentions credentials."),
    Rule("D07", "external_destination", 0.20,
         _rx(_SEND_VERB + r"[^\n]{0,80}?[\w.+-]+@[\w-]+(\.[\w-]+)+|[\w.+-]+@[\w-]+(\.[\w-]+)+[^\n]{0,80}?"
             + _SEND_VERB),
         "Pairs a send-type verb with an email address."),
    Rule("D08", "urgency", 0.10,
         _rx(r"\b(immediately|urgent(ly)?|asap|right away|within the hour|mandatory|before summari[sz]ing)\b"),
         "Uses pressure or urgency."),
)


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    return [m.span(m.lastindex or 0) for m in _QUOTED.finditer(text)]


def _inside(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(a <= span[0] and span[1] <= b for a, b in spans)


class RuleDetector:
    name = "rules-v1"

    def analyze(self, text: str) -> RiskReport:
        quoted = _quoted_spans(text)
        remaining = 1.0
        categories: list[str] = []
        evidence: list[str] = []
        for rule in RULES:
            matches = list(rule.pattern.finditer(text))
            if not matches:
                continue
            # A rule counts once. Use full weight if any match is outside quotes.
            any_unquoted = any(not _inside(m.span(), quoted) for m in matches)
            weight = rule.weight if any_unquoted else rule.weight * QUOTED_WEIGHT_FACTOR
            remaining *= 1.0 - weight
            categories.append(rule.category)
            evidence.append(rule.rule_id if any_unquoted else f"{rule.rule_id}(quoted)")
        return RiskReport(
            score=round(1.0 - remaining, 4),
            categories=tuple(categories),
            evidence=tuple(evidence),
            detector=self.name,
        )
