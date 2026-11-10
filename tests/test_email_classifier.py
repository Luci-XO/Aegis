"""Email corpus, classifier, red flags, CV splits and the generic model client."""

from __future__ import annotations

import json
import re
import urllib.error
from collections import Counter

import pytest

from aegis.agent.llm_client import LLMError, OpenAICompatibleClient, client_from_env, load_env_file
from aegis.detect.base import SafeDetector
from aegis.detect.email_classifier import (
    ClassifierDetector,
    EmailClassifier,
    featurize,
    lookalike_domain,
    red_flags,
    text_red_flags,
)
from aegis.eval import email_eval as ev

EMAILS = ev.load_corpus()
BY_ID = {e["id"]: e for e in EMAILS}


# --- corpus ----------------------------------------------------------------

def test_corpus_matches_stated_composition():
    assert [e["id"] for e in EMAILS] == [f"E{i:03d}" for i in range(1, 101)]
    labels = Counter(e["label"] for e in EMAILS)
    assert labels["LEGIT"] == 48 and labels["PHISHING"] + labels["SPAM"] == 52 and labels["SPAM"] == 8
    assert sum(e["tricky"] for e in EMAILS) == 10
    assert all(e["from"].endswith(".example") for e in EMAILS)


def test_corpus_spot_checks_against_pdf():
    assert BY_ID["E005"]["attachments"] == ["Invoice_31475.xlsm"] and BY_ID["E005"]["auth"]["spf"] == "softfail"
    assert BY_ID["E025"]["reply_to"] == "ceo.private@secure-mailer.example"
    assert "session=2492e46f4a919478" in BY_ID["E002"]["body"]
    assert BY_ID["E074"]["category"] == "Legit - Tricky (short link)"
    assert BY_ID["E088"]["label"] == "PHISHING" and "UPI PIN" in BY_ID["E088"]["body"]


# --- features and red flags ------------------------------------------------

def test_featurize_collapses_ids_and_adds_headers_only_when_asked():
    toks = featurize(BY_ID["E002"])
    assert "<hex>" in toks and "2492e46f4a919478" not in toks
    assert not any(t.startswith("__") for t in toks)
    with_h = featurize(BY_ID["E002"], use_headers=True)
    assert "__auth_dmarc_fail" in with_h and "__replyto_mismatch" in with_h


def test_red_flags_explain_phishing_and_stay_quiet_on_plain_legit():
    flags = red_flags(BY_ID["E005"])
    assert any("risky attachment type (.xlsm)" in f for f in flags)
    assert any("macro" in f for f in flags)
    assert red_flags(BY_ID["E004"]) == []


# --- classifier --------------------------------------------------------------

@pytest.fixture(scope="module")
def trained():
    return EmailClassifier("stdlib").fit(EMAILS, [e["label"] for e in EMAILS])


def test_classifier_fits_training_data_and_explains(trained):
    v = trained.predict([BY_ID["E002"], BY_ID["E004"]])
    assert [x.label for x in v] == ["PHISHING", "LEGIT"]
    assert v[0].malicious_probability > 0.5 > v[1].malicious_probability
    assert v[0].top_features and "PHISHING" in v[0].explain()


def test_untrained_and_bad_input_raise():
    with pytest.raises(RuntimeError):
        EmailClassifier("stdlib").predict([BY_ID["E001"]])
    with pytest.raises(ValueError):
        EmailClassifier("stdlib").fit([BY_ID["E001"]], [])
    with pytest.raises(ValueError):
        EmailClassifier("tensorflow")


def test_classifier_is_deterministic():
    a = EmailClassifier("stdlib").fit(EMAILS, [e["label"] for e in EMAILS]).predict(EMAILS[:10])
    b = EmailClassifier("stdlib").fit(EMAILS, [e["label"] for e in EMAILS]).predict(EMAILS[:10])
    assert [x.probabilities for x in a] == [x.probabilities for x in b]


def test_sklearn_backend_when_installed():
    pytest.importorskip("sklearn")
    clf = EmailClassifier("sklearn").fit(EMAILS, [e["label"] for e in EMAILS])
    assert clf.predict([BY_ID["E002"]])[0].label == "PHISHING"


def test_detector_adapter_feeds_aegis_and_fails_safe(trained):
    det = SafeDetector(ClassifierDetector(trained))
    hi, lo = det.analyze(BY_ID["E009"]["body"]), det.analyze(BY_ID["E012"]["body"])
    assert hi is not None and lo is not None and hi.score > lo.score
    with pytest.raises(ValueError):
        ClassifierDetector(EmailClassifier("stdlib", use_headers=True))


# --- smarter detector: lookalike domains + hybrid rules ----------------------

@pytest.mark.parametrize("addr", ["x@paypa1.example", "a@g00gle.example", "b@amaz0n.com"])
def test_lookalike_domain_flags_digit_for_letter_fakes(addr):
    assert lookalike_domain(addr) is not None


@pytest.mark.parametrize("addr", ["x@paypal.example", "a@office365.com", "b@s3.example",
                                  "c@govt-notice-india.example", "", "no-at-sign"])
def test_lookalike_domain_leaves_real_domains_alone(addr):
    assert lookalike_domain(addr) is None


def test_lookalike_domain_shows_up_as_a_red_flag():
    faked = {"from": "security@paypa1.example", "subject": "Verify", "body": "hello", "attachments": []}
    assert any("looks faked" in f for f in red_flags(faked))


def test_text_red_flags_ignore_headers():
    # text_red_flags must not depend on auth/reply-to, so the hybrid lift is honest.
    e = BY_ID["E003"]
    flags = text_red_flags(e)
    assert flags and all("authentication" not in f and "Reply-To" not in f for f in flags)


def test_hybrid_rules_escalate_a_missed_family_without_new_false_alarms():
    """Grouped CV: hybrid (classifier OR >=2 text red flags) must raise recall
    over the plain classifier and keep zero false positives on legit email."""
    def base():
        return EmailClassifier("stdlib", use_headers=True)

    def hybrid():
        return EmailClassifier("stdlib", use_headers=True, use_rules=True)

    _, plain = ev.cross_validate(EMAILS, base, grouped=True)
    _, smart = ev.cross_validate(EMAILS, hybrid, grouped=True)
    assert smart["malicious"]["recall"] > plain["malicious"]["recall"]
    assert smart["malicious"]["precision"] == 1.0
    assert smart["fpr_legit"] == 0.0


@pytest.mark.parametrize("use_rules", [False, True])
def test_predict_labels_matches_predict(trained, use_rules):
    """The fast batch path must make exactly the same decisions as predict()."""
    clf = EmailClassifier("stdlib", use_rules=use_rules).fit(EMAILS, [e["label"] for e in EMAILS])
    assert clf.predict_labels(EMAILS) == [v.label for v in clf.predict(EMAILS)]


def test_min_df_shrinks_vocabulary_and_is_validated():
    full = EmailClassifier("stdlib").fit(EMAILS, [e["label"] for e in EMAILS])
    small = EmailClassifier("stdlib", min_df=2).fit(EMAILS, [e["label"] for e in EMAILS])
    assert 0 < len(small._model.vocab) < len(full._model.vocab)
    with pytest.raises(ValueError):
        EmailClassifier("stdlib", min_df=0)


def test_hybrid_only_overrides_a_legit_call_never_the_reverse():
    # A plain-legit email with no text red flags stays LEGIT even with rules on.
    plain = EmailClassifier("stdlib", use_rules=True).fit(EMAILS, [e["label"] for e in EMAILS])
    assert plain.predict([BY_ID["E004"]])[0].label == "LEGIT"
    assert "+rules" in plain.name


# --- evaluation --------------------------------------------------------------

def test_grouped_folds_never_split_a_template_family():
    for test in ev.folds(EMAILS, 5, grouped=True):
        fams = {EMAILS[i]["family"] for i in test}
        rest = {e["family"] for i, e in enumerate(EMAILS) if i not in set(test)}
        assert not fams & rest
    assert sorted(i for f in ev.folds(EMAILS, 5, grouped=True) for i in f) == list(range(100))


def test_score_definitions():
    s = ev.score(EMAILS, [e["label"] for e in EMAILS])
    assert s["malicious"]["f1"] == 1.0 and s["fpr_legit"] == 0.0 and s["binary_errors"] == []
    s = ev.score(EMAILS, ["PHISHING"] * 100)
    assert s["fpr_legit"] == 1.0 and s["fpr_tricky_legit"] == 1.0 and s["malicious"]["recall"] == 1.0


def test_grouped_cv_is_harder_than_random_cv():
    """The headline methodological finding: random CV leaks templates."""
    make = lambda: EmailClassifier("stdlib")  # noqa: E731
    _, rnd = ev.cross_validate(EMAILS, make, grouped=False)
    _, grp = ev.cross_validate(EMAILS, make, grouped=True)
    assert grp["malicious"]["f1"] <= rnd["malicious"]["f1"]


def test_auth_rule_separates_this_corpus_completely():
    """Documented property of the corpus: header auth alone separates the labels."""
    assert ev.score(EMAILS, [ev.auth_rule(e) for e in EMAILS])["malicious"]["f1"] == 1.0


def test_unparsed_predictions_count_as_flagged_not_safe():
    s = ev.score(EMAILS[:4], ["ERROR"] * 4)
    assert s["errors_unparsed"] == 4 and s["malicious"]["fn"] == 0


# --- generic model client / .env configuration ------------------------------

def test_openai_provider_default_base_url():
    c = client_from_env({"AEGIS_LLM_PROVIDER": "openai", "AEGIS_LLM_MODEL": "some-model",
                         "AEGIS_LLM_API_KEY": "test-key"})
    assert c.base_url == "https://api.openai.com/v1" and c.api_key == "test-key"


def test_removed_providers_need_an_explicit_base_url():
    with pytest.raises(LLMError):
        client_from_env({"AEGIS_LLM_PROVIDER": "unknown-provider", "AEGIS_LLM_MODEL": "m"})


def test_env_file_loading_and_real_env_wins(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text('# comment\nAEGIS_LLM_PROVIDER=ollama\nAEGIS_LLM_MODEL="llama3"\n', "utf-8")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "from-real-env")
    env = load_env_file(str(f))
    assert env["AEGIS_LLM_PROVIDER"] == "ollama" and env["AEGIS_LLM_MODEL"] == "from-real-env"
    monkeypatch.delenv("AEGIS_LLM_PROVIDER", raising=False)
    assert "AEGIS_LLM_PROVIDER" not in load_env_file(str(tmp_path / "missing.env"))


def test_http_errors_report_status_without_leaking_body(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("https://x", 401, "Unauthorized", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", boom)
    c = OpenAICompatibleClient(base_url="https://example.invalid/v1", model="m", api_key="secret-key-value")
    with pytest.raises(LLMError) as exc:
        c.complete([{"role": "user", "content": "hi"}])
    assert "HTTP 401" in str(exc.value) and "API key rejected" in str(exc.value)
    assert "secret-key-value" not in str(exc.value)


def test_corpus_json_has_no_real_looking_keys():
    raw = json.dumps(EMAILS)
    # Catch accidentally committed API keys: Google-style (AIza.../AQ.Ab8...) and
    # OpenAI (sk- followed by a long secret, not words like "orderdesk-docs").
    assert "AIza" not in raw and "AQ.Ab8" not in raw
    assert not re.search(r"sk-[A-Za-z0-9_-]{20,}", raw)


def test_transient_errors_are_retried_then_succeed(monkeypatch):
    calls = {"n": 0}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"choices": [{"message": {"content": "ok"}}]}'

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError("https://x", 503, "Unavailable", {}, None)
        return Resp()

    monkeypatch.setattr("urllib.request.urlopen", flaky)
    monkeypatch.setattr("time.sleep", lambda s: None)
    c = OpenAICompatibleClient(base_url="https://example.invalid/v1", model="m")
    assert c.complete([{"role": "user", "content": "hi"}]) == "ok" and calls["n"] == 3


def test_permanent_errors_are_not_retried(monkeypatch):
    calls = {"n": 0}

    def bad(*a, **k):
        calls["n"] += 1
        raise urllib.error.HTTPError("https://x", 404, "Not Found", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", bad)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(LLMError):
        OpenAICompatibleClient(base_url="https://example.invalid/v1", model="m").complete([])
    assert calls["n"] == 1


def test_retries_give_up_with_clear_message(monkeypatch):
    def down(*a, **k):
        raise urllib.error.HTTPError("https://x", 503, "Unavailable", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", down)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(LLMError, match="HTTP 503"):
        OpenAICompatibleClient(base_url="https://example.invalid/v1", model="m", retries=2).complete([])


def test_empty_answer_raises_clear_error(monkeypatch):
    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"choices": [{"message": {"content": null}, "finish_reason": "length"}]}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Resp())
    with pytest.raises(LLMError, match="finish_reason=length"):
        OpenAICompatibleClient(base_url="https://example.invalid/v1", model="m").complete([])


def test_max_tokens_default_and_override():
    base = {"AEGIS_LLM_PROVIDER": "openai", "AEGIS_LLM_MODEL": "m"}
    assert client_from_env(base).max_tokens == 4096
    assert client_from_env({**base, "AEGIS_LLM_MAX_TOKENS": "8192"}).max_tokens == 8192
