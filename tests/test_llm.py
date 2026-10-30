import json
from types import SimpleNamespace

import pytest
from google.genai import errors

from patchgate.checks import find_matching, scan_object
from patchgate.config import ConfigError, load_settings
from patchgate.llm import (CallBudget, GeminiProposer, LLMUnavailable, ProposalRequest, BudgetExceeded,
                           build_prompt, parse_llm_json, redact)

from .conftest import CTR0

GOOD = json.dumps({"ops": [{"op": "add", "path": f"{CTR0}/securityContext/allowPrivilegeEscalation", "value_json": "false"}],
                   "rationale": "disable escalation", "runtime_assumptions": []})


class FakeModels:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def generate_content(self, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return SimpleNamespace(text=o)


def make(outcomes, monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    models = FakeModels(outcomes)
    p = GeminiProposer(load_settings(None), client=SimpleNamespace(models=models), sleep=lambda s: None)
    return p, models


def req(deployment, feedback=None):
    f = find_matching(scan_object(deployment), ("PG002", 0, "api"))
    return ProposalRequest(deployment, f, attempt=2 if feedback else 1, feedback=feedback or [])


def test_parse_llm_json_valid_and_fenced():
    ops, why, _ = parse_llm_json("```json\n" + GOOD + "\n```")
    assert ops == [{"op": "add", "path": f"{CTR0}/securityContext/allowPrivilegeEscalation", "value": False}]
    assert why == "disable escalation"


@pytest.mark.parametrize("text,msg", [
    ("", "empty"),
    ("not json", "schema"),
    (json.dumps({"ops": [{"op": "move", "path": "/a"}], "rationale": "x"}), "schema"),
    (json.dumps({"ops": [{"op": "add", "path": "/a"}], "rationale": "x"}), "missing value_json"),
    (json.dumps({"ops": [{"op": "add", "path": "/a", "value_json": "{bad"}], "rationale": "x"}), "not valid JSON"),
])
def test_parse_llm_json_rejects_malformed(text, msg):
    with pytest.raises(ValueError, match=msg):
        parse_llm_json(text)


def test_redaction_preserves_structure(deployment):
    deployment["metadata"]["annotations"] = {"token": "abc"}
    deployment["spec"]["template"]["spec"]["containers"][1]["args"] = ["--password=hunter2", "--verbose"]
    r = redact(deployment)
    c = r["spec"]["template"]["spec"]["containers"]
    assert c[0]["env"][0] == {"name": "DB_PASSWORD", "value": "<redacted>"}
    assert c[1]["args"] == ["<redacted>", "--verbose"]
    assert r["metadata"]["annotations"] == {"token": "<redacted>"}
    assert deployment["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] == "s3cr3t-value"


def test_prompt_contains_scope_feedback_and_no_secret(deployment):
    prompt = build_prompt(req(deployment, ["[scope] change outside contract: /x"]))
    assert "s3cr3t-value" not in prompt and "<redacted>" in prompt
    assert f"{CTR0}/securityContext/allowPrivilegeEscalation" in prompt
    assert "REJECTED" in prompt and "/x" in prompt


def test_success_and_config(deployment, monkeypatch):
    p, models = make([GOOD], monkeypatch, GEMINI_MODEL="gemini-test-model")
    prop = p.propose(req(deployment))
    assert prop.patch[0]["value"] is False and prop.error is None and not prop.simulated
    call = models.calls[0]
    assert call["model"] == "gemini-test-model"
    assert call["config"].response_mime_type == "application/json"
    assert call["config"].system_instruction


def test_retries_transient_errors_then_succeeds(deployment, monkeypatch):
    p, models = make([errors.ServerError(503, {"error": {"message": "overloaded", "status": "UNAVAILABLE"}}),
                      errors.ClientError(429, {"error": {"message": "quota", "status": "RESOURCE_EXHAUSTED"}}),
                      GOOD], monkeypatch)
    assert p.propose(req(deployment)).patch is not None
    assert len(models.calls) == 3 and p.budget.used == 3


def test_429_honours_server_retry_delay(deployment, monkeypatch):
    quota = {"error": {"code": 429, "message": "quota\nmore", "status": "RESOURCE_EXHAUSTED", "details": [
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "52s"}]}}
    sleeps = []
    monkeypatch.setenv("GEMINI_MAX_BACKOFF_S", "65")
    p = GeminiProposer(load_settings(None), client=SimpleNamespace(models=FakeModels([errors.ClientError(429, quota), GOOD])),
                       sleep=sleeps.append)
    assert p.propose(req(deployment)).patch is not None
    assert sleeps == [53.0]  # server hint + 1 s margin, not the 1-2 s exponential default


def test_daily_quota_fails_fast_without_sleeping(deployment, monkeypatch):
    quota = {"error": {"code": 429, "message": "per day", "status": "RESOURCE_EXHAUSTED", "details": [
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "76310s"}]}}
    sleeps = []
    models = FakeModels([errors.ClientError(429, quota), GOOD])
    p = GeminiProposer(load_settings(None), client=SimpleNamespace(models=models), sleep=sleeps.append)
    with pytest.raises(LLMUnavailable, match="quota exhausted"):
        p.propose(req(deployment))
    assert sleeps == [] and len(models.calls) == 1


def test_429_exhaustion_message_is_brief_and_actionable(deployment, monkeypatch):
    quota = {"error": {"code": 429, "message": "Quota exceeded\n" + "x" * 2000, "status": "RESOURCE_EXHAUSTED"}}
    p, _ = make([errors.ClientError(429, quota)] * 3, monkeypatch, GEMINI_MAX_RETRIES="2")
    with pytest.raises(LLMUnavailable) as ei:
        p.propose(req(deployment))
    assert "GEMINI_RPM" in str(ei.value) and len(str(ei.value)) < 400


def test_client_side_rpm_throttle(deployment, monkeypatch):
    monkeypatch.setenv("GEMINI_RPM", "5")
    now = [100.0]
    sleeps = []
    def sleep(s):
        sleeps.append(s)
        now[0] += s
    p = GeminiProposer(load_settings(None), client=SimpleNamespace(models=FakeModels([GOOD, GOOD, GOOD])),
                       sleep=sleep, clock=lambda: now[0])
    for _ in range(3):
        p.propose(req(deployment))
        now[0] += 1.0  # each call "takes" 1 s
    assert sleeps == [pytest.approx(11.0), pytest.approx(11.0)]  # 12 s spacing at 5 rpm


def test_non_retryable_error_is_actionable(deployment, monkeypatch):
    p, models = make([errors.ClientError(403, {"error": {"message": "denied", "status": "PERMISSION_DENIED"}})], monkeypatch)
    with pytest.raises(LLMUnavailable, match="GEMINI_API_KEY"):
        p.propose(req(deployment))
    assert len(models.calls) == 1


def test_retries_are_bounded(deployment, monkeypatch):
    err = errors.ServerError(500, {"error": {"message": "boom", "status": "INTERNAL"}})
    p, models = make([err] * 10, monkeypatch, GEMINI_MAX_RETRIES="2")
    with pytest.raises(LLMUnavailable):
        p.propose(req(deployment))
    assert len(models.calls) == 3


def test_budget_caps_calls(deployment, monkeypatch):
    p, _ = make([GOOD, GOOD], monkeypatch, PATCHGATE_MAX_LLM_CALLS="1")
    p.propose(req(deployment))
    with pytest.raises(BudgetExceeded):
        p.propose(req(deployment))


def test_malformed_output_becomes_proposal_error(deployment, monkeypatch):
    p, _ = make(["{\"ops\": 5}"], monkeypatch)
    prop = p.propose(req(deployment))
    assert prop.patch is None and "malformed" in prop.error


def test_missing_key_is_config_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "your-key-here")
    with pytest.raises(ConfigError, match="GEMINI_API_KEY"):
        GeminiProposer(load_settings(None))


def test_invalid_numeric_env(monkeypatch):
    monkeypatch.setenv("GEMINI_TIMEOUT_S", "abc")
    with pytest.raises(ConfigError, match="GEMINI_TIMEOUT_S"):
        load_settings(None)


def test_truncated_output_reported_as_truncation(deployment, monkeypatch):
    class Truncating(FakeModels):
        def generate_content(self, model, contents, config):
            return SimpleNamespace(text='{"ops": [{"op": "add", "pa',
                                   candidates=[SimpleNamespace(finish_reason="FinishReason.MAX_TOKENS")])
    p = GeminiProposer(load_settings(None), client=SimpleNamespace(models=Truncating([])), sleep=lambda s: None)
    prop = p.propose(req(deployment))
    assert prop.patch is None and "truncated" in prop.error


def test_budget_object():
    b = CallBudget(2)
    b.take(); b.take()
    with pytest.raises(BudgetExceeded):
        b.take()


def test_redaction_masks_url_credentials_and_flag_values():
    r = redact({"spec": {"containers": [{"name": "a", "args": [
        "--db=postgres://admin:S3cr3tPw@db:5432/app", "--password", "hunter2", "--verbose", "serve"]}]}})
    args = r["spec"]["containers"][0]["args"]
    assert args == ["--db=postgres://admin:<redacted>@db:5432/app", "<redacted>", "<redacted>", "--verbose", "serve"]
    assert "S3cr3tPw" not in str(r) and "hunter2" not in str(r)
