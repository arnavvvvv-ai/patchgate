"""Patch proposers: Gemini (google-genai SDK), deterministic templates, and scripted/simulated candidates.

Proposers only *suggest* patches. Nothing they return touches a manifest until the gate accepts it.
"""
from __future__ import annotations

import copy
import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Protocol

from pydantic import BaseModel, Field, ValidationError

from .checks import CONTROLS, Finding
from .config import ConfigError, Settings
from .fixers import template_fix

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
REDACTED = "<redacted>"
_SECRETISH = re.compile(r"(pass(word)?|secret|token|api[-_]?key|credential|private[-_]?key)", re.I)


@dataclass
class ProposalRequest:
    resource: dict[str, Any]
    finding: Finding
    attempt: int = 1
    feedback: list[str] = field(default_factory=list)


@dataclass
class Proposal:
    source: str
    patch: list[dict[str, Any]] | None
    rationale: str = ""
    runtime_assumptions: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0
    simulated: bool = False


class Proposer(Protocol):
    name: str

    def propose(self, req: ProposalRequest) -> Proposal: ...


class LLMUnavailable(RuntimeError):
    """Gemini could not be reached or refused the request; the repair run degrades to fallback."""


class BudgetExceeded(RuntimeError):
    pass


class CallBudget:
    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def take(self) -> None:
        if self.used >= self.limit:
            raise BudgetExceeded(f"LLM call budget of {self.limit} exhausted")
        self.used += 1


# ---------------------------------------------------------------- redaction

def redact(resource: dict[str, Any]) -> dict[str, Any]:
    """Copy of the resource with env values, annotation values and secret-looking args masked.

    Structure (and therefore every JSON-pointer path) is preserved, so patches still apply to the original.
    """
    out = copy.deepcopy(resource)

    def walk(node: Any, parent_key: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "annotations" and isinstance(v, dict):
                    for ak in v:
                        v[ak] = REDACTED
                elif k == "env" and isinstance(v, list):
                    for e in v:
                        if isinstance(e, dict) and "value" in e:
                            e["value"] = REDACTED
                elif k in ("args", "command") and isinstance(v, list):
                    for i, a in enumerate(v):
                        if isinstance(a, str) and _SECRETISH.search(a):
                            v[i] = REDACTED
                else:
                    walk(v, k)
        elif isinstance(node, list):
            for item in node:
                walk(item, parent_key)

    walk(out)
    return out


# ---------------------------------------------------------------- template / scripted proposers

class TemplateProposer:
    """Deterministic rule-based fixes; a single candidate per finding."""

    name = "template"

    def propose(self, req: ProposalRequest) -> Proposal:
        if req.attempt > 1:
            return Proposal(self.name, None, error="template proposer has no alternative candidate")
        patch = template_fix(req.resource, req.finding)
        if not patch:
            return Proposal(self.name, None, error="no template fix for this control")
        return Proposal(self.name, patch, rationale=f"template fix for {req.finding.control_id}",
                        runtime_assumptions=list(CONTROLS[req.finding.control_id].runtime_assumptions))


class ScriptedProposer:
    """Replays pre-written candidate patches per control id. Used for tests and the offline demo.

    Output is marked ``simulated=True`` so it is never confused with genuine Gemini output.
    ``script`` maps control id -> list of candidates; candidate ``patch`` may be the string
    ``"@template"`` to reuse the deterministic fix.
    """

    name = "simulated"

    def __init__(self, script: dict[str, list[dict[str, Any]]]):
        self.script = script

    def propose(self, req: ProposalRequest) -> Proposal:
        cands = self.script.get(req.finding.control_id) or []
        if req.attempt > len(cands):
            return Proposal(self.name, None, error="no more scripted candidates", simulated=True)
        cand = cands[req.attempt - 1]
        patch = cand.get("patch")
        if patch == "@template":
            patch = template_fix(req.resource, req.finding)
        elif isinstance(patch, list):
            patch = _fill_placeholders(patch, req.finding)
        return Proposal(self.name, patch, rationale=cand.get("rationale", ""),
                        runtime_assumptions=cand.get("runtime_assumptions", []), simulated=True)


def _fill_placeholders(patch: list[dict[str, Any]], finding: Finding) -> list[dict[str, Any]]:
    text = json.dumps(patch).replace("{ctr}", finding.container_pointer or "").replace("{pod}", finding.pod_prefix)
    return json.loads(text)


# ---------------------------------------------------------------- Gemini proposer

class LLMOp(BaseModel):
    op: Literal["add", "remove", "replace"]
    path: str = Field(description="RFC 6901 JSON pointer into the resource, e.g. /spec/template/spec/containers/0/securityContext")
    value_json: str | None = Field(default=None, description="The value encoded as a JSON string; omit for remove")


class LLMRepair(BaseModel):
    ops: list[LLMOp]
    rationale: str = Field(description="One or two sentences explaining the change")
    runtime_assumptions: list[str] = Field(default_factory=list,
                                           description="Conditions that must hold at runtime for the fix not to break the workload")


SYSTEM_INSTRUCTION = """You repair one Kubernetes misconfiguration at a time by emitting an RFC 6902 JSON Patch.
Rules:
- Patch only the single resource you are given. Paths are JSON pointers relative to that resource.
- Change only what is needed to resolve the finding. Only touch paths matching the ALLOWED PATHS patterns
  ('*' = one segment, '**' = any suffix). Never change images, commands, args, env, ports, labels,
  selectors, replicas, existing volumes or existing volume mounts.
- Use 'add' to create a missing object (the value may be a nested object); use '-' as the index to append to a list.
- Encode every value as JSON text in value_json (e.g. "false", "\\"RuntimeDefault\\"", "{\\"drop\\": [\\"ALL\\"]}").
- Values shown as <redacted> are hidden secrets; never copy or modify them.
- If a fix requires writable directories (e.g. for readOnlyRootFilesystem), add emptyDir volumes and mounts.
- List runtime assumptions the fix relies on (e.g. "image can run as UID 10001")."""


def build_prompt(req: ProposalRequest, redact_values: bool = True) -> str:
    f = req.finding
    control = CONTROLS[f.control_id]
    resource = redact(req.resource) if redact_values else req.resource
    lines = [
        f"FINDING {f.control_id} ({control.title}, severity {control.severity})",
        f"Subject: {f.subject}  Location: {f.pointer}",
        f"Problem: {f.message}",
        f"Why it matters: {control.rationale}",
        "ALLOWED PATHS:",
        *[f"  {p}" for p in control.allowed_patterns(f)],
        "RESOURCE (JSON):",
        json.dumps(resource, indent=1, sort_keys=False),
    ]
    if req.feedback:
        lines += ["", f"Your previous candidate (attempt {req.attempt - 1}) was REJECTED by the verifier:",
                  *[f"  - {r}" for r in req.feedback[:12]], "Produce a corrected patch that avoids these problems."]
    return "\n".join(lines)


def parse_llm_json(text: str) -> tuple[list[dict[str, Any]], str, list[str]]:
    """Validate Gemini's structured output. Raises ValueError with an actionable message on malformed output."""
    if not text or not text.strip():
        raise ValueError("empty response")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", cleaned)
    try:
        data = LLMRepair.model_validate_json(cleaned)
    except ValidationError as exc:
        raise ValueError(f"response does not match schema: {exc.errors()[0]['msg']}") from exc
    ops: list[dict[str, Any]] = []
    for i, o in enumerate(data.ops):
        d: dict[str, Any] = {"op": o.op, "path": o.path}
        if o.op != "remove":
            if o.value_json is None:
                raise ValueError(f"op {i} ({o.op}) is missing value_json")
            try:
                d["value"] = json.loads(o.value_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"op {i} value_json is not valid JSON: {exc.msg}") from exc
        ops.append(d)
    return ops, data.rationale, data.runtime_assumptions


def _is_retryable(exc: Exception) -> bool:
    try:
        from google.genai import errors as genai_errors
    except ImportError:  # pragma: no cover
        genai_errors = None
    code = getattr(exc, "code", None)
    if genai_errors is not None and isinstance(exc, genai_errors.APIError):
        return code in RETRYABLE_STATUS
    try:
        import httpx
        if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
            return True
    except ImportError:  # pragma: no cover
        pass
    return isinstance(exc, (TimeoutError, ConnectionError))


def _retry_delay_hint(exc: Exception) -> float | None:
    """Seconds from a google.rpc.RetryInfo detail (e.g. {'retryDelay': '52s'}) in a 429 response."""
    details = getattr(exc, "details", None)
    err = details.get("error", details) if isinstance(details, dict) else None
    for d in (err.get("details") or []) if isinstance(err, dict) else []:
        if isinstance(d, dict) and str(d.get("@type", "")).endswith("RetryInfo"):
            m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)s\s*$", str(d.get("retryDelay", "")))
            if m:
                return float(m.group(1))
    return None


def _brief_error(exc: Exception | None) -> str:
    if exc is None:
        return "unknown error"
    code, status = getattr(exc, "code", None), getattr(exc, "status", None)
    msg = getattr(exc, "message", None) or str(exc)
    head = f"{type(exc).__name__}" + (f" {code} {status}" if code else "")
    return f"{head}: {str(msg).splitlines()[0][:200]}"


class GeminiProposer:
    name = "gemini"

    def __init__(self, settings: Settings, budget: CallBudget | None = None, client: Any = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.model = settings.gemini_model
        self.budget = budget or CallBudget(settings.max_llm_calls)
        self._sleep = sleep
        self.tokens_in = 0
        self.tokens_out = 0
        self._clock = clock
        self._last_call = 0.0
        self.last_finish_reason = ""
        if client is None:
            api_key = settings.require_gemini()
            from google import genai
            from google.genai import types
            client = genai.Client(api_key=api_key,
                                  http_options=types.HttpOptions(timeout=settings.gemini_timeout_s * 1000))
        self.client = client

    def _config(self) -> Any:
        from google.genai import types
        return types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.2,
            # 2.5-series models spend part of this budget on internal reasoning; 2048 truncated JSON in live runs
            max_output_tokens=8192,
            response_mime_type="application/json",
            response_schema=LLMRepair,
        )

    def _throttle(self) -> None:
        """Client-side spacing for low per-minute quotas (e.g. free tier); off when GEMINI_RPM=0."""
        if self.settings.gemini_rpm <= 0:
            return
        interval = 60.0 / self.settings.gemini_rpm
        wait = self._last_call + interval - self._clock()
        if self._last_call and wait > 0:
            self._sleep(wait)
        self._last_call = self._clock()

    def _backoff(self, exc: Exception, attempt: int) -> float:
        hinted = _retry_delay_hint(exc)
        delay = hinted if hinted is not None else (2 ** attempt) + random.uniform(0, 0.5)
        return min(float(self.settings.gemini_max_backoff_s), delay + (1.0 if hinted is not None else 0.0))

    def _generate(self, prompt: str) -> str:
        last: Exception | None = None
        for attempt in range(self.settings.gemini_max_retries + 1):
            self.budget.take()
            self._throttle()
            try:
                resp = self.client.models.generate_content(model=self.model, contents=prompt, config=self._config())
                usage = getattr(resp, "usage_metadata", None)
                self.tokens_in += getattr(usage, "prompt_token_count", 0) or 0
                self.tokens_out += getattr(usage, "candidates_token_count", 0) or 0
                cands = getattr(resp, "candidates", None) or []
                self.last_finish_reason = str(getattr(cands[0], "finish_reason", "") or "") if cands else ""
                return getattr(resp, "text", None) or ""
            except BudgetExceeded:
                raise
            except Exception as exc:  # classified below
                last = exc
                if not _is_retryable(exc) or attempt == self.settings.gemini_max_retries:
                    break
                hinted = _retry_delay_hint(exc)
                if hinted is not None and hinted > self.settings.gemini_max_backoff_s:
                    # e.g. a daily quota: waiting is pointless within this run
                    raise LLMUnavailable(f"Gemini quota exhausted; server asks to retry in {hinted / 3600:.1f} h "
                                         f"({_brief_error(exc)}). Try another GEMINI_MODEL or a paid tier.")
                self._sleep(self._backoff(exc, attempt))
        code = getattr(last, "code", None)
        brief = _brief_error(last)
        if code in (400, 401, 403, 404):
            raise LLMUnavailable(f"Gemini rejected the request ({code}): check GEMINI_API_KEY and GEMINI_MODEL={self.model!r}. {brief}")
        hint = " Free-tier quota? Set GEMINI_RPM=5 (or your quota) to pace requests." if code == 429 else ""
        raise LLMUnavailable(f"Gemini unavailable after retries: {brief}{hint}")

    def propose(self, req: ProposalRequest) -> Proposal:
        t0 = time.perf_counter()
        prompt = build_prompt(req, redact_values=self.settings.redact)
        text = self._generate(prompt)
        ms = (time.perf_counter() - t0) * 1000
        try:
            patch, rationale, assumptions = parse_llm_json(text)
        except ValueError as exc:
            if "MAX_TOKENS" in self.last_finish_reason:
                return Proposal(self.name, None, latency_ms=ms,
                                error="model output was truncated (MAX_TOKENS); emit fewer, smaller operations")
            return Proposal(self.name, None, error=f"malformed model output: {exc}", latency_ms=ms)
        return Proposal(self.name, patch, rationale=rationale, runtime_assumptions=assumptions, latency_ms=ms)


def make_proposer(kind: str, settings: Settings, script: dict[str, Any] | None = None) -> Proposer:
    if kind == "gemini":
        return GeminiProposer(settings)
    if kind == "template":
        return TemplateProposer()
    if kind == "simulated":
        if script is None:
            from .demo import load_demo_script
            script = load_demo_script()
        return ScriptedProposer(script)
    raise ConfigError(f"unknown proposer {kind!r}; choose gemini, template or simulated")
