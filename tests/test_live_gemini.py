"""Optional live smoke test against the real Gemini API.

Skipped by default. Run with:   set GEMINI_API_KEY=...   then   pytest -m live
Costs a handful of requests.
"""
import os

import pytest

from patchgate.config import load_settings
from patchgate.llm import GeminiProposer
from patchgate.manifest import load_manifest
from patchgate.repair import repair_manifest

from .conftest import EXAMPLES

pytestmark = pytest.mark.live


@pytest.fixture
def live_key(monkeypatch):
    key = os.environ.get("PATCHGATE_LIVE_KEY") or os.environ.get("GEMINI_API_KEY_LIVE")
    if not key:
        pytest.skip("set PATCHGATE_LIVE_KEY to run live Gemini tests")
    monkeypatch.setenv("GEMINI_API_KEY", key)
    monkeypatch.setenv("PATCHGATE_MAX_LLM_CALLS", "12")


def test_live_repair_nightly_report(live_key):
    settings = load_settings(None)
    m = load_manifest((EXAMPLES / "nightly-report.yaml").read_text(encoding="utf-8"))
    report = repair_manifest(m, GeminiProposer(settings), max_attempts=2, fallback_to_template=False)
    assert report.llm_calls >= 1
    assert report.degraded is None, report.degraded
    # Every accepted change passed the gate; at least one finding should be repaired by Gemini itself.
    assert any(o.accepted_by == "gemini" for o in report.outcomes)
