"""Headless tests of the Streamlit dashboard (streamlit.testing AppTest): every view renders without
exceptions or warnings, and the core repair and gate-comparison workflows produce the right verdicts."""
from streamlit.testing.v1 import AppTest

from .conftest import ROOT

APP = str(ROOT / "app" / "streamlit_app.py")


def fresh() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert not at.exception, at.exception
    return at


def texts(at: AppTest) -> str:
    return " ".join([m.value for m in at.markdown] + [h.value for h in at.header] + [c.value for c in at.caption])


def test_every_view_renders_cleanly():
    at = fresh()
    for view in ("repair", "gate", "evaluation", "audit"):
        at.session_state["view"] = view
        at.run()
        assert not at.exception, (view, at.exception)
        assert not at.warning, (view, [w.value for w in at.warning])
        assert not at.error, (view, [e.value for e in at.error])


def test_repair_workflow_simulated():
    at = fresh()
    assert any(h.value == "Findings" for h in at.header)
    at.button(key="repair_btn").click().run()
    assert not at.exception, at.exception
    assert any(h.value == "Repair result" for h in at.header)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Findings before"] == "13" and metrics["Findings after"] == "1"
    assert int(metrics["Candidates rejected"]) >= 1
    assert "simulated candidates, not Gemini output" in texts(at)


def test_gate_playground_overbroad_demo_baselines_accept_patchgate_rejects():
    at = fresh()
    at.session_state["view"] = "gate"
    at.run()
    at.session_state["gate_start"] = "overbroad"
    at.run()
    at.button(key="verify_btn").click().run()
    assert not at.exception, at.exception
    verdicts = [m.value for m in at.markdown if m.value.startswith("### ")]
    assert verdicts == ["### :material/check_circle: Accept"] * 3 + ["### :material/cancel: Reject"]


def test_invalid_pasted_yaml_shows_error_not_crash():
    at = fresh()
    at.session_state["source"] = "Paste"
    at.session_state["pasted"] = "key: [unclosed"
    at.run()
    assert not at.exception
    assert any("Cannot load" in (e.proto.title or "") or "invalid YAML" in e.value for e in at.error)
