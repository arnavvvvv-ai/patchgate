import copy

import pytest

from patchgate.checks import CONTROLS, pattern_matches, scan, scan_object
from patchgate.fixers import set_ops, template_fix
from patchgate.manifest import load_manifest
from patchgate.verifier import verify

from .conftest import CTR0, EXAMPLES, POD


def keys(obj):
    return {(f.control_id, f.subject) for f in scan_object(obj)}


def test_detects_expected_controls(deployment):
    k = keys(deployment)
    assert ("PG002", "api") in k and ("PG003", "api") in k and ("PG007", "api") in k
    assert ("PG009", "sidecar") not in k  # busybox:1.36 is pinned
    assert ("PG011", "api") in k and ("PG011", "sidecar") not in k  # sidecar has no ports


def test_root_uid_and_inheritance(deployment):
    deployment["spec"]["template"]["spec"]["securityContext"] = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    k = keys(deployment)
    assert ("PG003", "sidecar") not in k and ("PG010", "sidecar") not in k  # inherited from pod
    deployment["spec"]["template"]["spec"]["containers"][1]["securityContext"] = {"runAsUser": 0}
    assert ("PG003", "sidecar") in keys(deployment)


def test_capabilities_rules(deployment):
    sc = deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    sc["capabilities"] = {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}
    assert ("PG005", "api") not in keys(deployment)
    sc["capabilities"]["add"].append("SYS_ADMIN")
    assert ("PG005", "api") in keys(deployment)


def test_manual_controls_have_no_template(deployment):
    deployment["spec"]["template"]["spec"]["volumes"].append({"name": "h", "hostPath": {"path": "/"}})
    deployment["spec"]["template"]["spec"]["containers"][1]["image"] = "busybox"
    fs = {f.control_id: f for f in scan_object(deployment)}
    assert not CONTROLS["PG008"].auto_repairable and template_fix(deployment, fs["PG008"]) is None
    assert template_fix(deployment, fs["PG009"]) is None


def test_non_workloads_ignored():
    m = load_manifest("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {a: b}\n")
    assert scan(m) == []


@pytest.mark.parametrize("pattern,pointer,ok", [
    ("/a/*/c", "/a/b/c", True),
    ("/a/*/c", "/a/b/d", False),
    ("/a/**", "/a/b/c/d", True),
    ("/a/b", "/a/b/c", False),
    ("/a/b/**", "/a/x", False),
])
def test_pattern_matches(pattern, pointer, ok):
    assert pattern_matches(pattern, pointer) is ok


def test_set_ops_creates_missing_parents(deployment):
    assert set_ops(deployment, f"{CTR0}/securityContext/privileged", False) == [
        {"op": "add", "path": f"{CTR0}/securityContext/privileged", "value": False}]
    assert set_ops(deployment, "/spec/template/spec/containers/1/securityContext/privileged", False) == [
        {"op": "add", "path": "/spec/template/spec/containers/1/securityContext", "value": {"privileged": False}}]
    assert set_ops(deployment, "/spec/replicas", 2) == []


@pytest.mark.parametrize("name", ["web-app.yaml", "node-agent.yaml", "nightly-report.yaml"])
def test_every_template_fix_passes_the_gate(name):
    m = load_manifest((EXAMPLES / name).read_text(encoding="utf-8"))
    for f in scan(m):
        res = m.resources[f.resource_index].obj
        patch = template_fix(res, f)
        if patch is None:
            assert not f.control.auto_repairable
            continue
        verdict, _ = verify(res, f, patch)
        assert verdict.accepted, (f.control_id, f.subject, verdict.reasons)


def test_template_fix_for_pod_root_uid():
    obj = {"kind": "Pod", "metadata": {"name": "p"},
           "spec": {"securityContext": {"runAsUser": 0}, "containers": [{"name": "c", "image": "x:1"}]}}
    f = next(x for x in scan_object(obj) if x.control_id == "PG003")
    verdict, after = verify(copy.deepcopy(obj), f, template_fix(obj, f))
    assert verdict.accepted
    assert after["spec"]["containers"][0]["securityContext"]["runAsUser"] == 10001
    assert POD  # imported for symmetry with other tests
