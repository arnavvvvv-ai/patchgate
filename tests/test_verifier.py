from decimal import Decimal

import pytest

from patchgate.checks import find_matching, scan_object
from patchgate.verifier import GATES, parse_quantity, structural_errors, verify

from .conftest import CTR0, POD


def finding(obj, control, subject="api"):
    f = find_matching(scan_object(obj), (control, 0, subject))
    assert f is not None
    return f


def failed(verdict):
    return {c.name for c in verdict.checks if not c.passed}


GOOD_PG002 = [{"op": "add", "path": f"{CTR0}/securityContext/allowPrivilegeEscalation", "value": False}]


def test_accepts_minimal_fix(deployment):
    v, after = verify(deployment, finding(deployment, "PG002"), GOOD_PG002)
    assert v.accepted and after is not None
    assert v.changed_paths == [f"{CTR0}/securityContext/allowPrivilegeEscalation"]
    assert "PG002:0:api" in v.resolved


def test_over_broad_rewrite_rejected_by_scope_but_not_relint(deployment):
    patch = [{"op": "replace", "path": f"{CTR0}/securityContext", "value": {"allowPrivilegeEscalation": False}}]
    f = finding(deployment, "PG002")
    v, _ = verify(deployment, f, patch)
    assert not v.accepted and "scope" in failed(v)
    assert verify(deployment, f, patch, GATES["relint-full"])[0].accepted


@pytest.mark.parametrize("extra,check", [
    ({"op": "replace", "path": f"{CTR0}/image", "value": "ghcr.io/acme/api:1.0.1"}, "invariants"),
    ({"op": "replace", "path": "/spec/template/metadata/labels/app", "value": "api2"}, "invariants"),
    ({"op": "replace", "path": "/spec/replicas", "value": 1}, "invariants"),
    ({"op": "replace", "path": f"{CTR0}/env/0/value", "value": "<redacted>"}, "invariants"),
    ({"op": "remove", "path": f"{CTR0}/volumeMounts/0"}, "invariants"),
    ({"op": "add", "path": f"{CTR0}/securityContext/hardened", "value": True}, "structural"),
])
def test_collateral_changes_rejected(deployment, extra, check):
    v, _ = verify(deployment, finding(deployment, "PG002"), GOOD_PG002 + [extra])
    assert not v.accepted and check in failed(v)
    assert verify(deployment, finding(deployment, "PG002"), GOOD_PG002 + [extra], GATES["relint-full"])[0].accepted


def test_string_boolean_rejected_structurally(deployment):
    deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
    f = finding(deployment, "PG001")
    patch = [{"op": "replace", "path": f"{CTR0}/securityContext/privileged", "value": "false"}]
    v, _ = verify(deployment, f, patch)
    assert not v.accepted and failed(v) == {"structural"}
    assert verify(deployment, f, patch, GATES["relint-target"])[0].accepted  # linter alone is fooled


def test_limits_below_requests(deployment):
    f = finding(deployment, "PG007")
    bad = [{"op": "add", "path": f"{CTR0}/resources/limits", "value": {"cpu": "100m", "memory": "64Mi"}}]
    assert "invariants" in failed(verify(deployment, f, bad)[0])
    good = [{"op": "add", "path": f"{CTR0}/resources/limits", "value": {"cpu": "1", "memory": "512Mi"}}]
    assert verify(deployment, f, good)[0].accepted


def test_probe_must_target_declared_port(deployment):
    f = finding(deployment, "PG011")
    for port, ok in ((8080, True), ("http", True), (9999, False), ("admin", False)):
        patch = [{"op": "add", "path": f"{CTR0}/readinessProbe", "value": {"httpGet": {"path": "/", "port": port}}}]
        assert verify(deployment, f, patch)[0].accepted is ok, port


def test_new_hostpath_volume_introduces_finding(deployment):
    f = finding(deployment, "PG006")
    patch = [{"op": "add", "path": f"{CTR0}/securityContext/readOnlyRootFilesystem", "value": True},
             {"op": "add", "path": f"{POD}/volumes/-", "value": {"name": "scratch", "hostPath": {"path": "/tmp"}}},
             {"op": "add", "path": f"{CTR0}/volumeMounts/-", "value": {"name": "scratch", "mountPath": "/scratch"}}]
    v, _ = verify(deployment, f, patch)
    assert not v.accepted and {"no-new-findings", "invariants"} <= failed(v)
    assert verify(deployment, f, patch, GATES["relint-target"])[0].accepted


def test_emptydir_for_readonly_root_accepted(deployment):
    f = finding(deployment, "PG006")
    patch = [{"op": "add", "path": f"{CTR0}/securityContext/readOnlyRootFilesystem", "value": True},
             {"op": "add", "path": f"{POD}/volumes/-", "value": {"name": "tmp", "emptyDir": {}}},
             {"op": "add", "path": f"{CTR0}/volumeMounts/-", "value": {"name": "tmp", "mountPath": "/tmp"}}]
    assert verify(deployment, f, patch)[0].accepted


def test_mount_to_undefined_volume_is_structural_error(deployment):
    f = finding(deployment, "PG006")
    patch = [{"op": "add", "path": f"{CTR0}/securityContext/readOnlyRootFilesystem", "value": True},
             {"op": "add", "path": f"{CTR0}/volumeMounts/-", "value": {"name": "ghost", "mountPath": "/tmp"}}]
    assert "structural" in failed(verify(deployment, f, patch)[0])


def test_removal_as_fix_rejected(deployment):
    f = finding(deployment, "PG002", "sidecar")
    v, _ = verify(deployment, f, [{"op": "remove", "path": f"{POD}/containers/1"}])
    assert not v.accepted and "invariants" in failed(v) and "scope" in failed(v)
    assert verify(deployment, f, [{"op": "remove", "path": f"{POD}/containers/1"}], GATES["relint-full"])[0].accepted


def test_unresolved_target_and_noop_and_unapplicable(deployment):
    f = finding(deployment, "PG002")
    assert "target" in failed(verify(deployment, f, [{"op": "add", "path": f"{CTR0}/securityContext/allowPrivilegeEscalation", "value": True}])[0])
    assert "effect" in failed(verify(deployment, f, [{"op": "replace", "path": "/spec/replicas", "value": 2}])[0])
    v, after = verify(deployment, f, [{"op": "replace", "path": "/nope", "value": 1}])
    assert after is None and failed(v) == {"apply"}
    assert failed(verify(deployment, f, "not a patch")[0]) == {"apply"}


def test_structural_errors_only_counts_new_ones(deployment):
    deployment["spec"]["template"]["spec"]["containers"][1]["bogus"] = 1  # pre-existing problem
    assert any("bogus" in e for e in structural_errors(deployment))
    assert verify(deployment, finding(deployment, "PG002"), GOOD_PG002)[0].accepted


@pytest.mark.parametrize("q,expected", [
    ("500m", Decimal("0.5")), ("2", Decimal(2)), ("1.5", Decimal("1.5")), ("256Mi", Decimal(256 * 2**20)),
    ("1G", Decimal(10**9)), (3, Decimal(3)), ("1e3", Decimal(1000)),
    ("half", None), ("-1", None), (True, None), ("10 Mi", None),
])
def test_parse_quantity(q, expected):
    assert parse_quantity(q) == expected
