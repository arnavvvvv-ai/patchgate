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


# ---------------------------------------------------------------- regressions for gaps found in the audit

def _hardened(extra_container: dict | None = None) -> dict:
    """A mostly hardened two-container Deployment with nginx keeping NET_BIND_SERVICE."""
    containers = [{
        "name": "nginx", "image": "nginx:1.27", "ports": [{"name": "http", "containerPort": 80}],
        "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
        "readinessProbe": {"tcpSocket": {"port": 80}},
        "volumeMounts": [{"name": "conf", "mountPath": "/etc/nginx/conf.d"}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": False, "runAsUser": 101,
                            "capabilities": {"add": ["NET_BIND_SERVICE"]}},
    }]
    if extra_container:
        containers.append(extra_container)
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
            "spec": {"selector": {"matchLabels": {"app": "web"}}, "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}, "containers": containers,
                         "volumes": [{"name": "conf", "configMap": {"name": "web"}}]}}}}


def finding_for(obj, control, subject):
    f = find_matching(scan_object(obj), (control, 0, subject))
    assert f is not None, (control, subject)
    return f


def test_capability_fix_may_not_remove_allowed_capability():
    obj = _hardened()
    f = finding_for(obj, "PG005", "nginx")
    bad = [{"op": "replace", "path": f"{CTR0}/securityContext/capabilities", "value": {"drop": ["ALL"]}}]
    v, _ = verify(obj, f, bad)
    assert not v.accepted and any("allowed to keep" in r for r in v.reasons)
    good = [{"op": "add", "path": f"{CTR0}/securityContext/capabilities/drop", "value": ["ALL"]}]
    assert verify(obj, f, good)[0].accepted


@pytest.mark.parametrize("path,ok", [
    ("/tmp", True), ("/var/cache/nginx", True), ("/var/run", True), ("/run/nginx", True),
    ("/usr/share/nginx/html", False), ("/app", False), ("/etc", False), ("/var/lib/data", False),
])
def test_new_writable_mounts_limited_to_scratch_locations(path, ok):
    obj = _hardened()
    f = finding_for(obj, "PG006", "nginx")
    patch = [{"op": "replace", "path": f"{CTR0}/securityContext/readOnlyRootFilesystem", "value": True},
             {"op": "add", "path": f"{POD}/volumes/-", "value": {"name": "scratch", "emptyDir": {}}},
             {"op": "add", "path": f"{CTR0}/volumeMounts/-", "value": {"name": "scratch", "mountPath": path}}]
    v, _ = verify(obj, f, patch)
    assert v.accepted is ok, (path, v.reasons)


def test_new_mount_may_not_hide_existing_mount():
    obj = _hardened()
    obj["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append({"name": "conf", "mountPath": "/var/cache/nginx/conf"})
    obj["spec"]["template"]["spec"]["volumes"].append({"name": "c2", "emptyDir": {}})
    obj["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][-1]["name"] = "c2"
    f = finding_for(obj, "PG006", "nginx")
    patch = [{"op": "replace", "path": f"{CTR0}/securityContext/readOnlyRootFilesystem", "value": True},
             {"op": "add", "path": f"{POD}/volumes/-", "value": {"name": "cache", "emptyDir": {}}},
             {"op": "add", "path": f"{CTR0}/volumeMounts/-", "value": {"name": "cache", "mountPath": "/var/cache"}}]
    v, _ = verify(obj, f, patch)
    assert not v.accepted and any("hides the existing mount" in r for r in v.reasons)


ROOT_SIDECAR = {"name": "legacy", "image": "legacy/app:1.0", "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": True}}


def test_pod_level_fix_that_makes_another_container_unstartable_is_rejected():
    obj = _hardened(dict(ROOT_SIDECAR))
    f = finding_for(obj, "PG003", "nginx")
    patch = [{"op": "add", "path": f"{POD}/securityContext/runAsNonRoot", "value": True}]
    v, _ = verify(obj, f, patch)
    assert not v.accepted and any("refused at start" in r for r in v.reasons)
    assert verify(obj, f, patch, GATES["relint-full"])[0].accepted  # re-linting cannot see it


def test_pod_level_change_to_container_without_the_finding_is_rejected():
    clean = {"name": "metrics", "image": "prom/x:1", "resources": {"limits": {"cpu": "50m", "memory": "32Mi"}},
             "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False,
                                 "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": True}}
    obj = _hardened(clean)
    obj["spec"]["template"]["spec"]["securityContext"]["runAsUser"] = 2000  # metrics inherits UID 2000
    f = finding_for(obj, "PG003", "nginx")
    patch = [{"op": "replace", "path": f"{POD}/securityContext/runAsUser", "value": 10001},
             {"op": "add", "path": f"{CTR0}/securityContext/runAsNonRoot", "value": True}]
    v, _ = verify(obj, f, patch)
    assert not v.accepted and any("alters container 'metrics'" in r for r in v.reasons)


def test_pod_level_fix_shared_by_all_affected_containers_is_still_accepted():
    plain = {"name": "worker", "image": "acme/worker:2", "resources": {"limits": {"cpu": "50m", "memory": "32Mi"}},
             "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                                 "readOnlyRootFilesystem": True}}
    obj = _hardened(plain)
    f = finding_for(obj, "PG003", "nginx")  # both containers lack runAsNonRoot, so both have the finding
    patch = [{"op": "add", "path": f"{POD}/securityContext/runAsNonRoot", "value": True}]
    v, _ = verify(obj, f, patch)
    assert v.accepted, v.reasons
