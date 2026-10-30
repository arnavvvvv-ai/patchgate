# Evaluation

All numbers below were produced by the commands shown, on 2026-10-29 (Windows 11, Python 3.12.3).
Datasets 1 and 2 involve no Gemini calls. Live Gemini results (free-tier key, `gemini-2.5-flash`) are in
the section *Live Gemini runs*.

## Baselines

| Gate | Represents |
|---|---|
| `apply-only` | Naive automation: accept if the patch applies |
| `relint-target` | Re-scan and accept if the targeted finding is gone |
| `relint-full` | Re-scan and accept if the target is gone **and** no new findings appear. This is the strongest check existing remediation pipelines describe, so it is the main baseline. |
| `patchgate` | relint-full + structural + scope + invariants |
| `patchgate-no-{structural,scope,invariants}` | Ablations (RQ3) |

## Dataset 1 — seeded benchmark (RQ1, RQ3)

`evaluation/corpus.py` generates workloads at random but plausibly: 6 kinds, 1–3 containers, ports, env,
requests and limits, partial pod and container security contexts, emptyDir/configMap/hostPath volumes,
probes, and selectors. Every auto-repairable finding then gets labelled candidates:

**Valid (8 categories).**
- the template fix;
- an `add`-op variant;
- pod-level `runAsNonRoot` or seccomp;
- an explicit UID;
- generous limits;
- an HTTP probe on a named port;
- read-only root plus an `/tmp` emptyDir.

**Invalid (17 categories).** Each operator fires only when its precondition guarantees real harm:

| Category | Models | Why harmful |
|---|---|---|
| unapplicable | patch to a non-existent path | cannot apply |
| wrong-container | fix aimed at a neighbouring container | target not fixed |
| over-broad-rewrite | `securityContext` replaced by only the fix key | deletes non-default settings (UID, caps, …) |
| collateral-image-change | fix + image tag bump | different software deployed |
| label-selector-edit | fix + renamed `app` label | controller/Service no longer selects pods |
| container-rewrite | container replaced without env/ports/mounts/args | configuration lost |
| string-boolean | `"false"` instead of `false` | rejected by the API server |
| delete-container | offending container removed | functionality removed |
| remove-ports | ports removed so the probe rule no longer applies | Service routing broken |
| probe-undeclared-port | readiness probe on a port not exposed | pod never Ready |
| limits-below-requests | limits < requests | rejected by the API server |
| hostpath-scratch | hostPath used as scratch for a read-only root | new host exposure |
| hallucinated-field | non-existent field alongside the fix | unknown field / strict validation failure |
| existing-mount-change | existing mountPath moved | application paths break |
| replicas-reset | replicas set to 1 | capacity loss |
| privilege-creep | adds `SYS_PTRACE` while an existing PG005 finding masks it | privilege increase |
| redacted-value-copied | env value overwritten with `<redacted>` | configuration corrupted |

**Split.** Seed **7** (200 workloads) was the development split, used while building the corpus and gate.
Seed **2026** (300 workloads) was first run after development as the test split. The gate was later
changed by the self-audit described below, so seed 2026 is no longer strictly held out.

```bash
python -m evaluation.run_eval --seed 2026 --workloads 300 --out evaluation/results --prefix test_seed2026
```

**Metrics.** The positive class is "harmful patch rejected".
- *False-accept rate* = invalid accepted / invalid.
- *False-reject rate* = valid rejected / valid.
- Reject precision, reject recall and F1.
- Gate latency per candidate (mean and p95, single-threaded, this laptop).

### Results — test split (seed 2026; 30,386 candidates over 2,766 findings: 5,579 valid, 24,807 invalid)

| Gate | False-accept rate | False-reject rate | F1 | Mean ms | p95 ms |
|---|---:|---:|---:|---:|---:|
| apply-only | 0.888 (22041/24807) | 0.000 | 0.201 | 0.300 | 0.418 |
| relint-target | 0.785 (19466/24807) | 0.000 | 0.354 | 0.298 | 0.414 |
| relint-full | 0.716 (17773/24807) | 0.000 | 0.442 | 0.298 | 0.413 |
| **patchgate** | **0.000 (0/24807)** | **0.000 (0/5579)** | **1.000** | 0.446 | 0.677 |
| patchgate − structural | 0.004 (110/24807) | 0.000 | 0.998 | 0.397 | 0.614 |
| patchgate − scope | 0.021 (529/24807) | 0.000 | 0.989 | 0.402 | 0.566 |
| patchgate − invariants | 0.025 (626/24807) | 0.000 | 0.987 | 0.389 | 0.608 |

The dev split (seed 7) gave the same pattern: relint-full 0.717 (10852/15132), PatchGate 0.000/0.000 (`evaluation/dev_results/dev_report.md`).

**Per category, relint-full vs PatchGate (accepted/total).** Relint-full accepts **all** candidates in 12 of the
17 harmful categories:
- collateral-image-change 2726/2726
- label-selector-edit 2766/2766
- container-rewrite 2385/2385
- delete-container 2228/2228
- hallucinated-field 2672/2672
- redacted-value-copied 1641/1641
- existing-mount-change 1001/1001
- replicas-reset 727/727
- privilege-creep 359/359
- limits-below-requests 268/268
- probe-undeclared-port 181/181
- remove-ports 181/181

It catches over-broad-rewrite only partly (accepts 528/1787) and string-boolean mostly (accepts 110/954). It
catches hostpath-scratch, wrong-container and unapplicable completely. PatchGate accepts 0 in every harmful
category. Full table: `evaluation/results/test_seed2026_report.md`.

**Ablation (RQ3): unique catches per component.**
- *Structural* alone catches string booleans that the linter treats as resolved (110; e.g. `privileged: "false"`).
- *Scope* alone catches over-broad rewrites that delete settings without creating findings (494), and privilege
  creep where the capability lands under the PG002 fix (35).
- *Invariants* alone catch limits below requests (268), probes on undeclared ports (181), moved existing mounts
  (161) and some container rewrites (16).

Each component has catches the others miss, so none is redundant on this taxonomy. Removing any one of them
leaves false-accept rates of 0.4–2.5%. Before the audit fixes below, scope alone caught 528 over-broad
rewrites; the new capability invariant now also catches the 34 that drop an allowed capability.

**Cost.** Gate overhead over relint-full is about 0.15 ms per candidate (0.446 vs 0.298 ms mean; timings vary slightly between runs), which is
negligible next to an LLM call.

### Audit fixes after the first test run (2026-10-30)

A self-audit found three kinds of harmful patch the gate accepted. Each is now a gate invariant with
regression tests:
- a capability fix that removes a capability the container is allowed to keep (e.g. `NET_BIND_SERVICE`);
- a new writable mount outside conventional scratch locations (`/tmp`, `/var/tmp`, `/run`, `/var/run`,
  `/var/cache`, `/var/log`), or one that hides an existing mount, either of which can hide files shipped in the
  image;
- a pod-level edit that leaves a container unable to start (it must be non-root but is set to UID 0), or that
  changes the start-up identity of a container that did not have the same finding.

The audit also found a **labelling error in the generator**. It marked "set `runAsNonRoot` at pod level" as a
valid fix even when another container in the pod runs as UID 0, which the kubelet would then refuse to
start. The generator now skips that variant in such pods. That removed 39 wrongly-valid candidates from the
test split (5,618 → 5,579) and 17 from the dev split (3,463 → 3,446). No harmful-candidate counts changed.

**Threat to validity: the gate was changed after the test split had been seen.** The test seed is therefore
no longer strictly held out. The changes close failure modes found by targeted probes, not by inspecting
test-split failures (PatchGate already had 0 false accepts there), but treat the benchmark as a development
benchmark from this point on.

## Dataset 2 — hand-written challenge set (RQ4)

`evaluation/challenge_set.py` has 21 cases on nginx, PostgreSQL and batch-job manifests, written and
**frozen before the first run**. The expected weak spots were written down in the file before running.

```bash
python -m evaluation.challenge_set
```

| | False accepts (of 13 harmful) | False rejects (of 8 valid) |
|---|---:|---:|
| relint-full | 13 | 0 |
| **patchgate** | **4** | **3** |

- **PatchGate false accepts (all runtime-only).** nginx made read-only without `/var/run` and cache
  emptyDirs; postgres forced to UID 10001; a 16 Mi memory limit; an HTTP probe against the PostgreSQL wire port.
  Static analysis cannot know these without image or runtime knowledge. PatchGate surfaces them only as
  "runtime assumptions to validate".
- **PatchGate false rejects (conservative scope).** Adding `runAsGroup` with `runAsUser`; marking an existing
  configMap mount read-only; adding a liveness probe alongside the readiness probe.
- **Correctly rejected, though relint-full accepted them.**
  - dropping NET_BIND_SERVICE;
  - inlining a literal password in place of a secretKeyRef;
  - rewriting args;
  - swapping a configMap volume for emptyDir;
  - changing StatefulSet `serviceName`;
  - changing Job `restartPolicy`;
  - Localhost seccomp with no profile;
  - a probe with two handlers;
  - CPU `"half"`.

Results file: `evaluation/results/challenge_set.json`.

## Live Gemini runs — demo manifest (`examples/web-app.yaml`, 13 findings)

```bash
patchgate repair examples\web-app.yaml --proposer gemini --no-fallback --out data\web-app.gemini.yaml --report data\web-app.gemini.json
```

Run with `--no-fallback`, so every accepted change came from Gemini itself.

| Run | Setting | Outcome |
|---|---|---|
| 1 | default retries (1/2/4 s backoff) | 4 repaired, then a **429** (free tier: 5 requests/min). Retries exhausted in seconds, so the run was marked *degraded* and Gemini was not called again. **Bug found:** the server's `retryDelay: 52s` was ignored. |
| 2 | after the fix, `GEMINI_RPM=5` | **11 of 12 auto-repairable findings repaired, 10 on the first attempt**; 1 unrepaired; PG009 (untagged image) correctly escalated as manual; findings 13 → 2 |

What the gate saw in real Gemini output:
- **Feedback loop works (run 1).** For PG002 on `log-shipper`, attempt 1 tried to add into a
  `securityContext` that did not exist and was rejected at *apply*. Attempt 2, given that reason, was accepted.
- **Unrepaired case (run 2, PG006 `log-shipper`).**
  - Attempt 1 was a sensible fix (read-only root plus a `/tmp` emptyDir), but it appended to a
    `volumeMounts` list the container did not have. That is an RFC 6902 error, and the gate rejected it at *apply*.
  - Attempts 2 and 3 were **truncated JSON** (`EOF while parsing`, about 210 characters). The likely cause:
    `max_output_tokens=2048` was consumed by the model's internal reasoning. This was raised to 8192
    afterwards; the run was not repeated.
- **Real instance of the static blind spot.** For PG006 on `web` (nginx), Gemini set
  `readOnlyRootFilesystem: true` without adding a writable `/var/run`. The gate accepted it, because it is
  statically valid, and listed the runtime assumption "every path the process writes to must be covered by
  a writable volume mount". This is exactly the challenge-set case `rt-nginx-readonly-no-run-dir`. nginx
  would probably fail to start with this patch; that was not tested on a cluster.
- Accepted patches were minimal and in-contract. For example, for PG003 on `web` Gemini removed
  `runAsUser: 0` and set `runAsNonRoot: true`. Gemini also wrote its own runtime assumptions, such as
  "the application serves HTTP traffic on port 8080 at '/'".

**Fixes made because of these runs** (with regression tests in `tests/test_llm.py`):
- honour the server-supplied `RetryInfo.retryDelay`, capped by `GEMINI_MAX_BACKOFF_S`;
- optional client-side pacing via `GEMINI_RPM`;
- 429 errors give a short message that suggests `GEMINI_RPM`;
- `max_output_tokens` raised to 8192, and truncated output is now reported as `MAX_TOKENS`;
- a server `retryDelay` longer than `GEMINI_MAX_BACKOFF_S` (daily quota) now fails fast instead of retrying;
- the CLI reports Gemini errors as a message (exit 2), not a traceback.

This is a single manifest and a single model, so these are observations, not rates.

## Dataset 3 — live Gemini study (RQ2) — 22 findings over two days

### Combined result (all runs; `python -m evaluation.merge_live`)

| Measure | Value |
|---|---:|
| Findings (20 × `gemini-3.5-flash-lite`, 2 × `gemini-2.5-flash`) | 22 |
| Controls covered | PG001–PG007, PG010, PG011 |
| LLM requests / tokens in / tokens out | 27 / 21,158 / 2,539 |
| Malformed single-shot outputs | 0 |
| Single-shot accepted by relint-full | 22/22 |
| Single-shot accepted by PatchGate | 22/22 |
| Relint-accepted but PatchGate-rejected | **0/22** (95% upper bound: 13.6% by the rule of three) |

**What this means.** For these mostly single-field findings on generated workloads, real Gemini patches
were minimal and in-contract. They needed no feedback, and the gate rejected none of them, so no false
rejects were observed. The study did **not** reproduce the harmful edits of the synthetic taxonomy. So on
simple findings, PatchGate's value is as a safety net that costs nothing when the model behaves. Its value is
not that Gemini often misbehaves here.

Still untested:
- whether harmful edits appear on harder cases: multi-container rewrites, unusual manifests, other proposers
  such as coding assistants;
- whether feedback helps at scale.

The demo-manifest runs above remain the only real cases of a rejection being corrected, and of a runtime-only
breakage that the gate cannot see.

Run files:
- `results/live_gemini_3.5-flash-lite.json` (8 findings, day 1)
- `results/live_gemini_3.5-flash-lite_seed100.json` (12 findings, day 2)
- `results/live_gemini_2.5-flash_partial.json` and `results/live_gemini_2.5-flash_seed101.json` (1 finding
  each; both stopped by the daily quota)
- `results/live_gemini_combined.json` (merged)

### Day 1 detail

The planned run was 30 findings with at most 120 calls. The key's free tier allows only **20 requests per day
per model**, so it could not run as planned.

- **`gemini-2.5-flash`** (`--findings 20 --max-calls 60`): stopped after 1 finding with
  `GenerateRequestsPerDayPerProjectPerModel-FreeTier` (limit 20, `retryDelay` 76,310 s). That finding
  (PG001) was accepted single-shot by both gates. Saved in `results/live_gemini_2.5-flash_partial.json`.
- **`gemini-3.5-flash-lite`** (`gemini-2.5-flash-lite` returned 404, "no longer available to new users").
  The run below had a separate per-model quota:

```bash
set GEMINI_MODEL=gemini-3.5-flash-lite
set GEMINI_RPM=5
python -m evaluation.live_eval --findings 8 --attempts 3 --max-calls 18 --out evaluation/results/live_gemini_3.5-flash-lite.json
```

| Measure (8 findings, one per control PG001–PG007, PG010) | Value |
|---|---:|
| LLM calls | 8 |
| Tokens in / out | 7,801 / 914 |
| Malformed single-shot outputs | 0 |
| Single-shot accepted by relint-full | 8/8 |
| Single-shot accepted by PatchGate | 8/8 |
| Relint-accepted but PatchGate-rejected (needs manual label) | 0 |
| Mean attempts when accepted | 1.0 |

**Interpretation.** On these 8 simple findings, Gemini produced no harmful edit that re-lint missed, so the
study gives **no evidence for or against H1**. It does show that the gate did not wrongly reject real
Gemini patches: 0 false rejects observed, so contract strictness did not get in the way here. With every
patch accepted first time, H2 (feedback helps) could not be tested on this run.

The only real-Gemini feedback evidence is from the demo manifest above: one apply-rejection was corrected
on attempt 2, and one finding failed across three attempts. The one real-Gemini *harmful* patch observed (nginx read-only
root without writable `/var/run`) belongs to the runtime-only class that neither gate can see. A
meaningful estimate of real-world catch rates needs a paid tier, or a run spread over several days, with
30 or more findings and manual labels.

Script usage: `python -m evaluation.live_eval --findings 30 --attempts 3 --max-calls 120`

The script samples findings stratified by control from a separate seed (99). For each finding it records:
- whether Gemini's single-shot patch is malformed;
- whether it is accepted by relint-full and by PatchGate;
- whether the feedback loop gets an accepted patch within K attempts, and how many attempts that takes;
- prompt and output token counts from `usage_metadata`.

Every relint-accepted, PatchGate-rejected candidate is exported to `needs_manual_label` for a human to judge.
Such a disagreement is a true catch or a false reject, and only a human can tell which.

**Hypotheses, still untested at a useful sample size:**
- H1: a non-trivial share of single-shot Gemini patches pass relint-full but fail PatchGate.
  0 of 22 so far, which leaves a 95% upper bound of 13.6% on simple findings.
- H2: verifier feedback raises the accepted-patch rate over single shot.

The spending bound is `--max-calls` (120 requests by default, retries included). Per-token prices change,
so check the Gemini pricing page; the script prints actual token totals.

## Threats to validity

1. **Construct circularity.** The same person wrote the mutation operators and the gate. The 0% figure shows
   that the gate covers the documented taxonomy; it is *not* an estimate of real-world LLM error rates.
   The challenge set, the live runs and the live study exist to counter this.
2. **Label validity.** Labels come from construction. Operator preconditions make harm likely but not proven;
   for example, a removed `securityContext` field could be harmless in some deployment.
3. **Non-independence.** There are many candidates per finding and per workload, and category sizes differ,
   so the aggregate rates depend on the category mix. Read the per-category table.
4. **Synthetic workloads.** Generated manifests are simpler than real Helm output. The prevalence of each
   control in the corpus is not real-world prevalence.
5. **Static blind spot.** The challenge set shows that runtime-dependent breakage passes the gate.
6. **Single platform.** Latency was measured on one laptop.
