# PatchGate: Verified, Behaviour-Preserving Repair of Kubernetes Misconfigurations with LLM-Proposed Patches

*Academic report draft — B.Tech CSE (AI & ML), VIT Vellore.*

## Abstract

Kubernetes manifests frequently contain security misconfigurations. Rule-based linters detect them reliably,
and LLMs can now propose fixes, but whether a fix is correct is usually judged by re-running the linter or by
human review. We show that re-linting accepts patches that resolve a finding while changing what the
workload does: deleting containers, renaming labels that selectors depend on, bumping images, or overwriting
whole security contexts. We present PatchGate. Gemini proposes RFC 6902 patches one finding at a time, and a
deterministic acceptance gate checks each patch for:
- applicability;
- newly introduced schema errors;
- resolution of the target;
- absence of new findings;
- confinement to a per-control repair contract;
- preservation of behavioural invariants.

Rejection reasons are fed back to the model, the number of attempts is bounded, and behaviour-changing
repairs are escalated to a human. On a seeded benchmark of 30,386 labelled candidate patches, the
strongest re-lint baseline accepted 71.6% of harmful candidates, while PatchGate accepted 0% with 0% false
rejections. Ablations show that each gate component catches categories the others miss. A hand-written
challenge set exposes the remaining limits: 4/13 runtime-only breakages pass, and 3/8 legitimate but
out-of-scope fixes are rejected.

## 1. Introduction

Misconfiguration is a leading cause of Kubernetes security incidents (Red Hat 2024). Rahman et al. found 11
categories of security misconfiguration across 2,039 open-source manifests. Detection is a solved
engineering problem: kube-linter, Checkov, Kubescape and SLI-KUBE all handle it. Remediation is not.
Templates such as `kubescape fix` apply fixed edits. LLM-based systems (GenKubeSec, KubeGuard) generate
richer edits but rely on expert or user review. The gap studied here is *automatic acceptance*: when may a
machine-proposed configuration change be applied without a human reading it?

## 2. Problem statement and objectives

Given a manifest *M* and a finding *f*, find a patch *p* such that *f* ∉ scan(p(M)), no new findings
appear, and p(M) behaves like M in every respect not required to resolve *f*. When no such *p* can be
established, refuse. Objectives are listed in the README.

**Target users.**
- Platform and DevOps engineers hardening many manifests;
- CI pipelines that want auto-fix PRs without silent breakage;
- security teams reviewing LLM-generated configuration changes.

**Use cases.**
- Auto-remediation PRs for linter findings;
- gating patches produced by an AI coding assistant (`patchgate verify`);
- batch hardening before adopting the Pod Security Standards "restricted" profile.

**Non-goals.**
- Runtime verification;
- cluster-wide policy (RBAC, NetworkPolicy);
- Helm/Kustomize rendering;
- choosing image versions;
- replacing `hostPath` storage.

## 3. Related work

See [RESEARCH.md](RESEARCH.md) for the screening of five candidate projects and the prior-art table. In short:
- GenKubeSec's remediation was validated by expert review;
- KubeGuard outputs recommendations for human adoption;
- `kubescape fix` applies templates with dry-run and interactive approval.

PatchGate is complementary to all three: it is a verification layer that can sit behind any of them. Program
repair research has long noted that test-passing patches can be wrong (Smith et al. 2015). Re-linting is the
configuration-repair analogue of re-running tests.

## 4. Methodology

1. **Controls with repair contracts.** Each of the 11 controls declares detection logic, allowed edit paths
   (`{ctr}`/`{pod}` placeholders, `*`/`**` wildcards), whether it is auto-repairable, and the runtime
   assumptions its fix relies on.
2. **Restricted patch language.** Only `add`/`remove`/`replace`/`test`, applied atomically. Changed paths are
   computed at leaf level.
3. **Acceptance gate.** G1–G6, detailed in [ARCHITECTURE.md](ARCHITECTURE.md). Every check runs, so a
   rejection lists all of its reasons.
4. **Generative proposer.** Gemini (`gemini-2.5-flash` by default, configurable) receives a redacted resource,
   the finding, the control rationale, the allowed paths, and any previous rejection reasons. It returns
   schema-constrained JSON: ops with `value_json` strings, a rationale, and runtime assumptions.
5. **Loop.** Up to K attempts per finding (default 3), with bounded retries and a per-run call budget. Then
   template fallback, gated the same way. Then escalation.

Gemini contributes candidate generation where templates are weak. For example, for a read-only root
filesystem it can add `emptyDir` mounts at image-specific writable paths (`/var/cache/nginx`, `/var/run`),
which a static template cannot know. It also turns verifier counterexamples into corrected patches. The gate
ensures that this flexibility cannot silently break the workload.

## 5. Implementation

Python 3.12; `google-genai` 2.33; Pydantic for patch and response schemas; PyYAML with an alias-rejecting safe
loader; FastAPI; Streamlit; SQLite audit log. 1,985 lines of application and UI code, 762 lines of
evaluation code and 568 lines of tests (95 tests), counted with `Measure-Object -Line`. See the README for the module map and the commands.

## 6. Experimental results

Summarised from [EVALUATION.md](EVALUATION.md); all numbers were measured.

| Gate | False-accept rate (24,807 harmful) | False-reject rate (5,579 valid) |
|---|---:|---:|
| apply-only | 88.8% | 0% |
| relint-target | 78.5% | 0% |
| relint-full | 71.6% | 0% |
| PatchGate | 0% | 0% |

- **Ablation.** Without structural checks: 0.4% false accepts. Without scope: 2.1%. Without invariants: 2.5%.
- **Self-audit.** Targeted probes found three gate blind spots, now closed as invariants, and 39 benchmark
  items wrongly labelled valid, now corrected. Because the gate changed after the test split was seen, the
  benchmark is reported as a development benchmark (see EVALUATION.md).
- **Challenge set (21 cases).** relint-full: 13/13 false accepts, 0/8 false rejects. PatchGate: 4/13 false
  accepts (all runtime-only), 3/8 false rejects (conservative scope).
- **Overhead.** About 0.15 ms per candidate.
- **Live Gemini, demo manifest** (`gemini-2.5-flash`, free tier, no template fallback):
  - 11 of 12 auto-repairable findings repaired, 10 on the first attempt; the image-tag finding was correctly
    escalated.
  - In an earlier run, verifier feedback turned a rejected patch (an `add` into a missing object) into an
    accepted one.
  - The remaining failure was a list-append to a non-existent list, followed by truncated JSON output.
  - Gemini independently produced the challenge set's runtime blind spot: nginx made read-only without a
    writable `/var/run`. The static gate accepted it and flagged the runtime assumption.
  - The live runs also exposed a rate-limit bug (the server's `retryDelay` was ignored on the 5 requests/min
    free tier). It is now fixed and covered by regression tests.
- **Live Gemini study.** 22 findings over two days, limited by the free tier's 20 requests/day/model
  (20 on `gemini-3.5-flash-lite`, 2 on `gemini-2.5-flash`):
  - 22/22 single-shot patches accepted by PatchGate;
  - 0 malformed outputs;
  - 0 re-lint/PatchGate disagreements (95% upper bound 13.6%);
  - 27 requests, 21,158 input and 2,539 output tokens.

  On simple findings, real Gemini output was minimal and in-contract: the gate caused no false rejects, but it
  also had nothing harmful to catch. H1 remains unsupported at this sample size.

## 7. Discussion and limitations

The 0% result is a coverage statement about a taxonomy the gate's author defined; it is not an estimate of
real-world error rates. The challenge set shows two honest failure modes:
- static checks cannot see runtime needs;
- strict scope rejects some harmless extras.

Both are by design. PatchGate prefers false rejects (a human looks) to false accepts (silent breakage), and it
surfaces runtime assumptions explicitly. Other limitations:
- synthetic workloads;
- non-independent candidates;
- YAML comments are not preserved (the JSON patches can be applied instead).

## 8. Risks and schedule (as planned for a 6–8 week project)

| Week | Work |
|---|---|
| 1 | Problem research, prior-art screening, PSS control selection |
| 2 | Loader, patch engine, controls, unit tests |
| 3 | Gate (structural, scope, invariants), template fixes |
| 4 | Gemini proposer, retries, budget, redaction, repair loop |
| 5 | Benchmark generator, challenge set, ablations |
| 6 | CLI, API, Streamlit UI, audit store |
| 7 | Live Gemini study + manual labelling |
| 8 | Report, demo, buffer |

**Risks.**
- The taxonomy may not reflect real LLM errors (mitigation: live study with manual labels).
- Model or SDK changes (mitigation: model in an env var, SDK isolated in `llm.py`, mocked tests).
- Over-strict scope (mitigation: measured on the challenge set; contracts are data and easy to extend).

**Cost.** The core and the offline evaluation are free. The live study is capped at `--max-calls` requests
(120 by default); actual tokens are reported by the script, and the bill depends on current Gemini pricing
(the free tier may suffice).

## 9. Conclusion

Re-linting is not a sufficient acceptance test for automated configuration repair. A small set of
deterministic, explainable checks — repair contracts, behavioural invariants and structural validation —
rejected every harmful candidate in our taxonomy at negligible cost, while still letting an LLM do the
creative part. Live runs confirm both halves of the argument: Gemini's patches were mostly minimal and
correct, but they also exhibited the failure modes the gate exists for (malformed or unapplicable patches)
as well as the one it cannot see (runtime needs). The next steps are a larger, manually labelled live study
and a server-side dry-run or `kind` runtime stage.

## References

See [RESEARCH.md §4](RESEARCH.md#4-references).
