# Likely faculty questions and accurate answers

**Q: Isn't this just a Gemini wrapper?**
No. Gemini only *proposes* patches. The contribution is the deterministic acceptance gate in
`verifier.py` and `checks.py`: repair contracts, behavioural invariants, structural validation, and the
feedback loop. It runs and is evaluated entirely without Gemini. You can delete `GeminiProposer` and the
gate, benchmark and tests still work.

**Q: Then why use Gemini at all?**
Some correct repairs need knowledge a template does not have. Making nginx's root filesystem read-only
requires writable `emptyDir` mounts at `/var/cache/nginx` and `/var/run`; a template cannot know that. Gemini
can also read the verifier's rejection reasons and correct its own patch. The gate makes that flexibility
safe to accept automatically.

**Q: What exactly is new compared with GenKubeSec, KubeGuard or `kubescape fix`?**
According to their abstracts and documentation (see RESEARCH.md), GenKubeSec validated remediation by
expert review, KubeGuard outputs recommendations for human review, and kubescape offers dry-run and
interactive approval. PatchGate adds automated, machine-checkable acceptance criteria that test behaviour
preservation, not just finding removal. We do not claim to be the first or only such tool.

**Q: Your gate scores 0% false accepts. Isn't that suspicious?**
Yes, and the docs say so. The mutation taxonomy and the gate have the same author, so the figure shows
coverage of that taxonomy. The meaningful benchmark results are these: the re-lint baseline accepts 71.6% of
harmful candidates; it accepts *all* candidates in 12 of 17 harmful categories; and each ablated component
leaves its own category of false accepts. The independent challenge set, frozen before it was run, shows
PatchGate failing on 4/13 harmful and 3/8 valid cases.

**Q: Was the test set used for tuning?**
No. Seed 7 was the development split. Seed 2026 was run once after development, and the gate was not
changed afterwards. The challenge set was written before its first run. One bug in the challenge-set
*harness* (a YAML indentation error in a test fixture) was fixed; no gate code changed.

**Q: What can't it catch?**
Runtime-only breakage: an image that needs root or writes to its root filesystem, a memory limit that is
too small, a probe that hits the right port with the wrong protocol. These pass, and the tool lists them as
runtime assumptions to validate. A server-side dry-run or a `kind` cluster test would be the next stage.

**Q: How do you stop the LLM from leaking secrets or doing damage?**
- Env values, annotation values and secret-like args are redacted before sending, with paths preserved.
- Model output is parsed against a Pydantic schema and treated as untrusted.
- Only a restricted patch language is executed, never code, shell or SQL.
- Nothing is applied without gate acceptance.
- The input file is never overwritten.
- The audit DB stores a SHA-256 of the manifest, not its contents.

**Q: What if Gemini is down or rate-limited?**
Requests with status 408/429/5xx or timeouts are retried with backoff, a bounded number of times. Auth and
model errors fail fast with an actionable message. A per-run call budget caps spending. If Gemini becomes
unavailable mid-run, the run is marked `degraded` and continues with template fixes, which are still gated.
Tests cover each path with a fake client.

**Q: How much does it cost?**
The core, tests and offline evaluation cost nothing. A Gemini run makes at most
`PATCHGATE_MAX_LLM_CALLS` requests (30 by default); the live study makes at most `--max-calls` (120).
Real token counts are recorded. The 22-finding live study used 27 requests (21,158 input and 2,539
output tokens) on the free tier, at no cost. The free tier's limit of 20 requests per day per model is the real
constraint on larger studies.

**Q: Why JSON Patch instead of letting Gemini rewrite the YAML?**
A patch makes every change enumerable, and that is what makes scope and invariant checking possible. A
rewritten file would need fragile diffing, and it would let the model silently reformat or drop content.

**Q: Why are hostPath and `:latest` not auto-fixed?**
Every possible fix changes behaviour: where data lives, or which software version runs. PatchGate's rule is
to escalate rather than guess.

**Q: Could this be deployed for real?**
As a CI step, `patchgate verify` and `patchgate scan --fail-on high` are usable today on plain manifests.
For production it would need Helm/Kustomize rendering, more controls, and a runtime validation stage.
It is a working prototype, not a production-hardened product.
