# Testing

## Strategy

| Area | File | What is covered |
|---|---|---|
| Loader & patch engine | `tests/test_manifest_and_patch.py` | multi-doc / `List` expansion; alias-bomb refusal; size/shape errors; pod-spec paths; every op type; `~0`/`~1` escaping; refused ops (`move`, missing `value`, > 40 ops); atomic failure; leaf diff |
| Controls & template fixes | `tests/test_checks_and_fixers.py` | detection and pod→container inheritance; capability rules; manual controls; pattern matching; `set_ops`; **every template fix on every example passes the gate** |
| Gate | `tests/test_verifier.py` | accept minimal fix; scope rejects over-broad rewrite that relint accepts; invariants for image, labels, replicas, env and mounts; string booleans; limits < requests; probe ports; hostPath scratch; emptyDir accepted; undefined mount; removal-as-fix; no-op / unapplicable / non-list patches; only *new* structural errors count; quantity parser |
| Gemini integration (mocked) | `tests/test_llm.py` | schema parsing incl. fenced JSON and 5 malformed shapes; redaction preserves paths; prompt has no secret and does include scope and feedback; config passed to SDK; retry on 503/429 then success; no retry on 403 with actionable message; bounded retries; call budget; malformed output → failed attempt; placeholder key → `ConfigError`; bad numeric env |
| Repair loop & persistence | `tests/test_repair_store.py` | reject → feedback → accept; input never mutated; outage → degraded + template fallback, model not called again; no-fallback path; demo end state; reported patches reproduce output; audit round-trip, survives reopen, manifest contents not stored |
| API, CLI, evaluation | `tests/test_api_cli_eval.py` | `/health`, `/controls`, `/scan` (422 on bad YAML), `/verify` compare (404/422), `/repair` + `/runs`, Gemini-without-key → 400; CLI exit codes, outputs, refusal to overwrite the input, verify; corpus determinism and metric consistency |
| Dashboard (headless) | `tests/test_ui.py` | Streamlit AppTest: the overview hero carries the measured numbers and its buttons switch views; every view renders with no exception, warning or error; simulated repair gives 13 → 1 findings; gate playground over-broad demo gives 3 × Accept from the baselines and Reject from PatchGate; invalid pasted YAML shows an error instead of crashing |
| Live smoke | `tests/test_live_gemini.py` | real Gemini repair of `nightly-report.yaml` (marker `live`) |

The Gemini client is replaced by a fake object exposing `models.generate_content`. Errors are the real
`google.genai.errors.ServerError` / `ClientError` classes, so retry classification is tested against
the SDK's own types.

## Commands

```bash
python -m pytest
```

```bash
python -m pytest -m live
```

The live test needs `PATCHGATE_LIVE_KEY` set to a real key. It uses a separate variable so that a
developer's `.env` key is never used by accident.

## Actual results (2026-10-29, Windows 11, Python 3.12.3)

```
python -m pytest -q        -> 120 passed, 1 deselected, 1 warning in 14.20s   (2026-10-30, incl. 5 UI tests and 15 audit regressions)
python -m pytest -m live   -> 1 passed, 100 deselected in 71.13s   (2026-10-29, before the UI tests existed; GEMINI_MODEL=gemini-3.5-flash-lite, GEMINI_RPM=5)
```

An earlier `pytest -m live` attempt with `gemini-2.5-flash` **failed**. The key's free-tier daily quota for
that model (20 requests/day, quota id `GenerateRequestsPerDayPerProjectPerModel-FreeTier`) had been used up by
earlier live runs. It was a quota failure, not a code failure.

Six tests are regression tests for bugs that the live runs exposed:
- the server's `retryDelay` was ignored;
- requests were not paced (`GEMINI_RPM`);
- 429 messages were too long;
- a daily-quota delay (hours) triggered pointless retries; it now fails fast;
- truncated output was reported as generic malformed JSON; it is now reported as `MAX_TOKENS`;
- the CLI printed a traceback instead of a message for Gemini errors.

The single warning is a Starlette deprecation notice about `httpx` in the test client; it comes from a
third-party library and does not affect results.

## Manual verification performed

- `pip install -e ".[dev]"` into a fresh venv succeeded.
- `patchgate check-config` reports the missing key. `evaluation.live_eval` without a key exits 2 with instructions.
- `uvicorn patchgate.api:app` was started on 127.0.0.1. `/health` and `/repair` were called over HTTP, and the run
  appeared in `patchgate runs`.
- The Streamlit UI was driven in a browser:
  - Repair on `nightly-report.yaml`: 6 → 0 findings, 3 rejected candidates shown with reasons, diff and downloads.
  - Gate playground: an over-broad rewrite is accepted by all 3 baselines and rejected by PatchGate
    (screenshot `docs/screenshots/gate-playground.jpg`).
  - The Evaluation tab renders the saved results.
- A secret scan of the repository for Google API-key patterns found nothing.

## Known gaps

- **Live Gemini coverage is small.** It consists of:
  - `check-config --live` on two models;
  - two demo repairs on `gemini-2.5-flash`;
  - a 22-finding study over two days (mostly `gemini-3.5-flash-lite`) and the live pytest.

  These confirm that the real SDK accepts `GenerateContentConfig` with a Pydantic `response_schema` and that
  structured output parses. No truncation occurred after `max_output_tokens` was raised to 8192, though only
  on these few calls. The free-tier daily quota (about 20 requests per model) prevents larger runs.
- No property-based or fuzz tests of the patch engine.
- UI tests are headless (AppTest); visual layout was checked manually in a browser at desktop and phone widths.
- No test against a real API server (server-side dry-run).
