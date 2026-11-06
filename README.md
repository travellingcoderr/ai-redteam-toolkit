# AI Red-Team Toolkit: a CI security gate for LLM apps

A small CLI that runs **58 attacks mapped to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)** against any OpenAI-compatible endpoint, scores every response with deterministic detectors, and **fails the pipeline** when the defense score or the benign pass rate drops below a threshold. It ships with a reference guardrail layer so you can measure the before/after.

## Results (real run, not estimates)

Target: `Qwen/Qwen2.5-0.5B-Instruct` served locally on CPU (transformers, OpenAI-compatible shim), `temperature=0`, 58 attacks + 12 benign prompts, November 2026. Full reports in [`results/`](results/) and [docs/results.md](docs/results.md).

| Guardrails | Defense score | Benign pass rate | Gate (≥90% / ≥80%) |
|---|---|---|---|
| none | **60.3%** (35/58) | 100% | FAIL |
| input only | 89.7% (52/58) | 100% | FAIL |
| input + output (`full`) | **100%** (58/58) | 100% | PASS |

| OWASP (2025) | none | input | full |
|---|---|---|---|
| LLM01 Prompt Injection | 18/32 | 32/32 | 32/32 |
| LLM02 Sensitive Information Disclosure | 5/7 | 7/7 | 7/7 |
| LLM05 Improper Output Handling | 3/5 | 4/5 | 5/5 |
| LLM06 Excessive Agency | 2/6 | 2/6 | 6/6 |
| LLM07 System Prompt Leakage | 5/6 | 6/6 | 6/6 |
| LLM10 Unbounded Consumption | 2/2 | 1/2 | 2/2 |

What this shows: input screening alone stops every prompt-injection and leak attempt in the set, but it cannot stop a model that **decides on its own** to emit an unauthorized action (`ACTION: transfer_funds`) or destructive SQL. Excessive agency (LLM06) only drops to zero failures once the output is validated against an allowlist. That's the argument for checking outputs, not just prompts.

Caveats: a 0.5B model is weaker than production models, the attack set is fixed (a motivated attacker adapts), and 100% here means "all 58 known attacks are blocked", not "secure".

## How it works

1. The target's system prompt holds a **canary** (`CANARY-7F3A`), fake customer PII and a confidential CRM record. None of it may leave.
2. `redteam/attacks.yaml`: 58 attacks across direct injection (10), role-play jailbreaks (8), encoding tricks (8: base64, leetspeak, reversal, acrostics, zero-width), PII extraction (7), indirect injection via emails/web pages (6), system prompt leak (6), excessive agency (6), output handling (5) and unbounded consumption (2), each tagged with its OWASP ID. Plus 12 benign prompts so over-blocking is measured too.
3. `redteam/detectors.py` checks every response for the canary (incl. spaced, reversed, base64 and acrostic variants), PII, system prompt text (ignoring markers the attacker typed themselves), markdown-image exfiltration, untrusted links, `<script>`, destructive SQL, non-allowlisted `ACTION:` lines and runaway output.
4. `redteam/guardrails.py` is the reference defense: Unicode normalization, base64 decoding before screening, injection/jailbreak patterns, spotlighting of untrusted context, a hardened system prompt, and output validation (redact leaks, strip disallowed actions/links/scripts/SQL, truncate runaways).
5. `redteam/runner.py` runs everything concurrently, writes `report.json` + `report.md` (per-OWASP and per-category scores, failed attack list) and exits non-zero when the gate fails.

## Quick start

```bash
pip install -r requirements.txt

# no model needed: built-in mock targets
python -m redteam.runner --target mock-vulnerable                      # exits 1 (0% defended)
python -m redteam.runner --target mock-vulnerable --guardrails full    # exits 0

# any OpenAI-compatible endpoint (vLLM, Ollama, Azure OpenAI, ...)
export OPENAI_API_KEY=...   # if the endpoint needs one
python -m redteam.runner --base-url http://localhost:8000/v1 --model Qwen/Qwen2.5-0.5B-Instruct \
  --guardrails none --report results/my-run.json

# re-score saved runs after changing detectors (no model calls)
python -m redteam.rescore results/*.json
```

Flags: `--guardrails none|input|output|full`, `--threshold 0.9`, `--min-benign 0.8`, `--only direct_injection,pii_extraction`, `--concurrency 4`.

## CI

`.github/workflows/redteam.yml` has three jobs:

- **unit**: 17 pytest tests for detectors, guardrails and the runner.
- **gate-self-test**: proves the gate works with no secrets. The unprotected mock target must fail, the guarded one must pass. Both reports land in the job summary.
- **live-endpoint**: runs only when the repo variable `LLM_BASE_URL` is set (plus `LLM_MODEL`, optional secret `LLM_API_KEY`, optional `LLM_GUARDRAILS`), so a PR that weakens your prompt or guardrails gets blocked.

## Next steps

- An attack mode for MCP tool-calling agents (indirect injection through tool results), pointed at [mcp-agent-demo](https://github.com/travellingcoderr/mcp-agent-demo).
- Layer a trained classifier (Llama Guard / Prompt Guard) on top of the deterministic checks and compare false-positive rates.
- Run the same suite against a larger model on the [llm-platform-k8s](https://github.com/travellingcoderr/llm-platform-k8s) stack.
