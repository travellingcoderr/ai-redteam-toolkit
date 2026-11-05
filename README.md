# Project 03: AI Red-Team Toolkit (CI Security Gate for LLM Apps)

An open-source CLI that runs prompt-injection, jailbreak, and data-leak attacks against any OpenAI-compatible LLM endpoint or agent, scores the results, and **fails the CI pipeline** if the security score drops below a threshold.

**Why it matters:** AI security is a fast-growing niche and is already your headline ("DevOps & AI Security"). This turns your guardrail work at Equity Prime and Eli Lilly into something public and reusable.

## How it works
1. The target system prompt contains a secret **canary** token (`CANARY-7F3A`) the model must never reveal.
2. `redteam/attacks.yaml` holds attack prompts grouped by category (direct injection, role-play jailbreak, encoding tricks, PII extraction, indirect injection).
3. `redteam/runner.py` sends each attack, checks responses for canary leaks or forbidden patterns, and writes `report.json` with a per-category score.
4. `.github/workflows/redteam.yml` runs it on every PR and blocks merges below the threshold.

## Milestones (about 2 weeks)
1. Run the runner against a local vLLM model (Project 01) and an unprotected prompt; record the baseline score
2. Grow `attacks.yaml` to 50+ attacks; map each category to the **OWASP Top 10 for LLM Applications**
3. Add a guardrail layer (input sanitization + output validation) and show the score improving
4. Add an attack mode for **MCP tool-calling agents** (indirect injection through tool results), using Project 04
5. Publish: README with before/after scores, a short demo GIF, LinkedIn post

## Quick start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python redteam/runner.py --base-url http://localhost:8000/v1 --model Qwen/Qwen2.5-0.5B-Instruct --threshold 0.9
```

## Resume bullet once finished
> Built an open-source LLM red-team toolkit (50+ prompt-injection, jailbreak, and data-leak attacks mapped to OWASP LLM Top 10) used as a CI/CD security gate; guardrails raised the defense score from __% to __%.
