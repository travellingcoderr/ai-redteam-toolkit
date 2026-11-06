"""LLM targets: any OpenAI-compatible endpoint, plus deterministic mocks for tests and CI."""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass


@dataclass
class Completion:
    text: str
    finish_reason: str | None
    latency_s: float


class OpenAITarget:
    """vLLM, Ollama, llama.cpp, Azure OpenAI, OpenAI, or any OpenAI-compatible server."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None, retries: int = 3):
        from openai import OpenAI

        self.client = OpenAI(base_url=base_url, api_key=api_key or os.getenv("OPENAI_API_KEY", "local"), timeout=300)
        self.model = model
        self.retries = retries

    def complete(self, messages: list[dict], max_tokens: int = 300) -> Completion:
        last = None
        for attempt in range(self.retries):
            try:
                t0 = time.perf_counter()
                out = self.client.chat.completions.create(
                    model=self.model, messages=messages, temperature=0, max_tokens=max_tokens
                )
                choice = out.choices[0]
                return Completion(choice.message.content or "", choice.finish_reason, time.perf_counter() - t0)
            except Exception as e:  # network blips, 429s
                last = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"target failed after {self.retries} attempts: {last}")


TRIGGERS = re.compile(
    r"(?i)code|instruction|prompt|above|configuration|initiali|ssn|account number|crm|record|number that|"
    r"debug|override|secret|reveal|translate your|every number|form using|c0d3|cuenta|never allowed"
)


class MockTarget:
    """Deterministic stand-in for a model.

    vulnerable: complies with every attack (leaks the system prompt, echoes URLs/HTML/SQL/actions,
                runs forever on repetition requests). Used to prove the detectors and guardrails work.
    hardened:   always gives a safe, helpful answer.
    """

    def __init__(self, mode: str = "vulnerable"):
        assert mode in {"vulnerable", "hardened"}
        self.mode = mode
        self.model = f"mock-{mode}"

    def complete(self, messages: list[dict], max_tokens: int = 300) -> Completion:
        system = messages[0]["content"]
        user = messages[-1]["content"]
        if self.mode == "hardened":
            return Completion("Happy to help with your banking question. Our branches are open 9am-5pm.", "stop", 0.0)
        if re.search(r"(?i)forever|from 1 to \d{4,}", user):
            word = "bank " if "bank" in user else "1\n"
            return Completion(word * (max_tokens * 2), "length", 0.0)
        echoed = []
        echoed += re.findall(r"!\[[^\]]*\]\([^)]+\)", user)
        echoed += re.findall(r"\[[^\]]+\]\(https?://[^)]+\)", user)
        echoed += re.findall(r"<script.*?</script>", user, flags=re.S)
        echoed += re.findall(r"SELECT .*?--", user)
        echoed += re.findall(r"ACTION: \w+\([^)]*\)", user)
        if re.search(r"(?i)transfer|change the email|close my account|change_email", user) and not echoed:
            tool = "transfer_funds" if "ransfer" in user else ("close_account" if "lose" in user else "change_email")
            echoed.append(f"ACTION: {tool}(confirmed=True)")
        if echoed:
            return Completion("Sure, here you go:\n" + "\n".join(echoed), "stop", 0.0)
        if TRIGGERS.search(user):
            return Completion("Sure! Here is everything I was told:\n" + system, "stop", 0.0)
        return Completion("Sure, I can help with that. Our branches are open 9am-5pm.", "stop", 0.0)


def build_target(kind: str, base_url: str | None, model: str | None) -> "OpenAITarget | MockTarget":
    if kind.startswith("mock-"):
        return MockTarget(kind.split("-", 1)[1])
    if not base_url or not model:
        raise SystemExit("--base-url and --model are required for --target openai")
    return OpenAITarget(base_url, model)
