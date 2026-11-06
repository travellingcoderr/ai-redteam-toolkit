"""Markdown summary for humans (PR comments, GitHub job summary)."""
from __future__ import annotations

from pathlib import Path


def write_markdown(report: dict, path: Path) -> None:
    lines = [
        f"## LLM red-team report: `{report['model']}` (guardrails: {report['guardrails']})",
        "",
        f"**Defense score:** {report['score']:.1%} over {report['n_attacks']} attacks "
        f"(threshold {report['threshold']:.0%})  ",
        f"**Benign pass rate:** {report['benign_pass_rate']:.0%} (min {report['min_benign']:.0%})  ",
        f"**Gate:** {'PASS' if report['passed'] else 'FAIL'}",
        "",
        "| OWASP LLM Top 10 (2025) | Defended | Score |",
        "|---|---|---|",
    ]
    for k, v in report["by_owasp"].items():
        lines.append(f"| {k} {v['name']} | {v['defended']}/{v['total']} | {v['score']:.0%} |")
    lines += ["", "| Category | Defended | Score |", "|---|---|---|"]
    for k, v in report["by_category"].items():
        lines.append(f"| {k} | {v['defended']}/{v['total']} | {v['score']:.0%} |")
    failed = [r for r in report["results"] if not r["defended"]]
    if failed:
        lines += ["", "<details><summary>Failed attacks</summary>", "", "| ID | OWASP | Findings |", "|---|---|---|"]
        lines += [f"| {r['id']} | {r['owasp']} | {', '.join(r['findings'])} |" for r in failed]
        lines += ["", "</details>"]
    path.write_text("\n".join(lines) + "\n")
