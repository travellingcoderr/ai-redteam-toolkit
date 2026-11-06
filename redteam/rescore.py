"""Re-apply the current detectors to a saved report without calling the model again.

Useful after fixing a detector false positive/negative:
  python -m redteam.rescore results/qwen2.5-0.5b-none.json

Responses stored at the length cap (possibly truncated) keep their original findings.
runaway_output needs finish_reason, so an original runaway finding is always kept.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.detectors import run_detectors
from redteam.report import write_markdown
from redteam.runner import OWASP_NAMES, detector_ctx, load_config

STORED_LIMITS = (600, 2000)


def rescore(path: Path, attacks_path: str) -> dict:
    cfg = load_config(attacks_path)
    by_id = {a["id"]: a for a in cfg["attacks"]}
    report = json.loads(path.read_text())
    changed = []
    for r in report["results"]:
        atk = by_id[r["id"]]
        if len(r["response"]) in STORED_LIMITS:
            continue
        ctx = detector_ctx(cfg)
        ctx.attack_text = atk["prompt"] + "\n" + (atk.get("context") or "")
        extra = [d for d in (atk.get("detect") or []) if d != "runaway_output"]
        findings = run_detectors(r["response"], ctx, extra) + [f for f in r["findings"] if f.startswith("runaway")]
        if findings != r["findings"]:
            changed.append((r["id"], r["findings"], findings))
        r["findings"], r["defended"] = findings, not findings
    res = report["results"]
    report["score"] = round(sum(x["defended"] for x in res) / len(res), 3)
    for key, field in (("by_category", "category"), ("by_owasp", "owasp")):
        buckets = {}
        for x in res:
            b = buckets.setdefault(x[field], [0, 0])
            b[0] += x["defended"]
            b[1] += 1
        report[key] = {k: {**({"name": OWASP_NAMES.get(k, k)} if key == "by_owasp" else {}),
                           "defended": v[0], "total": v[1], "score": round(v[0] / v[1], 3)} for k, v in sorted(buckets.items())}
    report["passed"] = report["score"] >= report["threshold"] and report["benign_pass_rate"] >= report["min_benign"]
    report["rescored"] = [{"id": i, "before": b, "after": a} for i, b, a in changed]
    path.write_text(json.dumps(report, indent=2))
    write_markdown(report, path.with_suffix(".md"))
    return report


if __name__ == "__main__":
    attacks = str(Path(__file__).with_name("attacks.yaml"))
    for p in sys.argv[1:]:
        rep = rescore(Path(p), attacks)
        print(f"{p}: score={rep['score']:.1%} changed={rep['rescored']}")
