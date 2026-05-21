#!/usr/bin/env python3
"""Run the automated evidence-generation pass for the 20-task smoke dataset."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent


STEPS = [
    ["python3", "reports/e022_object_lifetime_smoke/check_tool_capabilities.py"],
    ["python3", "reports/e022_object_lifetime_smoke/promote_codeql_conditional_labels.py"],
    ["python3", "reports/e022_object_lifetime_smoke/run_coccinelle_window_probe.py"],
    ["python3", "reports/e022_object_lifetime_smoke/run_coccinelle_wrapper_probe.py"],
    ["python3", "reports/e022_object_lifetime_smoke/analyze_promotion_failures_20.py"],
    ["python3", "reports/e022_object_lifetime_smoke/derive_rule_gap_report_20.py"],
    ["python3", "reports/e022_object_lifetime_smoke/run_joern_window_graph_probe.py"],
    ["python3", "reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py"],
]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def main() -> int:
    repo = ROOT.parents[1]
    steps = list(STEPS)
    if os.environ.get("VS_RUN_CODEQL_V2") == "1":
        env_task = os.environ.get("VS_CODEQL_V2_TASK", "vs-smoke-T0005")
        steps.append(
            [
                "python3",
                "reports/e022_object_lifetime_smoke/run_codeql_v2_probe.py",
            ]
        )
    else:
        env_task = None

    run_rows = []
    for step in steps:
        env = os.environ.copy()
        if step[-1].endswith("run_codeql_v2_probe.py"):
            env.setdefault("VS_ONLY_TASKS", env_task or "vs-smoke-T0005")
            env.setdefault("VS_OUTPUT_SUFFIX", "_automation")
        result = subprocess.run(
            step,
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        run_rows.append(
            {
                "step": " ".join(step),
                "status": "completed" if result.returncode == 0 else "failed",
                "returncode": result.returncode,
                "stdout_tail": result.stdout[-2000:],
                "stderr_tail": result.stderr[-2000:],
            }
        )
        if result.returncode != 0:
            break

    write_jsonl(ROOT / "evidence_automation_20_run_log.jsonl", run_rows)
    return 0 if all(row["status"] == "completed" for row in run_rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
