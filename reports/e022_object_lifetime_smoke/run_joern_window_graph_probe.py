#!/usr/bin/env python3
"""Create Joern graph exports for candidate source windows."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
WORK = REPO_ROOT / ".tools" / "e022-joern-windows"
SRC = WORK / "src"
CPG = WORK / "cpg.bin"


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, row: dict) -> None:
    with path.open("w") as fh:
        json.dump(row, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def main() -> int:
    labels = load_jsonl(ROOT / "labels_20_strengthened.jsonl")
    strong_ids = {row["candidate_id"] for row in labels if row.get("label_strength") == "codeql_conditional"}
    windows = [row for row in load_jsonl(ROOT / "source_windows_20_materialized.jsonl") if row["candidate_id"] in strong_ids]

    if WORK.exists():
        shutil.rmtree(WORK)
    SRC.mkdir(parents=True, exist_ok=True)

    materialized = []
    for row in windows:
        for view, key in [("vulnerable", "vulnerable_window"), ("fixed", "fixed_window")]:
            path = SRC / f"{row['candidate_id']}_{view}.c"
            path.write_text(row.get(key, "") + "\n")
            materialized.append(
                {
                    "candidate_id": row["candidate_id"],
                    "task_id": row["task_id"],
                    "view": view,
                    "path": str(path.relative_to(REPO_ROOT)),
                }
            )

    parse = run(["joern-parse", str(SRC), "-o", str(CPG), "--language", "C"])
    run_rows = [
        {
            "step": "joern_parse",
            "status": "completed" if parse.returncode == 0 else "failed",
            "returncode": parse.returncode,
            "stdout_tail": parse.stdout[-2000:],
            "stderr_tail": parse.stderr[-2000:],
        }
    ]

    export_summaries = []
    if parse.returncode == 0:
        for repr_name in ["cfg", "ddg", "cpg14"]:
            out_dir = WORK / f"export_{repr_name}"
            export = run(["joern-export", str(CPG), "--repr", repr_name, "--format", "dot", "-o", str(out_dir)])
            files = sorted(path for path in out_dir.rglob("*") if path.is_file()) if out_dir.exists() else []
            export_summaries.append(
                {
                    "repr": repr_name,
                    "status": "completed" if export.returncode == 0 else "failed",
                    "returncode": export.returncode,
                    "export_dir": str(out_dir.relative_to(REPO_ROOT)),
                    "file_count": len(files),
                    "stdout_tail": export.stdout[-2000:],
                    "stderr_tail": export.stderr[-2000:],
                }
            )
    run_rows.extend({"step": f"joern_export_{row['repr']}", **row} for row in export_summaries)

    write_jsonl(ROOT / "joern_window_graph_run_log_20.jsonl", run_rows)
    write_json(
        ROOT / "joern_window_graph_summary.json",
        {
            "candidate_count": len(strong_ids),
            "source_window_files": len(materialized),
            "parse_status": run_rows[0]["status"],
            "exports": export_summaries,
            "materialized_windows": materialized,
            "limitations": [
                "Runs over bounded source windows for promoted candidates.",
                "Used for automated graph cross-check development, not final truth by itself.",
            ],
        },
    )
    return 0 if parse.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
