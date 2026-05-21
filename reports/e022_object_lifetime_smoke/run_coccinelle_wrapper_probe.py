#!/usr/bin/env python3
"""Run Coccinelle wrapper-candidate patterns over materialized windows.

Wrapper candidates are parser-backed hints for rule engineering and model views.
They are not lifecycle truth and do not promote labels by themselves.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORK = ROOT.parents[1] / ".tools" / "e022-coccinelle-wrapper-windows"
COCCI = ROOT / "coccinelle_patterns" / "wrapper_candidates.cocci"


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def write_json(path: Path, row: dict) -> None:
    with path.open("w") as fh:
        json.dump(row, fh, indent=2, sort_keys=False)
        fh.write("\n")


def parse_matches(output: str) -> list[dict]:
    matches = []
    for line in output.splitlines():
        if not line.startswith("VS_COCCI_WRAPPER\t"):
            continue
        _, callee, role, file, line_no = line.split("\t", 4)
        matches.append(
            {
                "callee": callee,
                "role": role,
                "tool_file": file,
                "tool_line": int(line_no),
                "evidence_strength": "wrapper_candidate_only",
            }
        )
    return matches


def materialize_window(candidate_id: str, view: str, text: str) -> Path:
    path = WORK / f"{candidate_id}_{view}.c"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n")
    return path


def run_spatch(path: Path) -> tuple[int, str, str]:
    result = subprocess.run(
        ["spatch", "--very-quiet", "--sp-file", str(COCCI), str(path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.returncode, result.stdout, result.stderr


def main() -> int:
    rows = load_jsonl(ROOT / "source_windows_20_materialized.jsonl")
    output_rows = []
    for row in rows:
        for view, key in [("vulnerable", "vulnerable_window"), ("fixed", "fixed_window")]:
            path = materialize_window(row["candidate_id"], view, row.get(key, ""))
            returncode, stdout, stderr = run_spatch(path)
            matches = parse_matches(stdout)
            output_rows.append(
                {
                    "candidate_id": row["candidate_id"],
                    "task_id": row["task_id"],
                    "view": view,
                    "tool": "Coccinelle",
                    "pattern": str(COCCI.relative_to(ROOT)),
                    "source_window_file": str(path.relative_to(ROOT.parents[1])),
                    "status": "matched" if matches else "no_match_or_parse_incomplete",
                    "returncode": returncode,
                    "matches": matches,
                    "stderr_tail": stderr[-2000:],
                    "limitations": [
                        "Runs over bounded materialized source windows, not full translation units.",
                        "Wrapper-name matches are parser-backed candidates, not lifecycle truth.",
                        "No label promotion is allowed without a separate rule policy.",
                    ],
                }
            )

    write_jsonl(ROOT / "coccinelle_wrapper_candidate_matches_20.jsonl", output_rows)
    summary = {
        "candidate_windows": len(rows),
        "view_runs": len(output_rows),
        "matched_view_runs": sum(1 for row in output_rows if row["matches"]),
        "match_count": sum(len(row["matches"]) for row in output_rows),
        "tool": "Coccinelle",
        "pattern": str(COCCI.relative_to(ROOT)),
        "label_promotion": "none",
    }
    write_json(ROOT / "coccinelle_wrapper_candidate_summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
