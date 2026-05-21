#!/usr/bin/env python3
"""Materialize the 20 smoke candidates into VulnSignal dataset rows."""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PATCH_METADATA = ROOT / "patch_metadata_20_tasks.jsonl"
TASK_MATERIALIZATION = ROOT / "task_instances_20_candidate_materialization.jsonl"


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


def fetch_text(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "VulnSignal-materializer/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


def raw_url(repo: str, commit: str, path: str) -> str:
    return f"{repo}/plain/{urllib.parse.quote(path)}?id={urllib.parse.quote(commit, safe='')}"


def patch_url(repo: str, commit: str) -> str:
    return f"{repo}/patch/?id={commit}"


def parse_patch(patch: str) -> list[dict]:
    file_path: str | None = None
    hunks: list[dict] = []
    current: dict | None = None

    hunk_re = re.compile(r"@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<header>.*)")

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            file_path = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else None
            current = None
            continue

        match = hunk_re.match(line)
        if match and file_path and file_path.endswith(".c"):
            current = {
                "file": file_path,
                "old_start": int(match.group("old_start")),
                "old_count": int(match.group("old_count") or "1"),
                "new_start": int(match.group("new_start")),
                "new_count": int(match.group("new_count") or "1"),
                "hunk_header": match.group("header").strip(),
                "added_lines": [],
                "removed_lines": [],
            }
            hunks.append(current)
            continue

        if current is None:
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            current["added_lines"].append(line[1:])
        elif line.startswith("-"):
            current["removed_lines"].append(line[1:])

    return hunks


def guess_function(header: str, added: list[str], removed: list[str]) -> str | None:
    candidates = [header, *added, *removed]
    patterns = [
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=",
    ]
    blacklist = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "IS_ERR",
        "WARN_ON",
        "BUG_ON",
    }
    for text in candidates:
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                name = match.group(1)
                if name not in blacklist and not name.isupper():
                    return name
    return None


def source_window(source: str, start: int, count: int, radius: int = 8) -> dict:
    lines = source.splitlines()
    if not lines:
        return {"line_start": start, "line_end": start, "text": "", "status": "missing_source"}
    line_start = max(1, start - radius)
    line_end = min(len(lines), start + max(count, 1) + radius)
    text = "\n".join(lines[line_start - 1 : line_end])
    return {"line_start": line_start, "line_end": line_end, "text": text, "status": "extracted"}


def family_role(candidate_family: str) -> str:
    mapping = {
        "kref_refcount": "primary_refcount_lifecycle_candidate",
        "rcu_lifetime": "primary_rcu_lifecycle_candidate",
        "async_work_lifetime": "primary_async_lifecycle_candidate",
        "publish_remove_lifetime": "primary_publish_remove_lifecycle_candidate",
        "uaf_lifecycle_general": "primary_lifecycle_candidate",
    }
    return mapping.get(candidate_family, "primary_lifecycle_candidate")


def main() -> int:
    patch_rows = load_jsonl(PATCH_METADATA)
    task_rows_by_id = {row["task_id"]: row for row in load_jsonl(TASK_MATERIALIZATION)}

    candidate_rows: list[dict] = []
    hunk_rows: list[dict] = []
    source_window_rows: list[dict] = []
    label_rows: list[dict] = []
    source_snapshot_rows: list[dict] = []
    fetch_rows: list[dict] = []

    candidate_index = 1
    hunk_index = 1

    for patch_row in patch_rows:
        task_id = patch_row["task_id"]
        task = task_rows_by_id.get(task_id, {})
        repo = patch_row["repository_url"]
        commit = patch_row["fixed_commit"]
        vulnerable_ref = f"{commit}^"
        status, patch = fetch_text(patch_url(repo, commit))
        hunks = parse_patch(patch) if status == 200 else []

        source_snapshot_rows.append(
            {
                "task_id": task_id,
                "source_record_id": task.get("source_record_id"),
                "repository_url": repo,
                "fixed_ref": commit,
                "vulnerable_ref": vulnerable_ref,
                "snapshot_status": "patch_metadata_materialized",
                "files": patch_row.get("changed_c_files", []),
                "limitations": [
                    "Source windows fetched by raw public git endpoint",
                    "Full vulnerable/fixed checker comparison still pending",
                ],
            }
        )

        for hunk in hunks:
            candidate_id = f"vs-smoke-C20-{candidate_index:04d}"
            hunk_id = f"vs-smoke-H20-{hunk_index:04d}"
            candidate_index += 1
            hunk_index += 1
            function = guess_function(hunk["hunk_header"], hunk["added_lines"], hunk["removed_lines"])

            hunk_rows.append(
                {
                    "hunk_id": hunk_id,
                    "task_id": task_id,
                    "candidate_id": candidate_id,
                    "file": hunk["file"],
                    "function_guess": function,
                    "old_start": hunk["old_start"],
                    "old_count": hunk["old_count"],
                    "new_start": hunk["new_start"],
                    "new_count": hunk["new_count"],
                    "hunk_header": hunk["hunk_header"],
                    "added_line_count": len(hunk["added_lines"]),
                    "removed_line_count": len(hunk["removed_lines"]),
                    "added_lines_sample": hunk["added_lines"][:8],
                    "removed_lines_sample": hunk["removed_lines"][:8],
                    "evidence_strength": "patch_confirmed_weak",
                }
            )

            candidate_rows.append(
                {
                    "candidate_id": candidate_id,
                    "task_id": task_id,
                    "candidate_origin": "patch_hunk",
                    "file": hunk["file"],
                    "function": function,
                    "line_start": hunk["new_start"],
                    "line_end": hunk["new_start"] + max(hunk["new_count"], 1) - 1,
                    "candidate_role": family_role(task.get("task_family", "")),
                    "confidence": "medium",
                    "reason": "Patch hunk touches a C source region in an admitted object-lifetime/refcount smoke task.",
                    "patch_hunk_ids": [hunk_id],
                }
            )

            fixed_status, fixed_source = fetch_text(raw_url(repo, commit, hunk["file"]))
            vuln_status, vuln_source = fetch_text(raw_url(repo, vulnerable_ref, hunk["file"]))
            fixed_window = source_window(fixed_source if fixed_status == 200 else "", hunk["new_start"], hunk["new_count"])
            vulnerable_window = source_window(vuln_source if vuln_status == 200 else "", hunk["old_start"], hunk["old_count"])
            fetch_rows.append(
                {
                    "task_id": task_id,
                    "candidate_id": candidate_id,
                    "file": hunk["file"],
                    "fixed_status": fixed_status,
                    "vulnerable_status": vuln_status,
                    "fixed_url": raw_url(repo, commit, hunk["file"]),
                    "vulnerable_url": raw_url(repo, vulnerable_ref, hunk["file"]),
                }
            )
            source_window_rows.append(
                {
                    "candidate_id": candidate_id,
                    "task_id": task_id,
                    "status": "vulnerable_and_fixed_windows_extracted"
                    if fixed_status == 200 and vuln_status == 200
                    else "source_window_fetch_incomplete",
                    "source_kind": "parent_and_fixed_commit_plain_source",
                    "file": hunk["file"],
                    "function": function,
                    "vulnerable_ref": vulnerable_ref,
                    "fixed_ref": commit,
                    "vulnerable_line_start": vulnerable_window["line_start"],
                    "vulnerable_line_end": vulnerable_window["line_end"],
                    "fixed_line_start": fixed_window["line_start"],
                    "fixed_line_end": fixed_window["line_end"],
                    "vulnerable_window": vulnerable_window["text"],
                    "fixed_window": fixed_window["text"],
                    "patch_hunk_ids": [hunk_id],
                    "limitations": [
                        "Function name is best-effort from patch hunk header/content",
                        "Window is line-bounded source context, not a proof of vulnerability",
                    ],
                }
            )

            label_rows.append(
                {
                    "candidate_id": candidate_id,
                    "task_id": task_id,
                    "label": "positive_candidate",
                    "label_strength": "patch_confirmed_weak",
                    "is_final_truth": False,
                    "reason": "Candidate is anchored to a public kernel patch hunk for an admitted CVE task. Checker/oracle validation is still required.",
                    "oracle_status": "not_run",
                    "checker_status": "pending",
                }
            )

    write_jsonl(ROOT / "candidate_locations_20_materialized.jsonl", candidate_rows)
    write_jsonl(ROOT / "patch_hunks_20_materialized.jsonl", hunk_rows)
    write_jsonl(ROOT / "source_windows_20_materialized.jsonl", source_window_rows)
    write_jsonl(ROOT / "labels_20_materialized.jsonl", label_rows)
    write_jsonl(ROOT / "source_snapshots_20_materialized.jsonl", source_snapshot_rows)
    write_jsonl(ROOT / "source_window_fetch_log_20_materialized.jsonl", fetch_rows)

    summary = {
        "task_count": len(patch_rows),
        "candidate_location_count": len(candidate_rows),
        "patch_hunk_count": len(hunk_rows),
        "source_window_count": len(source_window_rows),
        "label_count": len(label_rows),
        "source_window_fetch_failures": sum(
            1 for row in fetch_rows if row["fixed_status"] != 200 or row["vulnerable_status"] != 200
        ),
    }
    (ROOT / "materialization_20_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
