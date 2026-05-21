#!/usr/bin/env python3
"""Finalize comparison and hard-negative artifacts for the 20-task smoke set."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
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


def fact_key(row: dict) -> tuple[str, str, str, str]:
    return (
        row.get("file") or "",
        row.get("enclosing_function") or "",
        row.get("callee") or "",
        row.get("role") or "",
    )


def fact_summary(rows: list[dict]) -> dict:
    by_role: dict[str, int] = defaultdict(int)
    by_file: dict[str, int] = defaultdict(int)
    for row in rows:
        by_role[row.get("role") or "unknown"] += 1
        by_file[row.get("file") or "unknown"] += 1
    return {
        "row_count": len(rows),
        "roles": dict(sorted(by_role.items())),
        "files": dict(sorted(by_file.items())),
    }


def build_codeql_comparison() -> dict:
    metadata_rows = load_jsonl(ROOT / "patch_metadata_20_tasks.jsonl")
    fixed_rows = load_jsonl(ROOT / "full_source_codeql_facts_combined.jsonl")
    vulnerable_rows = load_jsonl(ROOT / "full_source_codeql_facts_batch_vulnerable_success11.jsonl")
    vulnerable_log_rows = load_jsonl(ROOT / "kbuild_codeql_run_log_vulnerable_success11.jsonl")

    fixed_by_task: dict[str, list[dict]] = defaultdict(list)
    vulnerable_by_task: dict[str, list[dict]] = defaultdict(list)
    for row in fixed_rows:
        fixed_by_task[row["task_id"]].append(row)
    for row in vulnerable_rows:
        vulnerable_by_task[row["task_id"]].append(row)

    vulnerable_status_by_task: dict[str, set[str]] = defaultdict(set)
    for row in vulnerable_log_rows:
        vulnerable_status_by_task[row["task_id"]].add(row.get("status", "unknown"))

    comparison_rows = []
    status_counts: dict[str, int] = defaultdict(int)
    for meta in metadata_rows:
        task_id = meta["task_id"]
        fixed = fixed_by_task.get(task_id, [])
        vulnerable = vulnerable_by_task.get(task_id, [])
        fixed_keys = {fact_key(row) for row in fixed}
        vulnerable_keys = {fact_key(row) for row in vulnerable}

        if fixed and vulnerable:
            status = "fixed_and_vulnerable_compared"
        elif fixed and "db_failed" in vulnerable_status_by_task.get(task_id, set()):
            status = "fixed_available_vulnerable_build_failed"
        elif fixed:
            status = "fixed_available_vulnerable_not_extracted"
        elif vulnerable:
            status = "vulnerable_available_fixed_not_extracted"
        else:
            status = "full_source_extraction_not_available"
        status_counts[status] += 1

        comparison_rows.append(
            {
                "task_id": task_id,
                "cve_or_issue_id": meta.get("cve_or_issue_id"),
                "repository_url": meta.get("repository_url"),
                "fixed_commit": meta.get("fixed_commit"),
                "vulnerable_ref": f"{meta.get('fixed_commit')}^",
                "comparison_status": status,
                "fixed_fact_summary": fact_summary(fixed),
                "vulnerable_fact_summary": fact_summary(vulnerable),
                "common_fact_key_count": len(fixed_keys & vulnerable_keys),
                "fixed_only_fact_key_count": len(fixed_keys - vulnerable_keys),
                "vulnerable_only_fact_key_count": len(vulnerable_keys - fixed_keys),
                "common_fact_keys_sample": [list(key) for key in sorted(fixed_keys & vulnerable_keys)[:10]],
                "fixed_only_fact_keys_sample": [list(key) for key in sorted(fixed_keys - vulnerable_keys)[:10]],
                "vulnerable_only_fact_keys_sample": [list(key) for key in sorted(vulnerable_keys - fixed_keys)[:10]],
                "label_implication": "tool_fact_comparison_only_not_truth_label",
                "limitations": [
                    "This compares lifecycle-call fact presence, not a vulnerability oracle.",
                    "Line numbers can move across vulnerable and fixed views, so the primary comparison key omits line.",
                    "No label is promoted to codeql_conditional without a recorded checker rule.",
                ],
            }
        )

    write_jsonl(ROOT / "codeql_vulnerable_fixed_comparison_20.jsonl", comparison_rows)
    summary = {
        "task_count": len(metadata_rows),
        "fixed_view_fact_tasks": len(fixed_by_task),
        "vulnerable_view_fact_tasks": len(vulnerable_by_task),
        "fixed_view_fact_rows": len(fixed_rows),
        "vulnerable_view_fact_rows": len(vulnerable_rows),
        "comparison_status_counts": dict(sorted(status_counts.items())),
    }
    write_json(ROOT / "codeql_vulnerable_fixed_comparison_20_summary.json", summary)
    return summary


def slice_numbered_text(text: str, window_start: int, start: int, end: int) -> str:
    lines = text.splitlines()
    rel_start = max(0, start - window_start)
    rel_end = min(len(lines), end - window_start + 1)
    if rel_start >= rel_end:
        return ""
    return "\n".join(lines[rel_start:rel_end])


def build_hard_negatives() -> dict:
    candidates = load_jsonl(ROOT / "candidate_locations_20_materialized.jsonl")
    labels = load_jsonl(ROOT / "labels_20_materialized.jsonl")
    windows = load_jsonl(ROOT / "source_windows_20_materialized.jsonl")
    windows_by_candidate = {row["candidate_id"]: row for row in windows}

    hard_candidates = []
    hard_labels = []
    hard_windows = []
    hard_index = 1

    for candidate in candidates:
        window = windows_by_candidate.get(candidate["candidate_id"])
        if not window:
            continue

        spans = [
            ("nearby_before_patch_hunk", max(window["fixed_line_start"], candidate["line_start"] - 5), candidate["line_start"] - 1),
            ("nearby_after_patch_hunk", candidate["line_end"] + 1, min(window["fixed_line_end"], candidate["line_end"] + 5)),
        ]

        for origin, line_start, line_end in spans:
            if line_start > line_end:
                continue
            hard_id = f"vs-smoke-HN20-{hard_index:04d}"
            hard_index += 1
            hard_candidates.append(
                {
                    "candidate_id": hard_id,
                    "task_id": candidate["task_id"],
                    "candidate_origin": origin,
                    "file": candidate["file"],
                    "function": candidate.get("function"),
                    "line_start": line_start,
                    "line_end": line_end,
                    "candidate_role": "hard_negative_near_patch_evidence",
                    "confidence": "low",
                    "reason": "Nearby same-window source region used as a ranking contrast candidate. It is not proven non-vulnerable.",
                    "positive_anchor_candidate_id": candidate["candidate_id"],
                    "patch_hunk_ids": candidate.get("patch_hunk_ids", []),
                }
            )
            hard_labels.append(
                {
                    "candidate_id": hard_id,
                    "task_id": candidate["task_id"],
                    "label": "hard_negative_candidate",
                    "label_strength": "weak",
                    "is_final_truth": False,
                    "reason": "Generated near a patch-confirmed candidate to test whether ranking can separate direct evidence from nearby context. This is not a final negative label.",
                    "oracle_status": "not_run",
                    "checker_status": "pending",
                    "positive_anchor_candidate_id": candidate["candidate_id"],
                }
            )
            hard_windows.append(
                {
                    "candidate_id": hard_id,
                    "task_id": candidate["task_id"],
                    "status": "derived_from_materialized_source_window",
                    "source_kind": window.get("source_kind"),
                    "file": candidate["file"],
                    "function": candidate.get("function"),
                    "vulnerable_ref": window.get("vulnerable_ref"),
                    "fixed_ref": window.get("fixed_ref"),
                    "vulnerable_line_start": line_start,
                    "vulnerable_line_end": line_end,
                    "fixed_line_start": line_start,
                    "fixed_line_end": line_end,
                    "vulnerable_window": slice_numbered_text(
                        window.get("vulnerable_window", ""),
                        window["vulnerable_line_start"],
                        line_start,
                        line_end,
                    ),
                    "fixed_window": slice_numbered_text(
                        window.get("fixed_window", ""),
                        window["fixed_line_start"],
                        line_start,
                        line_end,
                    ),
                    "positive_anchor_candidate_id": candidate["candidate_id"],
                    "limitations": [
                        "Derived from an already materialized bounded source window.",
                        "Used as weak ranking contrast, not as proof of non-vulnerability.",
                    ],
                }
            )

    write_jsonl(ROOT / "hard_negative_candidates_20_materialized.jsonl", hard_candidates)
    write_jsonl(ROOT / "hard_negative_labels_20_materialized.jsonl", hard_labels)
    write_jsonl(ROOT / "hard_negative_source_windows_20_materialized.jsonl", hard_windows)
    write_jsonl(ROOT / "candidate_locations_20_with_hard_negatives.jsonl", candidates + hard_candidates)
    write_jsonl(ROOT / "labels_20_with_hard_negatives.jsonl", labels + hard_labels)
    write_jsonl(ROOT / "source_windows_20_with_hard_negatives.jsonl", windows + hard_windows)

    summary = {
        "patch_candidate_count": len(candidates),
        "hard_negative_candidate_count": len(hard_candidates),
        "combined_candidate_count": len(candidates) + len(hard_candidates),
        "hard_negative_policy": "weak ranking contrast only; not final non-vulnerable truth",
    }
    write_json(ROOT / "hard_negative_20_summary.json", summary)
    return summary


def append_tool_manifest() -> None:
    manifest_path = ROOT / "tool_run_manifest.jsonl"
    rows = load_jsonl(manifest_path)
    run_id = "vs-smoke-toolrun-kbuild-vulnerable-0003"
    if any(row.get("tool_run_id") == run_id for row in rows):
        return
    rows.append(
        {
            "tool_run_id": run_id,
            "tool": "CodeQL",
            "tool_version": "2.22.3",
            "run_kind": "full_source_kbuild_vulnerable_view_batch",
            "status": "partially_completed",
            "input_scope": "Vulnerable parent refs for the 11 fixed-view-success smoke tasks",
            "query": "reports/e022_object_lifetime_smoke/full_source_probe/queries/ExtractLifecycleSourceFacts.ql",
            "command_summary": "VS_VIEW=vulnerable VS_ONLY_TASKS=... VS_OUTPUT_SUFFIX=_vulnerable_success11 VS_RUN_CODEQL=1 python3 reports/e022_object_lifetime_smoke/full_source_probe/run_kbuild_codeql_pipeline.py",
            "task_candidates_retried": 11,
            "tasks_with_vulnerable_view_kbuild_codeql_facts": 10,
            "candidate_relevant_rows_recorded": 66,
            "created": "2026-05-20",
            "local_workspace": ".tools/kernel-work",
            "limitations": [
                "T0020 fixed view produced facts but vulnerable parent failed to compile.",
                "This is fact extraction, not final vulnerability truth.",
                "No label is promoted to codeql_conditional without a recorded checker rule.",
            ],
        }
    )
    write_jsonl(manifest_path, rows)


def main() -> int:
    comparison_summary = build_codeql_comparison()
    hard_negative_summary = build_hard_negatives()
    append_tool_manifest()
    write_json(
        ROOT / "finalize_20_smoke_summary.json",
        {
            "codeql_comparison": comparison_summary,
            "hard_negatives": hard_negative_summary,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
