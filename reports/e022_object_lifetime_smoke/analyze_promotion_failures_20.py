#!/usr/bin/env python3
"""Explain why remaining smoke candidates did not receive stronger labels."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
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


def task_fact_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        counts[row["task_id"]] += 1
    return counts


def coccinelle_roles(rows: list[dict], candidate_id: str, view: str) -> set[str]:
    roles = set()
    for row in rows:
        if row.get("candidate_id") != candidate_id or row.get("view") != view:
            continue
        for match in row.get("matches", []):
            roles.add(match["role"])
            roles.add(match["callee"])
    return roles


def classify_candidate(
    candidate: dict,
    label: dict,
    comparison_by_task: dict[str, dict],
    fixed_counts: Counter,
    vulnerable_counts: Counter,
    rule_runs_by_candidate: dict[str, list[dict]],
    coccinelle_rows: list[dict],
) -> dict:
    task_id = candidate["task_id"]
    candidate_id = candidate["candidate_id"]
    comparison = comparison_by_task.get(task_id, {})
    rule_runs = rule_runs_by_candidate.get(candidate_id, [])
    vulnerable_cocci = coccinelle_roles(coccinelle_rows, candidate_id, "vulnerable")
    fixed_cocci = coccinelle_roles(coccinelle_rows, candidate_id, "fixed")

    reasons = []
    next_actions = []
    if label.get("label_strength") in {"codeql_conditional", "codeql_conditional_negative"}:
        reasons.append("already_promoted")
    else:
        status = comparison.get("comparison_status")
        if status == "full_source_extraction_not_available":
            reasons.append("no_full_source_codeql_extraction")
            next_actions.append("solve_kbuild_profile_or_use_secondary_tool_lane")
        elif status == "fixed_available_vulnerable_build_failed":
            reasons.append("vulnerable_parent_build_failed")
            next_actions.append("repair_vulnerable_build_profile_or_replace_task")

        if fixed_counts[task_id] == 0:
            reasons.append("missing_fixed_view_codeql_facts")
        if vulnerable_counts[task_id] == 0:
            reasons.append("missing_vulnerable_view_codeql_facts")

        if not rule_runs:
            reasons.append("no_current_rule_selected_candidate")
            next_actions.append("add_rule_spec_or_object_aware_facts")
        elif all(row.get("status") != "passed" for row in rule_runs):
            reasons.append("rule_selected_but_preconditions_failed")
            for row in rule_runs:
                if not row.get("fixed_fact_refs"):
                    reasons.append(f"missing_fixed_fact_for_{row['rule_id']}")
                if row.get("preconditions", {}).get("vulnerable_fact_required") and not row.get("vulnerable_fact_refs"):
                    reasons.append(f"missing_vulnerable_fact_for_{row['rule_id']}")
            next_actions.append("use_codeql_v2_object_facts_or_secondary_tool_crosscheck")

        if vulnerable_cocci or fixed_cocci:
            reasons.append("coccinelle_window_evidence_available")
            next_actions.append("crosscheck_with_full_source_or_promote_under_coccinelle_window_policy")
        else:
            reasons.append("no_coccinelle_window_match")

    return {
        "candidate_id": candidate_id,
        "task_id": task_id,
        "file": candidate.get("file"),
        "function": candidate.get("function"),
        "line_start": candidate.get("line_start"),
        "line_end": candidate.get("line_end"),
        "current_label_strength": label.get("label_strength"),
        "comparison_status": comparison.get("comparison_status"),
        "fixed_view_codeql_fact_count": fixed_counts[task_id],
        "vulnerable_view_codeql_fact_count": vulnerable_counts[task_id],
        "selected_rule_ids": [row["rule_id"] for row in rule_runs],
        "passed_rule_ids": [row["rule_id"] for row in rule_runs if row.get("status") == "passed"],
        "vulnerable_coccinelle_roles": sorted(vulnerable_cocci),
        "fixed_coccinelle_roles": sorted(fixed_cocci),
        "failure_reasons": sorted(set(reasons)),
        "automated_next_actions": sorted(set(next_actions)),
    }


def main() -> int:
    candidates = load_jsonl(ROOT / "candidate_locations_20_materialized.jsonl")
    labels = load_jsonl(ROOT / "labels_20_strengthened.jsonl")
    comparisons = load_jsonl(ROOT / "codeql_vulnerable_fixed_comparison_20.jsonl")
    fixed_facts = load_jsonl(ROOT / "full_source_codeql_facts_combined.jsonl")
    vulnerable_facts = load_jsonl(ROOT / "full_source_codeql_facts_batch_vulnerable_success11.jsonl")
    rule_runs = load_jsonl(ROOT / "codeql_conditional_rule_runs_20.jsonl")
    coccinelle_rows = load_jsonl(ROOT / "coccinelle_window_lifecycle_matches_20.jsonl")

    labels_by_id = {row["candidate_id"]: row for row in labels}
    comparison_by_task = {row["task_id"]: row for row in comparisons}
    rule_runs_by_candidate: dict[str, list[dict]] = defaultdict(list)
    for row in rule_runs:
        rule_runs_by_candidate[row["candidate_id"]].append(row)

    fixed_counts = task_fact_counts(fixed_facts)
    vulnerable_counts = task_fact_counts(vulnerable_facts)
    rows = [
        classify_candidate(
            candidate,
            labels_by_id.get(candidate["candidate_id"], {}),
            comparison_by_task,
            fixed_counts,
            vulnerable_counts,
            rule_runs_by_candidate,
            coccinelle_rows,
        )
        for candidate in candidates
    ]

    write_jsonl(ROOT / "promotion_failure_analysis_20.jsonl", rows)

    reason_counts: Counter = Counter()
    action_counts: Counter = Counter()
    for row in rows:
        if row["current_label_strength"] in {"codeql_conditional", "codeql_conditional_negative"}:
            continue
        for reason in row["failure_reasons"]:
            reason_counts[reason] += 1
        for action in row["automated_next_actions"]:
            action_counts[action] += 1

    summary = {
        "candidate_count": len(rows),
        "unpromoted_patch_candidate_count": sum(
            1 for row in rows if row["current_label_strength"] not in {"codeql_conditional", "codeql_conditional_negative"}
        ),
        "failure_reason_counts": dict(sorted(reason_counts.items())),
        "automated_next_action_counts": dict(sorted(action_counts.items())),
    }
    write_json(ROOT / "promotion_failure_analysis_20_summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
