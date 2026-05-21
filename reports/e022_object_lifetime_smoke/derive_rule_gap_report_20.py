#!/usr/bin/env python3
"""Derive rule-gap categories for the 20-task smoke dataset.

This pass is planning evidence, not label promotion. It uses already generated
dataset artifacts and parser-backed/tool-backed rows where available. Patch and
source-window text is used only to prioritize rule engineering work; it is not
emitted as model-visible normalized evidence and does not promote labels.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows: list[dict[str, Any]] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def write_json(path: Path, row: dict[str, Any]) -> None:
    path.write_text(json.dumps(row, indent=2, sort_keys=False) + "\n")


def text_blob(*parts: Any) -> str:
    chunks: list[str] = []
    for part in parts:
        if isinstance(part, str):
            chunks.append(part)
        elif isinstance(part, list):
            chunks.extend(str(item) for item in part)
    return "\n".join(chunks)


def coccinelle_roles(rows: list[dict[str, Any]], candidate_id: str, view: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for row in rows:
        if row.get("candidate_id") == candidate_id and row.get("view") == view:
            matches.extend(row.get("matches", []))
    return matches


def wrapper_matches(rows: list[dict[str, Any]], candidate_id: str, view: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for row in rows:
        if row.get("candidate_id") == candidate_id and row.get("view") == view:
            matches.extend(row.get("matches", []))
    return matches


def task_comparison_status(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {row["task_id"]: row.get("comparison_status", "unknown") for row in rows}


def group_rule_runs(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["candidate_id"]].append(row)
    return grouped


def candidate_fact_roles(
    rows: list[dict[str, Any]],
    candidate: dict[str, Any],
    *,
    line_slop: int = 3,
) -> list[str]:
    roles: list[str] = []
    start = int(candidate.get("line_start") or 0) - line_slop
    end = int(candidate.get("line_end") or 0) + line_slop
    for row in rows:
        if row.get("task_id") != candidate.get("task_id"):
            continue
        if row.get("file") != candidate.get("file"):
            continue
        line = row.get("line")
        if not isinstance(line, int) or not (start <= line <= end):
            continue
        if candidate.get("function") and row.get("enclosing_function") != candidate.get("function"):
            continue
        role = row.get("role")
        callee = row.get("callee")
        if role:
            roles.append(str(role))
        if callee:
            roles.append(str(callee))
    return sorted(set(roles))


def add_category(categories: list[dict[str, str]], category: str, basis: str, action: str) -> None:
    categories.append({"category": category, "basis": basis, "recommended_action": action})


def derive_categories(
    candidate: dict[str, Any],
    label: dict[str, Any],
    hunk: dict[str, Any],
    window: dict[str, Any],
    failure: dict[str, Any],
    rule_runs: list[dict[str, Any]],
    vulnerable_cocci: list[dict[str, Any]],
    fixed_cocci: list[dict[str, Any]],
    vulnerable_wrappers: list[dict[str, Any]],
    fixed_wrappers: list[dict[str, Any]],
    fixed_fact_roles: list[str],
    vulnerable_fact_roles: list[str],
) -> list[dict[str, str]]:
    if label.get("label_strength") in {"codeql_conditional", "codeql_conditional_negative"}:
        return [
            {
                "category": "already_covered_by_current_rule_policy",
                "basis": "existing rule run already promoted or cleared this candidate",
                "recommended_action": "keep_as_regression_case",
            }
        ]

    categories: list[dict[str, str]] = []
    added = text_blob(hunk.get("added_lines_sample", []), window.get("fixed_window", ""))
    removed = text_blob(hunk.get("removed_lines_sample", []), window.get("vulnerable_window", ""))
    combined = "\n".join([added, removed])
    vulnerable_roles = {match.get("role") for match in vulnerable_cocci}
    fixed_roles = {match.get("role") for match in fixed_cocci}
    wrapper_roles = {match.get("role") for match in vulnerable_wrappers + fixed_wrappers}
    all_tool_roles = vulnerable_roles | fixed_roles | set(fixed_fact_roles) | set(vulnerable_fact_roles)
    reasons = set(failure.get("failure_reasons", []))

    if "no_full_source_codeql_extraction" in reasons:
        add_category(
            categories,
            "tool_lane_gap_full_source_codeql",
            "full-source CodeQL facts are unavailable for this task",
            "repair_kbuild_profile_or_route_to_secondary_tool_lane",
        )

    if "vulnerable_parent_build_failed" in reasons:
        add_category(
            categories,
            "tool_lane_gap_vulnerable_build",
            "fixed-view facts exist but vulnerable-parent facts failed",
            "repair_vulnerable_build_profile_or_replace_task",
        )

    if vulnerable_cocci or fixed_cocci:
        add_category(
            categories,
            "secondary_tool_evidence_available",
            "Coccinelle produced parser-backed lifecycle matches in the candidate window",
            "define_explicit_secondary_tool_rule_policy_before_promotion",
        )

    if "refcount_inc_not_zero" in added or "acquire_ref_if_live" in all_tool_roles:
        add_category(
            categories,
            "live_ref_acquire_rule_candidate",
            "fixed view introduces or exposes a live-object refcount acquire",
            "generalize_REF_LIVE_or_REF_INSERT_rule_with_object_identity_crosscheck",
        )

    if "call_rcu" in added or "defer_free_rcu" in all_tool_roles:
        add_category(
            categories,
            "rcu_deferred_release_rule_candidate",
            "candidate has deferred release evidence through call_rcu or RCU role",
            "generalize_RCU_DEFER_rule_and_require_release_or_unlink_context",
        )

    if "kref_put_mutex" in added:
        add_category(
            categories,
            "locked_ref_release_rule_candidate",
            "fixed view uses kref_put_mutex",
            "keep_under_KREF_LOCK_rule_or_add_missing_fact_extraction",
        )

    if "sctp_endpoint_hold" in added or "sctp_endpoint_put" in added:
        add_category(
            categories,
            "callback_ref_handoff_rule_candidate",
            "fixed view adds endpoint hold/put around callback traversal",
            "add_callback_lifetime_rule_with_callback_graph_or_path_facts",
        )

    if "sock_put" in added or "release_socket_ref" in all_tool_roles:
        add_category(
            categories,
            "socket_ref_release_rule_candidate",
            "candidate has socket-reference release evidence",
            "add_socket_ref_lifecycle_rule_only_when paired acquire_or_defer_context_exists",
        )

    if "= NULL" in added:
        add_category(
            categories,
            "post_free_pointer_nulling_rule_candidate",
            "fixed view nulls object fields after cleanup/free path",
            "treat_as_cleanup_lifetime_extension_or_out_of_initial_refcount_scope",
        )

    if "custom_release_wrapper_candidate" in wrapper_roles and not any(
        cat["category"] == "socket_ref_release_rule_candidate" for cat in categories
    ):
        add_category(
            categories,
            "custom_release_wrapper_rule_candidate",
            "Coccinelle identified a project-specific release-wrapper candidate",
            "extend_tool_extracted_lifecycle_call_ontology_with_wrapper_mapping",
        )

    if "custom_acquire_wrapper_candidate" in wrapper_roles:
        add_category(
            categories,
            "custom_acquire_wrapper_rule_candidate",
            "Coccinelle identified a project-specific acquire-wrapper candidate",
            "extend_tool_extracted_lifecycle_call_ontology_with_wrapper_mapping",
        )

    if "list_del_rcu" in removed and "_put" in added:
        add_category(
            categories,
            "release_helper_owns_unlink_rule_candidate",
            "patch moves RCU unlink/release behavior into a put helper",
            "require tool facts for helper body before promotion",
        )

    if rule_runs and all(row.get("status") != "passed" for row in rule_runs):
        add_category(
            categories,
            "existing_rule_preconditions_failed",
            "a current rule selected the candidate but required facts were missing",
            "improve_object_identity_or_missing_view_extraction_before_new_rule",
        )

    if not categories:
        add_category(
            categories,
            "no_parser_backed_lifecycle_signal",
            "no current tool lane found a lifecycle/refcount signal in this candidate window",
            "keep_weak_or_replace_with_better_source_record",
        )

    return categories


def main() -> int:
    candidates = read_jsonl(ROOT / "candidate_locations_20_materialized.jsonl")
    labels = {row["candidate_id"]: row for row in read_jsonl(ROOT / "labels_20_strengthened.jsonl")}
    hunks = {row["candidate_id"]: row for row in read_jsonl(ROOT / "patch_hunks_20_materialized.jsonl")}
    windows = {row["candidate_id"]: row for row in read_jsonl(ROOT / "source_windows_20_materialized.jsonl")}
    failures = {row["candidate_id"]: row for row in read_jsonl(ROOT / "promotion_failure_analysis_20.jsonl")}
    comparisons = task_comparison_status(read_jsonl(ROOT / "codeql_vulnerable_fixed_comparison_20.jsonl"))
    rule_runs = group_rule_runs(read_jsonl(ROOT / "codeql_conditional_rule_runs_20.jsonl"))
    coccinelle_rows = read_jsonl(ROOT / "coccinelle_window_lifecycle_matches_20.jsonl")
    wrapper_rows = read_jsonl(ROOT / "coccinelle_wrapper_candidate_matches_20.jsonl")
    fixed_facts = read_jsonl(ROOT / "full_source_codeql_facts_combined.jsonl")
    vulnerable_facts = read_jsonl(ROOT / "full_source_codeql_facts_batch_vulnerable_success11.jsonl")

    rows: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    promotability_counts: Counter[str] = Counter()

    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        label = labels.get(candidate_id, {})
        hunk = hunks.get(candidate_id, {})
        window = windows.get(candidate_id, {})
        failure = failures.get(candidate_id, {})
        candidate_rule_runs = rule_runs.get(candidate_id, [])
        vulnerable_cocci = coccinelle_roles(coccinelle_rows, candidate_id, "vulnerable")
        fixed_cocci = coccinelle_roles(coccinelle_rows, candidate_id, "fixed")
        vulnerable_wrappers = wrapper_matches(wrapper_rows, candidate_id, "vulnerable")
        fixed_wrappers = wrapper_matches(wrapper_rows, candidate_id, "fixed")
        fixed_roles = candidate_fact_roles(fixed_facts, candidate)
        vulnerable_roles = candidate_fact_roles(vulnerable_facts, candidate)
        categories = derive_categories(
            candidate,
            label,
            hunk,
            window,
            failure,
            candidate_rule_runs,
            vulnerable_cocci,
            fixed_cocci,
            vulnerable_wrappers,
            fixed_wrappers,
            fixed_roles,
            vulnerable_roles,
        )

        has_secondary_tool_evidence = any(
            item["category"] == "secondary_tool_evidence_available" for item in categories
        )
        has_rule_candidate = any(item["category"].endswith("_rule_candidate") for item in categories)
        already_covered = label.get("label_strength") in {"codeql_conditional", "codeql_conditional_negative"}
        if already_covered:
            promotability = "already_covered"
        elif has_secondary_tool_evidence and has_rule_candidate:
            promotability = "secondary_tool_policy_candidate"
        elif candidate_rule_runs:
            promotability = "needs_missing_fact_repair"
        elif has_rule_candidate:
            promotability = "needs_new_rule_and_tool_extraction"
        else:
            promotability = "keep_weak_or_replace"

        for item in categories:
            category_counts[item["category"]] += 1
            action_counts[item["recommended_action"]] += 1
        promotability_counts[promotability] += 1

        rows.append(
            {
                "candidate_id": candidate_id,
                "task_id": candidate["task_id"],
                "file": candidate.get("file"),
                "function": candidate.get("function"),
                "line_start": candidate.get("line_start"),
                "line_end": candidate.get("line_end"),
                "current_label_strength": label.get("label_strength"),
                "comparison_status": comparisons.get(candidate["task_id"], "unknown"),
                "selected_rule_ids": [row.get("rule_id") for row in candidate_rule_runs],
                "passed_rule_ids": [
                    row.get("rule_id") for row in candidate_rule_runs if row.get("status") == "passed"
                ],
                "vulnerable_coccinelle_roles": sorted({row.get("role") for row in vulnerable_cocci if row.get("role")}),
                "fixed_coccinelle_roles": sorted({row.get("role") for row in fixed_cocci if row.get("role")}),
                "vulnerable_wrapper_candidate_roles": sorted(
                    {row.get("role") for row in vulnerable_wrappers if row.get("role")}
                ),
                "fixed_wrapper_candidate_roles": sorted(
                    {row.get("role") for row in fixed_wrappers if row.get("role")}
                ),
                "wrapper_candidate_callees": sorted(
                    {row.get("callee") for row in vulnerable_wrappers + fixed_wrappers if row.get("callee")}
                ),
                "candidate_window_fixed_codeql_roles": fixed_roles,
                "candidate_window_vulnerable_codeql_roles": vulnerable_roles,
                "rule_gap_categories": categories,
                "promotability_bucket": promotability,
                "limitations": [
                    "Rule-gap categories prioritize rule engineering only.",
                    "Patch/source-window text categories are not model-visible normalized evidence.",
                    "No label is promoted by this report.",
                ],
            }
        )

    summary = {
        "candidate_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "recommended_action_counts": dict(sorted(action_counts.items())),
        "promotability_counts": dict(sorted(promotability_counts.items())),
        "policy": {
            "report_role": "rule engineering triage",
            "label_promotion": "none",
            "tool_evidence_first": True,
            "patch_text_use": "planning_only_not_model_visible_evidence",
        },
    }
    write_jsonl(ROOT / "rule_gap_report_20.jsonl", rows)
    write_json(ROOT / "rule_gap_report_20_summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
