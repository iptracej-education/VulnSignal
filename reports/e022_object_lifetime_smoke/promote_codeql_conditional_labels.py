#!/usr/bin/env python3
"""Promote eligible 20-task smoke labels using executable fact-delta rules."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
RULE_DIR = REPO_ROOT / "rules" / "lifecycle"


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


def load_rule_specs() -> dict[str, dict]:
    rules = {}
    for path in sorted(RULE_DIR.glob("VS-LIFE-*.json")):
        with path.open() as fh:
            rule = json.load(fh)
        rules[rule["rule_id"]] = rule
    return rules


def fact_matches(fact: dict, rule_side: dict | None) -> bool:
    if rule_side is None:
        return True
    return all(fact.get(key) == value for key, value in rule_side.items())


def fact_ref(row: dict) -> str:
    return f"{row.get('view')}:{row.get('fact_id')}"


def facts_for(
    rows: list[dict],
    candidate: dict,
    rule_side: dict | None,
    line_slop: int = 3,
    require_function: bool = True,
) -> list[dict]:
    function = candidate.get("function")
    line_start = candidate.get("line_start")
    line_end = candidate.get("line_end")
    return [
        row
        for row in rows
        if row.get("task_id") == candidate["task_id"]
        and row.get("file") == candidate["file"]
        and (not require_function or not function or row.get("enclosing_function") == function)
        and (line_start is None or row.get("line", 0) >= line_start - line_slop)
        and (line_end is None or row.get("line", 0) <= line_end + line_slop)
        and fact_matches(row, rule_side)
    ]


def source_window_contains(window: dict | None, tokens: list[str]) -> bool:
    if not window:
        return False
    vulnerable = window.get("vulnerable_window", "")
    fixed = window.get("fixed_window", "")
    combined = vulnerable + "\n" + fixed
    return all(token in combined for token in tokens)


def source_window_any(window: dict | None, tokens: list[str]) -> bool:
    if not tokens:
        return True
    if not window:
        return False
    combined = "\n".join([window.get("vulnerable_window", ""), window.get("fixed_window", "")])
    return any(token in combined for token in tokens)


def contains_all(text: str, tokens: list[str]) -> bool:
    return all(token in text for token in tokens)


def excludes_all(text: str, tokens: list[str]) -> bool:
    return all(token not in text for token in tokens)


def rule_selects_candidate(rule: dict, hunk: dict, window: dict | None) -> bool:
    selectors = rule.get("candidate_selectors", {})
    added_text = "\n".join(hunk.get("added_lines_sample", []))
    removed_text = "\n".join(hunk.get("removed_lines_sample", []))
    fixed_window = (window or {}).get("fixed_window", "")
    vulnerable_window = (window or {}).get("vulnerable_window", "")

    checks = [
        contains_all(added_text, selectors.get("patch_added_contains", [])),
        contains_all(removed_text, selectors.get("patch_removed_contains", [])),
        excludes_all(removed_text, selectors.get("patch_removed_excludes", [])),
        contains_all(fixed_window, selectors.get("fixed_window_contains", [])),
        contains_all(vulnerable_window, selectors.get("vulnerable_window_contains", [])),
    ]
    return all(checks)


def build_positive_rule_runs(
    candidates: list[dict],
    patch_hunks_by_candidate: dict[str, dict],
    windows_by_candidate: dict[str, dict],
    fixed_facts: list[dict],
    vulnerable_facts: list[dict],
    rules: dict[str, dict],
) -> tuple[list[dict], list[dict], dict[str, list[dict]]]:
    rule_runs = []
    evidence_packets = []
    promoted_by_candidate: dict[str, list[dict]] = defaultdict(list)
    run_index = 1
    packet_index = 1

    for candidate in candidates:
        hunk = patch_hunks_by_candidate.get(candidate["candidate_id"], {})
        window = windows_by_candidate.get(candidate["candidate_id"])
        candidate_rules = [
            rule_id for rule_id, rule in rules.items() if rule_selects_candidate(rule, hunk, window)
        ]

        for rule_id in candidate_rules:
            rule = rules[rule_id]
            matching = rule.get("matching", {})
            require_function = matching.get("require_function", True)
            line_slop = int(matching.get("line_slop", 3))
            fixed = facts_for(
                fixed_facts,
                candidate,
                rule["fixed_required"],
                line_slop=line_slop,
                require_function=require_function,
            )
            vulnerable = facts_for(
                vulnerable_facts,
                candidate,
                rule.get("vulnerable_required"),
                line_slop=line_slop,
                require_function=require_function,
            )

            if rule.get("vulnerable_required") is None and rule.get("source_window_required"):
                source_ok = source_window_contains(window, rule.get("source_window_required", [])) and source_window_any(
                    window,
                    rule.get("source_window_any_of", []),
                )
                vulnerable_ok = source_ok
            elif rule.get("vulnerable_required") is None:
                source_ok = True
                vulnerable_ok = not vulnerable
            else:
                source_ok = True
                vulnerable_ok = bool(vulnerable)

            fixed_ok = bool(fixed)
            passed = fixed_ok and vulnerable_ok and source_ok
            status = "passed" if passed else "not_promoted"
            run_id = f"vs-smoke-rule-run-20-{run_index:04d}"
            run_index += 1
            rule_run = {
                "rule_run_id": run_id,
                "rule_id": rule_id,
                "task_id": candidate["task_id"],
                "candidate_id": candidate["candidate_id"],
                "status": status,
                "rule_family": rule["family"],
                "checker_engine": "VulnSignal fact-delta rule over CodeQL lifecycle facts and materialized source windows",
                "vulnerable_fact_refs": [fact_ref(row) for row in vulnerable],
                "fixed_fact_refs": [fact_ref(row) for row in fixed],
                "source_window_candidate_id": candidate["candidate_id"],
                "preconditions": {
                    "fixed_fact_required": rule["fixed_required"],
                    "vulnerable_fact_required": rule.get("vulnerable_required"),
                    "source_window_required": rule.get("source_window_required", []),
                    "source_window_any_of": rule.get("source_window_any_of", []),
                    "matching": matching,
                },
                "limitations": [
                    "Conditional checker label, not dynamic proof.",
                    "Rule is intentionally narrow and tied to extracted lifecycle facts.",
                    "Promotion is candidate-local and does not prove the whole function vulnerable or safe.",
                ],
            }
            rule_runs.append(rule_run)

            if passed:
                packet_id = f"vs-smoke-evidence-20-{packet_index:04d}"
                packet_index += 1
                evidence_packets.append(
                    {
                        "evidence_packet_id": packet_id,
                        "task_id": candidate["task_id"],
                        "candidate_id": candidate["candidate_id"],
                        "rule_run_id": run_id,
                        "rule_id": rule_id,
                        "label_strength": "codeql_conditional",
                        "candidate_location": {
                            "file": candidate["file"],
                            "function": candidate.get("function"),
                            "line_start": candidate.get("line_start"),
                            "line_end": candidate.get("line_end"),
                        },
                        "vulnerable_facts": vulnerable,
                        "fixed_facts": fixed,
                        "source_window_refs": {
                            "vulnerable_ref": (window or {}).get("vulnerable_ref"),
                            "fixed_ref": (window or {}).get("fixed_ref"),
                        },
                        "decision": rule["label_reason"],
                    }
                )
                promoted_by_candidate[candidate["candidate_id"]].append(rule_run)

    return rule_runs, evidence_packets, promoted_by_candidate


def build_negative_rule_runs(
    hard_candidates: list[dict],
    hard_windows_by_candidate: dict[str, dict],
    promoted_by_candidate: dict[str, list[dict]],
    rules: dict[str, dict],
) -> tuple[list[dict], list[dict]]:
    negative_runs = []
    negative_labels = []
    run_index = 1
    for hard_candidate in hard_candidates:
        anchor_id = hard_candidate.get("positive_anchor_candidate_id")
        anchor_promotions = promoted_by_candidate.get(anchor_id, [])
        if not anchor_promotions:
            continue
        window = hard_windows_by_candidate.get(hard_candidate["candidate_id"], {})
        combined = "\n".join([window.get("vulnerable_window", ""), window.get("fixed_window", "")])
        for promotion in anchor_promotions:
            rule_id = promotion["rule_id"]
            rule = rules[rule_id]
            if not rule.get("negative_policy", {}).get("enabled", False):
                continue
            trigger_terms = [rule["fixed_required"]["callee"]]
            vulnerable_required = rule.get("vulnerable_required")
            if vulnerable_required:
                trigger_terms.append(vulnerable_required["callee"])
            trigger_present = any(term in combined for term in trigger_terms)
            if trigger_present:
                continue
            run_id = f"vs-smoke-negative-rule-run-20-{run_index:04d}"
            run_index += 1
            negative_runs.append(
                {
                    "rule_run_id": run_id,
                    "rule_id": rule_id,
                    "task_id": hard_candidate["task_id"],
                    "candidate_id": hard_candidate["candidate_id"],
                    "positive_anchor_candidate_id": anchor_id,
                    "status": "checker_scoped_cleared",
                    "checker_engine": "VulnSignal candidate-local text/fact trigger clearance for a previously passed rule",
                    "limitations": [
                        "This is not a global non-vulnerable label.",
                        "It only says this candidate window did not contain the trigger terms for the anchor rule.",
                    ],
                }
            )
            negative_labels.append(
                {
                    "candidate_id": hard_candidate["candidate_id"],
                    "task_id": hard_candidate["task_id"],
                    "label": "checker_scoped_negative_candidate",
                    "label_strength": "codeql_conditional_negative",
                    "is_final_truth": False,
                    "reason": "Candidate was checked against a rule that promoted its positive anchor and did not contain the rule trigger terms.",
                    "oracle_status": "not_run",
                    "checker_status": "passed_for_scoped_negative",
                    "rule_id": rule_id,
                    "rule_run_id": run_id,
                    "positive_anchor_candidate_id": anchor_id,
                }
            )
    return negative_runs, negative_labels


def main() -> int:
    rules = load_rule_specs()
    candidates = load_jsonl(ROOT / "candidate_locations_20_materialized.jsonl")
    hard_candidates = load_jsonl(ROOT / "hard_negative_candidates_20_materialized.jsonl")
    labels = load_jsonl(ROOT / "labels_20_with_hard_negatives.jsonl")
    patch_hunks = load_jsonl(ROOT / "patch_hunks_20_materialized.jsonl")
    windows = load_jsonl(ROOT / "source_windows_20_materialized.jsonl")
    hard_windows = load_jsonl(ROOT / "hard_negative_source_windows_20_materialized.jsonl")
    fixed_facts = load_jsonl(ROOT / "full_source_codeql_facts_combined.jsonl")
    vulnerable_facts = load_jsonl(ROOT / "full_source_codeql_facts_batch_vulnerable_success11.jsonl")

    patch_hunks_by_candidate = {row["candidate_id"]: row for row in patch_hunks}
    windows_by_candidate = {row["candidate_id"]: row for row in windows}
    hard_windows_by_candidate = {row["candidate_id"]: row for row in hard_windows}

    positive_rule_runs, evidence_packets, promoted_by_candidate = build_positive_rule_runs(
        candidates,
        patch_hunks_by_candidate,
        windows_by_candidate,
        fixed_facts,
        vulnerable_facts,
        rules,
    )
    negative_rule_runs, negative_labels = build_negative_rule_runs(
        hard_candidates,
        hard_windows_by_candidate,
        promoted_by_candidate,
        rules,
    )

    promoted_ids = set(promoted_by_candidate)
    labels_by_id = {row["candidate_id"]: row for row in labels}
    strengthened_labels = []
    for row in labels:
        candidate_id = row["candidate_id"]
        if candidate_id in promoted_ids:
            passed_runs = promoted_by_candidate[candidate_id]
            strengthened_labels.append(
                {
                    **row,
                    "label": "positive_candidate",
                    "label_strength": "codeql_conditional",
                    "is_final_truth": False,
                    "reason": "Promoted from patch_confirmed_weak by executable fact-delta rule evidence.",
                    "oracle_status": "not_run",
                    "checker_status": "passed",
                    "rule_ids": [rule_run["rule_id"] for rule_run in passed_runs],
                    "rule_run_ids": [rule_run["rule_run_id"] for rule_run in passed_runs],
                }
            )
        elif candidate_id not in {label["candidate_id"] for label in negative_labels}:
            strengthened_labels.append(row)

    for label in negative_labels:
        base = labels_by_id.get(label["candidate_id"], {})
        strengthened_labels.append({**base, **label})

    all_rule_runs = positive_rule_runs + negative_rule_runs
    write_jsonl(ROOT / "codeql_conditional_rule_catalog.jsonl", list(rules.values()))
    write_jsonl(ROOT / "codeql_conditional_rule_runs_20.jsonl", all_rule_runs)
    write_jsonl(ROOT / "evidence_packets_20_codeql_conditional.jsonl", evidence_packets)
    write_jsonl(ROOT / "labels_20_strengthened.jsonl", strengthened_labels)

    by_rule: dict[str, int] = defaultdict(int)
    for packet in evidence_packets:
        by_rule[packet["rule_id"]] += 1
    summary = {
        "positive_codeql_conditional_labels": len(promoted_ids),
        "positive_evidence_packets": len(evidence_packets),
        "checker_scoped_negative_labels": len(negative_labels),
        "rule_run_count": len(all_rule_runs),
        "positive_promotions_by_rule": dict(sorted(by_rule.items())),
        "remaining_patch_confirmed_weak_labels": sum(
            1 for row in strengthened_labels if row.get("label_strength") == "patch_confirmed_weak"
        ),
        "remaining_weak_labels": sum(1 for row in strengthened_labels if row.get("label_strength") == "weak"),
        "limitations": [
            "No dynamic labels were created.",
            "codeql_conditional labels are strong only under the recorded rule preconditions.",
            "checker_scoped_negative labels are not global safe-code claims.",
        ],
    }
    write_json(ROOT / "strong_label_promotion_20_summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
