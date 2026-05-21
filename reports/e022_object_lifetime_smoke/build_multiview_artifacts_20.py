#!/usr/bin/env python3
"""Build tool-derived multi-view artifacts for the 20-task smoke dataset.

This script intentionally does not infer object identity from raw source text.
It joins existing tool outputs, emits stable view records, and records UNKNOWN
where the required tool evidence is not available yet.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
UNKNOWN_OBJECT_ID = "UNKNOWN_OBJECT_ID"


ROLE_ONTOLOGY = {
    "acquire_ref_if_live": {
        "api_family": "refcount",
        "operation_class": "acquire",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "live_guard",
    },
    "acquire_ref_unchecked": {
        "api_family": "refcount",
        "operation_class": "acquire",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "unchecked_acquire",
    },
    "release_ref": {
        "api_family": "refcount",
        "operation_class": "release",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "release",
    },
    "release_ref_locked": {
        "api_family": "kref",
        "operation_class": "release",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "locked_release",
    },
    "release_socket_ref": {
        "api_family": "socket_refcount",
        "operation_class": "release",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "release",
    },
    "acquire_socket_ref": {
        "api_family": "socket_refcount",
        "operation_class": "acquire",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "acquire",
    },
    "custom_release_wrapper_candidate": {
        "api_family": "custom_wrapper",
        "operation_class": "release_candidate",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "wrapper_candidate",
    },
    "custom_acquire_wrapper_candidate": {
        "api_family": "custom_wrapper",
        "operation_class": "acquire_candidate",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "wrapper_candidate",
    },
    "defer_free_rcu": {
        "api_family": "rcu",
        "operation_class": "defer_free",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "deferred_release",
    },
    "rcu_unlink": {
        "api_family": "rcu",
        "operation_class": "unlink",
        "security_axis": "object_lifecycle",
        "lifecycle_stage": "publish_remove",
    },
    "workqueue_enqueue": {
        "api_family": "workqueue",
        "operation_class": "async_enqueue",
        "security_axis": "async_lifecycle",
        "lifecycle_stage": "async_publish",
    },
    "timer_register": {
        "api_family": "timer",
        "operation_class": "async_register",
        "security_axis": "async_lifecycle",
        "lifecycle_stage": "async_publish",
    },
    "free": {
        "api_family": "allocator",
        "operation_class": "free",
        "security_axis": "memory_lifecycle",
        "lifecycle_stage": "destroy",
    },
    "free_sensitive": {
        "api_family": "allocator",
        "operation_class": "free",
        "security_axis": "memory_lifecycle",
        "lifecycle_stage": "destroy_sensitive",
    },
}

CALLEE_FAMILY_HINTS = {
    "kref_": "kref",
    "refcount_": "refcount",
    "call_rcu": "rcu",
    "kfree_rcu": "rcu",
    "list_del_rcu": "rcu",
    "queue_work": "workqueue",
    "schedule_work": "workqueue",
    "mod_timer": "timer",
    "kfree": "allocator",
    "sock_put": "socket_refcount",
}


OUTPUTS = {
    "ast_expression_facts": ROOT / "ast_expression_facts.jsonl",
    "object_identity_facts": ROOT / "object_identity_facts.jsonl",
    "operation_role_facts": ROOT / "operation_role_facts.jsonl",
    "control_flow_order_facts": ROOT / "control_flow_order_facts.jsonl",
    "alias_dataflow_facts": ROOT / "alias_dataflow_facts.jsonl",
    "callback_graph_facts": ROOT / "callback_graph_facts.jsonl",
    "vulnerability_rule_instances": ROOT / "vulnerability_rule_instances.jsonl",
    "vulnerability_rule_validation": ROOT / "vulnerability_rule_validation.jsonl",
}


def normalized_operation(role: str | None, callee: str | None) -> dict[str, str]:
    """Return model-facing semantic categories from tool-emitted role/callee."""
    role_key = role or "UNKNOWN_OPERATION_ROLE"
    row = dict(
        ROLE_ONTOLOGY.get(
            role_key,
            {
                "api_family": "unknown",
                "operation_class": "unknown",
                "security_axis": "unknown",
                "lifecycle_stage": "unknown",
            },
        )
    )
    if row["api_family"] == "unknown" and callee:
        for prefix, family in CALLEE_FAMILY_HINTS.items():
            if callee.startswith(prefix):
                row["api_family"] = family
                break
    row["normalized_operation_role"] = role_key
    row["model_event_token"] = "|".join(
        [
            f"axis={row['security_axis']}",
            f"family={row['api_family']}",
            f"class={row['operation_class']}",
            f"stage={row['lifecycle_stage']}",
            f"role={role_key}",
        ]
    )
    return row


def read_json(path: Path, default: Any) -> Any:
    if not path.exists() or path.stat().st_size == 0:
        return default
    with path.open() as fh:
        return json.load(fh)


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


def short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def is_unknown_expr(value: str | None) -> bool:
    if not value:
        return True
    stripped = value.strip()
    return not stripped or "..." in stripped


def line_value(row: dict[str, Any]) -> int | None:
    for key in ("line", "line_start", "arg0_line"):
        value = row.get(key)
        if isinstance(value, int):
            return value
    return None


def candidate_index(candidates: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    by_task_file: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        by_task_file[(candidate.get("task_id", ""), candidate.get("file", ""))].append(candidate)
    return by_task_file


def candidate_for_fact(
    fact: dict[str, Any],
    by_task_file: dict[tuple[str, str], list[dict[str, Any]]],
    *,
    line_slop: int = 3,
) -> str | None:
    task_id = fact.get("task_id") or fact.get("task_db_key")
    file_name = fact.get("file")
    fact_line = line_value(fact)
    if not task_id or not file_name or fact_line is None:
        return None

    function = fact.get("enclosing_function") or fact.get("function")
    exact_matches: list[dict[str, Any]] = []
    loose_matches: list[dict[str, Any]] = []
    for candidate in by_task_file.get((task_id, file_name), []):
        start = int(candidate.get("line_start") or 0) - line_slop
        end = int(candidate.get("line_end") or 0) + line_slop
        if start <= fact_line <= end:
            loose_matches.append(candidate)
            if function and candidate.get("function") == function:
                exact_matches.append(candidate)
    matches = exact_matches or loose_matches
    if len(matches) == 1:
        return matches[0].get("candidate_id")
    if matches:
        return sorted(m.get("candidate_id", "") for m in matches)[0]
    return None


def fact_ref(view: str | None, fact_id: str | None) -> str | None:
    if not fact_id:
        return None
    return f"{view}:{fact_id}" if view else fact_id


def codeql_source_name(path: Path) -> str:
    return path.name


def load_codeql_facts() -> list[dict[str, Any]]:
    paths = [
        ROOT / "full_source_codeql_facts_combined.jsonl",
        ROOT / "full_source_codeql_facts_batch_vulnerable_success11.jsonl",
        ROOT / "full_source_codeql_facts_v2_smoke_t0005.jsonl",
    ]
    seen: set[tuple[str, str, str, int | None, str]] = set()
    facts: list[dict[str, Any]] = []
    for path in paths:
        for row in read_jsonl(path):
            row = dict(row)
            row["_input_artifact"] = codeql_source_name(path)
            key = (
                row.get("view", ""),
                row.get("fact_id", ""),
                row.get("file", ""),
                line_value(row),
                row.get("callee", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            facts.append(row)
    return facts


def source_window_ids(source_windows: list[dict[str, Any]]) -> set[str]:
    return {row.get("candidate_id", "") for row in source_windows if row.get("candidate_id")}


def build_operation_and_expression_facts(
    candidates: list[dict[str, Any]],
    codeql_facts: list[dict[str, Any]],
    coccinelle_rows: list[dict[str, Any]],
    wrapper_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_task_file = candidate_index(candidates)
    ast_rows: list[dict[str, Any]] = []
    object_rows: list[dict[str, Any]] = []
    operation_rows: list[dict[str, Any]] = []

    for idx, fact in enumerate(codeql_facts, start=1):
        view = fact.get("view", "unknown")
        source_fact_ref = fact_ref(view, fact.get("fact_id"))
        candidate_id = candidate_for_fact(fact, by_task_file)
        line = line_value(fact)
        ast_id = f"vs-smoke-ast-{idx:05d}"
        op_id = f"vs-smoke-op-{idx:05d}"
        arg0 = fact.get("arg0")
        normalized = normalized_operation(fact.get("role"), fact.get("callee"))
        object_status = "unresolved"
        object_id = UNKNOWN_OBJECT_ID
        trust_level = "unknown"
        if "arg0" in fact and not is_unknown_expr(arg0):
            object_id = "obj-" + short_hash(
                "|".join(
                    [
                        str(fact.get("task_id") or fact.get("task_db_key")),
                        str(view),
                        str(fact.get("file")),
                        str(fact.get("arg0_file") or fact.get("file")),
                        str(fact.get("arg0_line") or line or ""),
                        str(arg0),
                    ]
                )
            )
            object_status = "tool_expression_identity"
            trust_level = "tool_derived"

        ast_rows.append(
            {
                "ast_expression_fact_id": ast_id,
                "task_id": fact.get("task_id") or fact.get("task_db_key"),
                "candidate_id": candidate_id,
                "view": view,
                "producer_tool": "CodeQL",
                "source_representation": "CodeQL AST/call expression",
                "input_artifact": fact.get("_input_artifact"),
                "source_fact_ref": source_fact_ref,
                "file": fact.get("file"),
                "function": fact.get("enclosing_function"),
                "line_start": fact.get("line_start", fact.get("line")),
                "line_end": fact.get("line_end", fact.get("line")),
                "expression_kind": "call",
                "callee": fact.get("callee"),
                "role": fact.get("role"),
                "normalized_view": {
                    "view_type": "ast_expression",
                    "expression_kind": "call",
                    "api_family": normalized["api_family"],
                    "operation_class": normalized["operation_class"],
                    "security_axis": normalized["security_axis"],
                    "lifecycle_stage": normalized["lifecycle_stage"],
                    "model_event_token": normalized["model_event_token"],
                    "raw_symbol_policy": "audit_only_by_default",
                },
                "arguments": {
                    "arg0": fact.get("arg0"),
                    "arg1": fact.get("arg1"),
                    "arg2": fact.get("arg2"),
                },
                "trust_level": "tool_derived",
                "limitations": fact.get("limitations", []),
            }
        )
        operation_rows.append(
            {
                "operation_role_fact_id": op_id,
                "task_id": fact.get("task_id") or fact.get("task_db_key"),
                "candidate_id": candidate_id,
                "view": view,
                "producer_tool": "CodeQL",
                "source_representation": "CodeQL lifecycle-call fact",
                "input_artifact": fact.get("_input_artifact"),
                "source_fact_ref": source_fact_ref,
                "file": fact.get("file"),
                "function": fact.get("enclosing_function"),
                "line": line,
                "callee": fact.get("callee"),
                "operation_role": fact.get("role"),
                "normalized_operation_role": normalized["normalized_operation_role"],
                "api_family": normalized["api_family"],
                "operation_class": normalized["operation_class"],
                "security_axis": normalized["security_axis"],
                "lifecycle_stage": normalized["lifecycle_stage"],
                "model_event_token": normalized["model_event_token"],
                "raw_symbol_policy": "audit_only_by_default",
                "trust_level": "tool_derived",
                "limitations": fact.get("limitations", []),
            }
        )
        object_rows.append(
            {
                "object_identity_fact_id": f"vs-smoke-obj-{idx:05d}",
                "task_id": fact.get("task_id") or fact.get("task_db_key"),
                "candidate_id": candidate_id,
                "view": view,
                "producer_tool": "CodeQL",
                "source_representation": "CodeQL rendered argument expression",
                "input_artifact": fact.get("_input_artifact"),
                "source_fact_ref": source_fact_ref,
                "file": fact.get("arg0_file") or fact.get("file"),
                "line": fact.get("arg0_line") or line,
                "object_id": object_id,
                "object_expression": arg0,
                "identity_status": object_status,
                "normalized_object_view": {
                    "object_token": object_id,
                    "identity_status": object_status,
                    "has_tool_rendered_expression": object_id != UNKNOWN_OBJECT_ID,
                    "raw_expression_policy": "audit_only_by_default",
                },
                "trust_level": trust_level,
                "limitations": [
                    "The object ID is a tool-expression identity, not an alias-equivalence proof.",
                    "UNKNOWN_OBJECT_ID is emitted when CodeQL cannot render a usable expression.",
                ],
            }
        )

    cocc_index = len(operation_rows)
    for row in coccinelle_rows:
        for match in row.get("matches", []):
            cocc_index += 1
            normalized = normalized_operation(match.get("role"), match.get("callee"))
            operation_rows.append(
                {
                    "operation_role_fact_id": f"vs-smoke-op-cocci-{cocc_index:05d}",
                    "task_id": row.get("task_id"),
                    "candidate_id": row.get("candidate_id"),
                    "view": row.get("view"),
                    "producer_tool": "Coccinelle",
                    "source_representation": "Coccinelle semantic patch over bounded source window",
                    "input_artifact": "coccinelle_window_lifecycle_matches_20.jsonl",
                    "source_fact_ref": None,
                    "file": row.get("source_window_file"),
                    "function": None,
                    "line": match.get("tool_line"),
                    "callee": match.get("callee"),
                    "operation_role": match.get("role"),
                    "normalized_operation_role": normalized["normalized_operation_role"],
                    "api_family": normalized["api_family"],
                    "operation_class": normalized["operation_class"],
                    "security_axis": normalized["security_axis"],
                    "lifecycle_stage": normalized["lifecycle_stage"],
                    "model_event_token": normalized["model_event_token"],
                    "raw_symbol_policy": "audit_only_by_default",
                    "trust_level": "supporting",
                    "limitations": row.get("limitations", []),
                }
            )

    wrapper_index = len(operation_rows)
    for row in wrapper_rows:
        for match in row.get("matches", []):
            wrapper_index += 1
            normalized = normalized_operation(match.get("role"), match.get("callee"))
            operation_rows.append(
                {
                    "operation_role_fact_id": f"vs-smoke-op-wrapper-{wrapper_index:05d}",
                    "task_id": row.get("task_id"),
                    "candidate_id": row.get("candidate_id"),
                    "view": row.get("view"),
                    "producer_tool": "Coccinelle",
                    "source_representation": "Coccinelle wrapper-candidate semantic patch over bounded source window",
                    "input_artifact": "coccinelle_wrapper_candidate_matches_20.jsonl",
                    "source_fact_ref": None,
                    "file": row.get("source_window_file"),
                    "function": None,
                    "line": match.get("tool_line"),
                    "callee": match.get("callee"),
                    "operation_role": match.get("role"),
                    "normalized_operation_role": normalized["normalized_operation_role"],
                    "api_family": normalized["api_family"],
                    "operation_class": normalized["operation_class"],
                    "security_axis": normalized["security_axis"],
                    "lifecycle_stage": normalized["lifecycle_stage"],
                    "model_event_token": normalized["model_event_token"],
                    "raw_symbol_policy": "audit_only_by_default",
                    "trust_level": "wrapper_candidate_only",
                    "limitations": row.get("limitations", []),
                }
            )

    return ast_rows, object_rows, operation_rows


def build_graph_rows(
    candidates: list[dict[str, Any]],
    joern_summary: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    materialized = joern_summary.get("materialized_windows", [])
    graph_candidates = {row.get("candidate_id") for row in materialized if row.get("candidate_id")}
    exports = {row.get("repr"): row for row in joern_summary.get("exports", [])}

    control_rows: list[dict[str, Any]] = []
    alias_rows: list[dict[str, Any]] = []
    callback_rows: list[dict[str, Any]] = []

    for idx, candidate in enumerate(candidates, start=1):
        candidate_id = candidate.get("candidate_id")
        has_graph = candidate_id in graph_candidates
        cfg = exports.get("cfg", {})
        ddg = exports.get("ddg", {})
        cpg = exports.get("cpg14", {})

        control_rows.append(
            {
                "control_flow_order_fact_id": f"vs-smoke-cfg-{idx:05d}",
                "task_id": candidate.get("task_id"),
                "candidate_id": candidate_id,
                "producer_tool": "Joern",
                "source_representation": "Joern CFG export over bounded source window",
                "status": "graph_artifact_available" if has_graph and cfg.get("status") == "completed" else "missing_required_tool_input",
                "normalized_view": {
                    "view_type": "control_flow_order",
                    "graph_family": "cfg",
                    "availability": "available" if has_graph and cfg.get("status") == "completed" else "missing",
                    "model_graph_token": "graph=cfg|availability="
                    + ("available" if has_graph and cfg.get("status") == "completed" else "missing"),
                },
                "export_dir": cfg.get("export_dir") if has_graph else None,
                "export_file_count": cfg.get("file_count") if has_graph else 0,
                "trust_level": "supporting" if has_graph else "unknown",
                "limitations": [
                    "This row records graph availability, not a proven order relation.",
                    "Candidate-local order claims require parsed CFG edges in a later pass.",
                ],
            }
        )
        alias_rows.append(
            {
                "alias_dataflow_fact_id": f"vs-smoke-ddg-{idx:05d}",
                "task_id": candidate.get("task_id"),
                "candidate_id": candidate_id,
                "producer_tool": "Joern",
                "source_representation": "Joern DDG export over bounded source window",
                "status": "supporting_graph_available" if has_graph and ddg.get("status") == "completed" else "missing_required_tool_input",
                "normalized_view": {
                    "view_type": "alias_dataflow",
                    "graph_family": "ddg",
                    "availability": "available" if has_graph and ddg.get("status") == "completed" else "missing",
                    "model_graph_token": "graph=ddg|availability="
                    + ("available" if has_graph and ddg.get("status") == "completed" else "missing"),
                },
                "export_dir": ddg.get("export_dir") if has_graph else None,
                "export_file_count": ddg.get("file_count") if has_graph else 0,
                "trust_level": "supporting" if has_graph else "unknown",
                "limitations": [
                    "This is not an alias-equivalence proof.",
                    "SVF or CodeQL dataflow is still required for strong alias/object continuity.",
                ],
            }
        )
        callback_rows.append(
            {
                "callback_graph_fact_id": f"vs-smoke-callback-{idx:05d}",
                "task_id": candidate.get("task_id"),
                "candidate_id": candidate_id,
                "producer_tool": "Joern/SVF/CodeQL",
                "source_representation": "callback/async graph resolution",
                "status": "supporting_cpg_available_but_callback_unresolved"
                if has_graph and cpg.get("status") == "completed"
                else "missing_required_tool_input",
                "normalized_view": {
                    "view_type": "callback_async_graph",
                    "graph_family": "cpg14",
                    "availability": "supporting_graph_available"
                    if has_graph and cpg.get("status") == "completed"
                    else "missing",
                    "callback_resolution": "unresolved",
                    "model_graph_token": "graph=cpg14|callback=unresolved|availability="
                    + (
                        "supporting_graph_available"
                        if has_graph and cpg.get("status") == "completed"
                        else "missing"
                    ),
                },
                "available_supporting_artifact": cpg.get("export_dir") if has_graph else None,
                "trust_level": "unknown",
                "limitations": [
                    "No callback target, timer handler, workqueue handler, or RCU handler is resolved yet.",
                    "SVF/CodeQL/Joern callback extraction must produce explicit async edges before this view can support stronger validation.",
                ],
            }
        )

    return control_rows, alias_rows, callback_rows, graph_candidates


def build_rule_rows(
    rule_runs: list[dict[str, Any]],
    evidence_packets: list[dict[str, Any]],
    source_window_candidates: set[str],
    object_rows: list[dict[str, Any]],
    graph_candidates: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_by_run = {row.get("rule_run_id"): row for row in evidence_packets}
    resolved_object_candidates = {
        row.get("candidate_id")
        for row in object_rows
        if row.get("candidate_id") and row.get("object_id") != UNKNOWN_OBJECT_ID
    }

    instance_rows: list[dict[str, Any]] = []
    validation_rows: list[dict[str, Any]] = []

    for idx, run in enumerate(rule_runs, start=1):
        candidate_id = run.get("candidate_id")
        evidence = evidence_by_run.get(run.get("rule_run_id"), {})
        required_representations = [
            "source_window",
            "AST/expression facts",
            "lifecycle/API event facts",
            "tool rule result",
        ]
        if run.get("rule_id") in {"VS-LIFE-RCU-DEFER-001"}:
            required_representations.append("callback/async graph facts")
        if run.get("rule_id") in {"VS-LIFE-REF-LIVE-001", "VS-LIFE-REF-INSERT-001", "VS-LIFE-KREF-LOCK-001"}:
            required_representations.append("object_identity facts")

        object_identity_status = "resolved" if candidate_id in resolved_object_candidates else "unresolved"
        validation_status = (
            "conditional_pass"
            if run.get("status") == "passed" and object_identity_status == "resolved"
            else "conditional_pass_object_unresolved"
            if run.get("status") == "passed"
            else "not_promoted"
        )

        instance_rows.append(
            {
                "rule_instance_id": f"vs-smoke-rule-instance-{idx:05d}",
                "task_id": run.get("task_id"),
                "candidate_id": candidate_id,
                "rule_run_id": run.get("rule_run_id"),
                "rule_template_id": run.get("rule_id"),
                "rule_family": run.get("rule_family"),
                "vulnerability_essence": rule_essence(run.get("rule_id")),
                "required_representations": required_representations,
                "evidence_packet_id": evidence.get("evidence_packet_id"),
                "tool_evidence_refs": {
                    "vulnerable_fact_refs": run.get("vulnerable_fact_refs", []),
                    "fixed_fact_refs": run.get("fixed_fact_refs", []),
                    "source_window_candidate_id": run.get("source_window_candidate_id"),
                },
                "object_identity_status": object_identity_status,
                "validation_status": validation_status,
                "normalized_rule_view": {
                    "rule_template_id": run.get("rule_id"),
                    "rule_family": run.get("rule_family"),
                    "rule_status": run.get("status"),
                    "object_identity_status": object_identity_status,
                    "model_rule_token": "|".join(
                        [
                            f"rule={run.get('rule_id')}",
                            f"family={run.get('rule_family')}",
                            f"status={run.get('status')}",
                            f"object_identity={object_identity_status}",
                        ]
                    ),
                },
                "promotion_policy": "Keep as codeql_conditional until object identity and any required path/callback evidence are tool-crosschecked.",
                "limitations": run.get("limitations", []),
            }
        )

        validation_rows.append(
            {
                "rule_validation_id": f"vs-smoke-rule-validation-{idx:05d}",
                "task_id": run.get("task_id"),
                "candidate_id": candidate_id,
                "rule_run_id": run.get("rule_run_id"),
                "rule_template_id": run.get("rule_id"),
                "rule_run_status": run.get("status"),
                "required_view_status": {
                    "source_window": "present" if candidate_id in source_window_candidates else "missing",
                    "tool_lifecycle_facts": "present"
                    if run.get("vulnerable_fact_refs") or run.get("fixed_fact_refs")
                    else "missing",
                    "object_identity_facts": object_identity_status,
                    "cfg_order_facts": "supporting_graph_available"
                    if candidate_id in graph_candidates
                    else "missing_required_tool_input",
                    "alias_dataflow_facts": "missing_required_tool_input",
                    "callback_graph_facts": "missing_required_tool_input",
                    "dynamic_oracle": "not_run",
                },
                "validation_status": validation_status,
                "label_strength_allowed": "codeql_conditional"
                if run.get("status") == "passed"
                else "not_promoted",
                "is_final_truth": False,
                "limitations": [
                    "Validation records the current evidence boundary.",
                    "Object-aware, alias-aware, callback-aware, or dynamic labels require additional tool outputs.",
                ],
            }
        )

    return instance_rows, validation_rows


def rule_essence(rule_id: str | None) -> str:
    essences = {
        "VS-LIFE-KREF-LOCK-001": "ref release should occur under the required mutex-protected release protocol",
        "VS-LIFE-REF-LIVE-001": "timer or async use should acquire a reference only if the object is still live",
        "VS-LIFE-RCU-DEFER-001": "RCU-list removal should defer release/free until the callback or grace-period path",
        "VS-LIFE-REF-INSERT-001": "fixed code inserts a live-object reference acquire that the vulnerable view lacks",
    }
    return essences.get(rule_id, "candidate-local lifecycle rule instance")


def update_tool_manifest(summary: dict[str, Any]) -> None:
    path = ROOT / "tool_run_manifest.jsonl"
    rows = read_jsonl(path)
    tool_run_id = "vs-smoke-toolrun-multiview-20-0001"
    rows = [row for row in rows if row.get("tool_run_id") != tool_run_id]
    rows.append(
        {
            "tool_run_id": tool_run_id,
            "tool": "VulnSignal multi-view artifact builder",
            "command": "python3 reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py",
            "status": "completed",
            "output_summary": "reports/e022_object_lifetime_smoke/multiview_artifact_summary_20.json",
            "artifacts": {name: str(path.relative_to(REPO)) for name, path in OUTPUTS.items()},
            "counts": summary["output_counts"],
            "limitations": [
                "Object identity is UNKNOWN unless tool-rendered identity evidence exists.",
                "Graph rows record availability unless parsed edges are available.",
            ],
        }
    )
    write_jsonl(path, rows)


def main() -> int:
    candidates = read_jsonl(ROOT / "candidate_locations_20_with_hard_negatives.jsonl")
    source_windows = read_jsonl(ROOT / "source_windows_20_with_hard_negatives.jsonl")
    codeql_facts = load_codeql_facts()
    coccinelle_rows = read_jsonl(ROOT / "coccinelle_window_lifecycle_matches_20.jsonl")
    wrapper_rows = read_jsonl(ROOT / "coccinelle_wrapper_candidate_matches_20.jsonl")
    joern_summary = read_json(ROOT / "joern_window_graph_summary.json", {})
    rule_runs = read_jsonl(ROOT / "codeql_conditional_rule_runs_20.jsonl")
    evidence_packets = read_jsonl(ROOT / "evidence_packets_20_codeql_conditional.jsonl")

    ast_rows, object_rows, operation_rows = build_operation_and_expression_facts(
        candidates,
        codeql_facts,
        coccinelle_rows,
        wrapper_rows,
    )
    control_rows, alias_rows, callback_rows, graph_candidates = build_graph_rows(candidates, joern_summary)
    instance_rows, validation_rows = build_rule_rows(
        rule_runs,
        evidence_packets,
        source_window_ids(source_windows),
        object_rows,
        graph_candidates,
    )

    rows_by_output = {
        "ast_expression_facts": ast_rows,
        "object_identity_facts": object_rows,
        "operation_role_facts": operation_rows,
        "control_flow_order_facts": control_rows,
        "alias_dataflow_facts": alias_rows,
        "callback_graph_facts": callback_rows,
        "vulnerability_rule_instances": instance_rows,
        "vulnerability_rule_validation": validation_rows,
    }
    for name, rows in rows_by_output.items():
        write_jsonl(OUTPUTS[name], rows)

    object_status_counts = Counter(row.get("identity_status") for row in object_rows)
    rule_validation_counts = Counter(row.get("validation_status") for row in validation_rows)
    graph_status_counts = Counter(row.get("status") for row in control_rows)

    summary = {
        "status": "completed",
        "artifact_purpose": "tool-derived multi-view bridge between evidence extraction and model input encoders",
        "input_counts": {
            "candidate_locations": len(candidates),
            "source_windows": len(source_windows),
            "codeql_fact_rows": len(codeql_facts),
            "coccinelle_view_rows": len(coccinelle_rows),
            "coccinelle_wrapper_view_rows": len(wrapper_rows),
            "rule_runs": len(rule_runs),
            "evidence_packets": len(evidence_packets),
        },
        "output_counts": {name: len(rows) for name, rows in rows_by_output.items()},
        "object_identity_counts": dict(object_status_counts),
        "rule_validation_counts": dict(rule_validation_counts),
        "control_flow_status_counts": dict(graph_status_counts),
        "policy": {
            "normalization": "tool-derived views with candidate-level alignment; fine-grained cross-view relationships are learned unless a tool explicitly provides them for validation",
            "model_visible_generalization": [
                "normalized_operation_role",
                "api_family",
                "operation_class",
                "security_axis",
                "lifecycle_stage",
                "identity_status",
                "missing-view status",
                "rule_family",
            ],
            "audit_only_raw_fields": [
                "callee",
                "object_expression",
                "file",
                "function",
                "source windows",
            ],
            "unknown_object_id": UNKNOWN_OBJECT_ID,
            "no_manual_source_text_identity": True,
            "stronger_label_blocker": "object identity, alias/dataflow, callback graph, and dynamic oracle views are still incomplete for most candidates",
            "default_model_input_alignment": "task_id + candidate_id + source location + view + producer tool + missing-view mask",
            "explicit_relationship_edges": "not required for default inference; use only as optional tool-proven validation evidence",
        },
        "outputs": {name: str(path.relative_to(REPO)) for name, path in OUTPUTS.items()},
    }
    write_json(ROOT / "multiview_artifact_summary_20.json", summary)
    update_tool_manifest(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
