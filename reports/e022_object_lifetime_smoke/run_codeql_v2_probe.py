#!/usr/bin/env python3
"""Run the v2 lifecycle CodeQL query on existing local CodeQL databases."""

from __future__ import annotations

import csv
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
QUERY = ROOT / "full_source_probe" / "queries" / "ExtractLifecycleSourceFactsV2.ql"
QLPACK = ROOT / "full_source_probe"
DB_ROOT = REPO_ROOT / ".tools" / "kernel-work"


TASK_DBS = {
    "vs-smoke-T0003": "codeql-db-vs-smoke-T0003-drivers_tee_amdtee_core_c",
    "vs-smoke-T0005": "codeql-db-vs-smoke-T0005-net_ipv4_igmp_c",
    "vs-smoke-T0007": "codeql-db-vs-smoke-T0007-drivers_media_dvb-core_dmxdev_c",
    "vs-smoke-T0008": "codeql-db-vs-smoke-T0008-net_wireless_scan_c",
    "vs-smoke-T0013": "codeql-db-vs-smoke-T0013-net_ipv4_tcp_minisocks_c",
    "vs-smoke-T0014-direct": "codeql-db-vs-smoke-T0014-fs_nfs_direct_c",
    "vs-smoke-T0014-write": "codeql-db-vs-smoke-T0014-fs_nfs_write_c",
    "vs-smoke-T0015": "codeql-db-vs-smoke-T0015-net_mac802154_llsec_c",
    "vs-smoke-T0016": "codeql-db-vs-smoke-T0016-drivers_peci_cpu_c",
    "vs-smoke-T0017": "codeql-db-vs-smoke-T0017-net_bluetooth_sco_c",
    "vs-smoke-T0018": "codeql-db-vs-smoke-T0018-net_ipv4_tcp_ipv4_c",
    "vs-smoke-T0020": "codeql-db-vs-smoke-T0020-drivers_misc_fastrpc_c",
}


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def write_json(path: Path, row: dict) -> None:
    with path.open("w") as fh:
        json.dump(row, fh, indent=2, sort_keys=False)
        fh.write("\n")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def decode_csv(text: str) -> list[list[str]]:
    return list(csv.reader(text.splitlines()))


def normalize_rows(task_key: str, view: str, csv_rows: list[list[str]]) -> list[dict]:
    if not csv_rows:
        return []
    normalized = []
    for index, row in enumerate(csv_rows[1:], start=1):
        if len(row) < 14:
            continue
        task_id = task_key.split("-direct")[0].split("-write")[0]
        normalized.append(
            {
                "fact_id": f"vs-smoke-FSV2-{task_key}-{index:04d}",
                "task_id": task_id,
                "task_db_key": task_key,
                "view": view,
                "fact_kind": row[1],
                "role": row[2],
                "callee": row[3],
                "enclosing_function": row[4],
                "file": row[5],
                "line_start": int(row[6]),
                "line_end": int(row[7]),
                "arg0": row[8],
                "arg1": row[9],
                "arg2": row[10],
                "arg0_file": row[11],
                "arg0_line": int(row[12]),
                "query_call": row[13],
                "limitations": [
                    "CodeQL Expr.toString may abbreviate complex expressions.",
                    "Use this as object-aware extraction input, then cross-check with source windows or graph facts.",
                ],
            }
        )
    return normalized


def main() -> int:
    only = os.environ.get("VS_ONLY_TASKS", "")
    view = os.environ.get("VS_VIEW", "current_db_snapshot")
    selected = [item.strip() for item in only.split(",") if item.strip()] or sorted(TASK_DBS)

    output_rows = []
    run_rows = []
    for task_key in selected:
        db_name = TASK_DBS.get(task_key)
        if not db_name:
            run_rows.append({"task_db_key": task_key, "status": "unknown_task_key"})
            continue
        db = DB_ROOT / db_name
        if not db.exists():
            run_rows.append({"task_db_key": task_key, "status": "missing_database", "database": str(db)})
            continue

        bqrs = DB_ROOT / f"{task_key}-lifecycle-v2.bqrs"
        query = run(
            [
                "codeql",
                "query",
                "run",
                str(QUERY),
                "--database",
                str(db),
                "--output",
                str(bqrs),
                "--search-path",
                str(QLPACK),
            ]
        )
        if query.returncode != 0:
            run_rows.append(
                {
                    "task_db_key": task_key,
                    "status": "query_failed",
                    "returncode": query.returncode,
                    "stderr_tail": query.stderr[-2000:],
                    "stdout_tail": query.stdout[-2000:],
                }
            )
            continue

        decoded = run(["codeql", "bqrs", "decode", "--format=csv", str(bqrs)])
        if decoded.returncode != 0:
            run_rows.append(
                {
                    "task_db_key": task_key,
                    "status": "decode_failed",
                    "returncode": decoded.returncode,
                    "stderr_tail": decoded.stderr[-2000:],
                }
            )
            continue

        rows = normalize_rows(task_key, view, decode_csv(decoded.stdout))
        output_rows.extend(rows)
        run_rows.append(
            {
                "task_db_key": task_key,
                "status": "completed",
                "view": view,
                "database": str(db.relative_to(REPO_ROOT)),
                "row_count": len(rows),
            }
        )

    suffix = os.environ.get("VS_OUTPUT_SUFFIX", "")
    write_jsonl(ROOT / f"full_source_codeql_facts_v2{suffix}.jsonl", output_rows)
    write_jsonl(ROOT / f"codeql_v2_run_log{suffix}.jsonl", run_rows)
    write_json(
        ROOT / f"codeql_v2_summary{suffix}.json",
        {
            "selected_task_db_keys": selected,
            "view": view,
            "row_count": len(output_rows),
            "completed_databases": sum(1 for row in run_rows if row.get("status") == "completed"),
            "limitations": [
                "Existing local DB paths may have been reused across fixed/vulnerable runs.",
                "For label promotion, run from fresh view-specific databases or record the view source explicitly.",
            ],
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
