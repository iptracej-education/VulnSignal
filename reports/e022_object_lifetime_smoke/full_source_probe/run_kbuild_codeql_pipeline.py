#!/usr/bin/env python3
"""Run a bounded Kbuild-backed CodeQL extraction attempt for smoke tasks.

This script intentionally writes generated outputs under reports/ and .tools/.
It does not commit, push, add remotes, or modify the VulnSignal repository's
Git configuration.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
REPORT_ROOT = REPO_ROOT / "reports" / "e022_object_lifetime_smoke"
PROBE_ROOT = REPORT_ROOT / "full_source_probe"
TOOLS_ROOT = REPO_ROOT / ".tools" / "kernel-work"
ANALYSIS_ENV = REPO_ROOT / ".tools" / "vulnsignal-analysis"
QUERY = PROBE_ROOT / "queries" / "ExtractLifecycleSourceFacts.ql"

MAX_TASKS = int(os.environ.get("VS_MAX_TASKS", "20"))
RUN_CODEQL = os.environ.get("VS_RUN_CODEQL", "1") != "0"
ONLY_TASKS = {item for item in os.environ.get("VS_ONLY_TASKS", "").split(",") if item}
OUTPUT_SUFFIX = os.environ.get("VS_OUTPUT_SUFFIX", "")
EXTRACTION_VIEW = os.environ.get("VS_VIEW", "fixed")

TASK_CONFIG_ENABLES = {
    "vs-smoke-T0003": [
        "CRYPTO",
        "CRYPTO_DEV_CCP",
        "CRYPTO_DEV_CCP_DD",
        "CRYPTO_DEV_SP_CCP",
        "CRYPTO_DEV_SP_PSP",
        "TEE",
        "AMDTEE",
    ],
    "vs-smoke-T0015": [
        "IEEE802154",
        "IEEE802154_SOCKET",
        "MAC802154",
        "MAC802154_LLSEC",
    ],
    "vs-smoke-T0016": [
        "PECI",
        "PECI_CPU",
    ],
    "vs-smoke-T0017": [
        "BT",
        "BT_BREDR",
        "BT_SCO",
    ],
}


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def append_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=False) + "\n")


def infer_repo_and_commit(row: dict) -> tuple[str, str]:
    if row.get("repository_url") and row.get("fixed_commit"):
        return row["repository_url"], row["fixed_commit"]

    url = row["primary_patch_url"]
    match = re.search(r"(?:id=|/c/)([0-9a-f]{12,40})", url)
    if not match:
        raise ValueError(f"Cannot parse commit SHA from {url}")
    commit = match.group(1)

    if "wireless/wireless.git" in url:
        repo = "https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless.git"
    elif "torvalds/linux.git" in url:
        repo = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    else:
        repo = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    return repo, commit


def patch_url(repo: str, commit: str) -> str:
    return f"{repo}/patch/?id={commit}"


def fetch_text(url: str) -> tuple[int, str]:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "VulnSignal-research-probe/0.1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


def changed_c_files(patch: str) -> list[str]:
    files: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        path = parts[3]
        if path.startswith("b/"):
            path = path[2:]
        if path.endswith(".c") and path not in files:
            files.append(path)
    return files


def object_target(source_path: str) -> str:
    return source_path[:-2] + ".o"


def env_for_build() -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{ANALYSIS_ENV / 'bin'}:/usr/local/bin:/usr/bin:/bin"
    env["C_INCLUDE_PATH"] = str(ANALYSIS_ENV / "include")
    env["LIBRARY_PATH"] = str(ANALYSIS_ENV / "lib")
    return env


def ensure_checkout(repo: str, fetch_ref: str, checkout_ref: str) -> tuple[Path, list[dict]]:
    repo_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", repo.replace("https://", ""))
    checkout = TOOLS_ROOT / f"checkout-{repo_key}"
    events: list[dict] = []
    checkout.parent.mkdir(parents=True, exist_ok=True)

    if not (checkout / ".git").exists():
        checkout.mkdir(parents=True, exist_ok=True)
        events.append({"step": "git_init", "cmd": f"git init {checkout}"})
        proc = run(["git", "init", str(checkout)], cwd=REPO_ROOT, timeout=60)
        events[-1]["returncode"] = proc.returncode
        events[-1]["output_tail"] = proc.stdout[-1000:]
        if proc.returncode != 0:
            return checkout, events

    events.append({"step": "git_fetch", "cmd": f"git fetch --depth=2 {repo} {fetch_ref}"})
    proc = run(["git", "fetch", "--depth=2", repo, fetch_ref], cwd=checkout, timeout=900)
    events[-1]["returncode"] = proc.returncode
    events[-1]["output_tail"] = proc.stdout[-1500:]
    if proc.returncode != 0:
        return checkout, events

    events.append({"step": "git_checkout", "cmd": f"git checkout --detach {checkout_ref}"})
    proc = run(["git", "checkout", "--detach", checkout_ref], cwd=checkout, timeout=180)
    events[-1]["returncode"] = proc.returncode
    events[-1]["output_tail"] = proc.stdout[-1500:]
    if proc.returncode != 0:
        return checkout, events

    events.append({"step": "git_clean", "cmd": "git clean -fdx"})
    proc = run(["git", "clean", "-fdx"], cwd=checkout, timeout=300)
    events[-1]["returncode"] = proc.returncode
    events[-1]["output_tail"] = proc.stdout[-1500:]
    return checkout, events


def ensure_prepared(task_id: str, checkout: Path) -> list[dict]:
    events: list[dict] = []
    env = env_for_build()
    if not (checkout / ".config").exists():
        events.append({"step": "make_defconfig", "cmd": "make defconfig"})
        proc = run(["make", "defconfig"], cwd=checkout, env=env, timeout=900)
        events[-1]["returncode"] = proc.returncode
        events[-1]["output_tail"] = proc.stdout[-2000:]
        if proc.returncode != 0:
            return events

    config_script = checkout / "scripts" / "config"
    if config_script.exists():
        for config_name in TASK_CONFIG_ENABLES.get(task_id, []):
            events.append({"step": f"enable_config_{config_name}", "cmd": f"scripts/config -e {config_name}"})
            proc = run([str(config_script), "-e", config_name], cwd=checkout, env=env, timeout=120)
            events[-1]["returncode"] = proc.returncode
            events[-1]["output_tail"] = proc.stdout[-2000:]

        events.append({"step": "disable_objtool_stack_validation", "cmd": "scripts/config -d STACK_VALIDATION -d UNWINDER_ORC -e UNWINDER_FRAME_POINTER"})
        proc = run(
            [str(config_script), "-d", "STACK_VALIDATION", "-d", "UNWINDER_ORC", "-e", "UNWINDER_FRAME_POINTER"],
            cwd=checkout,
            env=env,
            timeout=120,
        )
        events[-1]["returncode"] = proc.returncode
        events[-1]["output_tail"] = proc.stdout[-2000:]

        events.append({"step": "make_olddefconfig", "cmd": "make olddefconfig"})
        proc = run(["make", "olddefconfig"], cwd=checkout, env=env, timeout=900)
        events[-1]["returncode"] = proc.returncode
        events[-1]["output_tail"] = proc.stdout[-2000:]
        if proc.returncode != 0:
            return events

    events.append({"step": "make_prepare_scripts", "cmd": "make prepare scripts"})
    proc = run(["make", "prepare", "scripts"], cwd=checkout, env=env, timeout=1200)
    events[-1]["returncode"] = proc.returncode
    events[-1]["output_tail"] = proc.stdout[-2000:]
    return events


def build_codeql_db(task_id: str, checkout: Path, source_path: str) -> tuple[Path, list[dict]]:
    db = TOOLS_ROOT / f"codeql-db-{task_id}-{source_path.replace('/', '_').replace('.', '_')}"
    if db.exists():
        shutil.rmtree(db)

    build_script = PROBE_ROOT / "build_target_for_codeql.sh"
    target = object_target(source_path)
    cmd = [
        "codeql",
        "database",
        "create",
        str(db),
        "--language=cpp",
        "--source-root",
        str(checkout),
        "--command",
        f"bash {build_script} {target}",
    ]
    proc = run(cmd, cwd=checkout, timeout=1800)
    event = {
        "step": "codeql_database_create",
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
        "output_tail": proc.stdout[-3000:],
    }
    return db, [event]


def run_query(task_id: str, db: Path, source_path: str) -> tuple[list[dict], list[dict]]:
    bqrs = TOOLS_ROOT / f"{task_id}-{source_path.replace('/', '_').replace('.', '_')}.bqrs"
    csv_path = TOOLS_ROOT / f"{task_id}-{source_path.replace('/', '_').replace('.', '_')}.csv"
    events: list[dict] = []
    facts: list[dict] = []

    proc = run(["codeql", "query", "run", str(QUERY), "--database", str(db), "--output", str(bqrs)], cwd=REPO_ROOT, timeout=900)
    events.append({"step": "codeql_query_run", "returncode": proc.returncode, "output_tail": proc.stdout[-2000:]})
    if proc.returncode != 0:
        return facts, events

    proc = run(["codeql", "bqrs", "decode", "--format=csv", str(bqrs)], cwd=REPO_ROOT, timeout=300)
    events.append({"step": "codeql_bqrs_decode", "returncode": proc.returncode, "output_tail": proc.stdout[:500] + proc.stdout[-1500:]})
    if proc.returncode != 0:
        return facts, events

    csv_path.write_text(proc.stdout)
    reader = csv.DictReader(proc.stdout.splitlines())
    for raw in reader:
        file_path = raw.get("col5", "")
        if file_path != source_path:
            continue
        facts.append(
            {
                "fact_kind": raw.get("col1"),
                "role": raw.get("role"),
                "callee": raw.get("col3"),
                "enclosing_function": raw.get("col4"),
                "file": file_path,
                "line": int(raw.get("col6") or 0),
                "query_call": raw.get("call"),
            }
        )
    return facts, events


def main() -> int:
    seed_rows = load_jsonl(PROBE_ROOT / "task_manifest_seed.jsonl")
    expansion_rows = load_jsonl(REPORT_ROOT / "task_expansion_candidates.jsonl")
    tasks = (seed_rows + expansion_rows)[:MAX_TASKS]
    if ONLY_TASKS:
        tasks = [task for task in tasks if task["task_id"] in ONLY_TASKS]

    patch_rows: list[dict] = []
    materialized_rows: list[dict] = []
    run_rows: list[dict] = []
    fact_rows: list[dict] = []

    for row in tasks:
        task_id = row["task_id"]
        repo, commit = infer_repo_and_commit(row)
        p_url = patch_url(repo, commit)
        status, patch = fetch_text(p_url)
        files = changed_c_files(patch) if status == 200 else []
        patch_rows.append(
            {
                "task_id": task_id,
                "cve_or_issue_id": row.get("cve_or_issue_id"),
                "repository_url": repo,
                "fixed_commit": commit,
                "patch_url": p_url,
                "http_status": status,
                "changed_c_files": files,
                "changed_c_file_count": len(files),
                "patch_fetch_status": "ok" if status == 200 else "failed",
            }
        )
        materialized_rows.append(
            {
                "task_id": task_id,
                "source_record_id": row.get("source_record_id"),
                "cve_or_issue_id": row.get("cve_or_issue_id"),
                "project": "linux_kernel",
                "task_family": row.get("candidate_family"),
                "source_snapshot_status": "patch_metadata_resolved" if files else "patch_metadata_failed",
                "repository_url": repo,
                "fixed_commit": commit,
                "vulnerable_ref": f"{commit}^",
                "affected_c_files": files,
                "task_question": f"Rank source locations involved in {row.get('title', task_id)}.",
                "oracle_available": False,
                "checker_available": "kbuild_codeql_attempted" if RUN_CODEQL else "pending_kbuild_codeql",
                "initial_label_strength": row.get("initial_label_strength", "patch_confirmed_weak"),
                "split_policy": "unassigned_until_dedup",
            }
        )

        if not RUN_CODEQL or not files:
            continue

        checkout_ref = commit if EXTRACTION_VIEW == "fixed" else f"{commit}^"
        checkout, events = ensure_checkout(repo, commit, checkout_ref)
        run_rows.append({"task_id": task_id, "repository_url": repo, "fixed_commit": commit, "checkout_ref": checkout_ref, "view": EXTRACTION_VIEW, "source_file": None, "status": "checkout", "events": events})
        if any(event.get("returncode") not in (0, None) for event in events):
            continue

        events = ensure_prepared(task_id, checkout)
        run_rows.append({"task_id": task_id, "repository_url": repo, "fixed_commit": commit, "checkout_ref": checkout_ref, "view": EXTRACTION_VIEW, "source_file": None, "status": "prepare", "events": events})
        if any(event.get("returncode") not in (0, None) for event in events):
            continue

        for source_path in files:
            db, events = build_codeql_db(task_id, checkout, source_path)
            status_name = "db_created" if events and events[-1]["returncode"] == 0 else "db_failed"
            run_rows.append({"task_id": task_id, "repository_url": repo, "fixed_commit": commit, "checkout_ref": checkout_ref, "view": EXTRACTION_VIEW, "source_file": source_path, "status": status_name, "events": events})
            if status_name != "db_created":
                continue
            facts, events = run_query(task_id, db, source_path)
            run_rows.append({"task_id": task_id, "repository_url": repo, "fixed_commit": commit, "checkout_ref": checkout_ref, "view": EXTRACTION_VIEW, "source_file": source_path, "status": "query_ran", "events": events, "candidate_relevant_fact_count": len(facts)})
            for index, fact in enumerate(facts, start=1):
                fact_rows.append(
                    {
                        "fact_id": f"vs-smoke-FS-{task_id}-{index:04d}",
                        "task_id": task_id,
                        "tool_run_id": "vs-smoke-toolrun-kbuild-batch-0001",
                        "view": EXTRACTION_VIEW,
                        "source": "CodeQL full-source Kbuild-backed extraction",
                        "repository_url": repo,
                        "commit": checkout_ref,
                        **fact,
                    }
                )

    write_jsonl(REPORT_ROOT / f"patch_metadata_20_tasks{OUTPUT_SUFFIX}.jsonl", patch_rows)
    write_jsonl(REPORT_ROOT / f"task_instances_20_candidate_materialization{OUTPUT_SUFFIX}.jsonl", materialized_rows)
    write_jsonl(REPORT_ROOT / f"kbuild_codeql_run_log{OUTPUT_SUFFIX}.jsonl", run_rows)
    write_jsonl(REPORT_ROOT / f"full_source_codeql_facts_batch{OUTPUT_SUFFIX}.jsonl", fact_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
