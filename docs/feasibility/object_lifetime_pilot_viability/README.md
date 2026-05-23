# Object-Lifetime / Refcount Pilot Viability Gate

Date: 2026-05-18

## Decision

The first object-lifetime/refcount dataset is viable as a **100-task candidate pilot** if the dataset preserves label strength and does not pretend that every task is a reproduced vulnerability.

The pilot should target:

```text
100 task_instances
5,000-10,000 candidate_locations
one primary family: C/C++ object lifetime, refcount, RCU/free, async work/free, and use-after-free lifecycle rules
label strengths: dynamic, codeql_conditional, patch_confirmed_weak, weak, UNKNOWN
```

The gate is **not** passed for "100 strong dynamic-oracle Linux refcount vulnerabilities." That stronger claim is not proven by the current evidence. The realistic first dataset is a mixed-strength, tool-grounded pilot where strong and conditional rows are separated from weak and UNKNOWN rows.

Mixed-strength evidence is not a temporary embarrassment or a hidden weakness. It is the expected long-term condition for a real vulnerability-research dataset, especially as VulnSignal expands to additional vulnerability families. The model and evaluation protocol must accommodate this directly: train with label-strength weighting, use weak rows carefully, preserve UNKNOWN instead of forcing false negatives, and report metrics by evidence strength.

## Four-Point Validation

### 1. Credible original sources

The pilot can draw from these source families:

| Source | Why it is usable | Expected role |
| --- | --- | --- |
| NVD CVE records | Public CVE metadata with descriptions, references, affected product context, and patch/advisory links. | Candidate discovery and weak provenance. |
| Linux kernel upstream stable/CVE-style commit descriptions | Many Linux kernel CVE descriptions now include the upstream fix commit message, crash stack, subsystem, and root-cause narrative. | Primary source for object-lifetime/refcount task creation after source snapshot and patch anchors are resolved. |
| syzkaller / syzbot dashboard | Public Linux kernel crash reports often include KASAN reports, syz reproducers, C reproducers, fix status, patch links, configs, and logs. | Stronger dynamic-oracle seeds when a reproducer and fixed source can be tied to the candidate. |
| OSS-Fuzz / ClusterFuzz public issues | Public reproduced crash reports with fuzz target, reproducer testcase, sanitizer, and stack trace. Less Linux-refcount-specific, but useful for broader C/C++ lifecycle/memory-safety expansion. | Dynamic-oracle seeds and fuzz-guidance supervision when object-lifetime-like cases exist. |
| CVEfixes / MoreFixes / OSV / GHSA | Large patch/advisory corpora with commit links and metadata. | Candidate expansion and deduplication, not final truth alone. |
| Magma-style benchmarks | Real-bug fuzzing benchmark infrastructure with reproducible targets. Not focused on Linux refcount. | Optional oracle/evaluation source for broader memory-safety families. |

Primary source links:

- NVD CVE API: <https://nvd.nist.gov/developers/vulnerabilities>
- syzkaller dashboard: <https://syzkaller.appspot.com/>
- OSS-Fuzz reproducing guide: <https://google.github.io/oss-fuzz/advanced-topics/reproducing/>
- Magma technical docs: <https://hexhive.epfl.ch/magma/docs/technical.html>
- CVEfixes paper: <https://arxiv.org/abs/2107.08760>

### 2. Whether 50-100 task instances are realistic

Public keyword counts show a large candidate pool, but the counts are noisy and must go through an admission funnel.

Commands used:

```bash
for q in \
  'refcount linux kernel' \
  'reference count linux kernel' \
  'kref linux kernel' \
  'use-after-free linux kernel' \
  'RCU use-after-free linux kernel' \
  'double free linux kernel' \
  'race condition use-after-free linux kernel' \
  'object lifetime linux kernel'
do
  url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(printf '%s' "$q" | sed 's/ /%20/g')&resultsPerPage=1"
  printf '%s\t' "$q"
  curl -s "$url" | jq -r '.totalResults'
  sleep 1
done
```

Observed NVD keyword counts on 2026-05-18:

| Query | NVD `totalResults` | Interpretation |
| --- | ---: | --- |
| `refcount linux kernel` | 618 | Large but noisy candidate pool. Includes underflow, leak, and refcount mention, not all true lifecycle tasks. |
| `reference count linux kernel` | 315 | Useful expansion query for non-`refcount` wording. |
| `kref linux kernel` | 45 | Higher precision for Linux object lifecycle, but smaller. |
| `use-after-free linux kernel` | 1258 | Broad temporal memory pool; must filter to lifecycle/refcount/RCU/async patterns. |
| `RCU use-after-free linux kernel` | 92 | Strong candidate pool for RCU lifetime tasks. |
| `double free linux kernel` | 244 | Adjacent memory-lifecycle family; useful for expansion, not pure refcount. |
| `race condition use-after-free linux kernel` | 140 | Useful for concurrency-sensitive lifecycle tasks. |
| `object lifetime linux kernel` | 16 | High-relevance phrase, but too narrow as a primary query. |

Representative NVD records from the query sample included:

- `CVE-2021-46968`: kref get/put mismatch causing zcard/zqueue hot-unplug leak.
- `CVE-2021-47078`: refcount underflow / use-after-free path in RDMA rxe cleanup.
- `CVE-2023-52503`: race around `kref_put()` / session destruction causing use-after-free.
- `CVE-2021-47100`: IPMI uninstall path, kref, scheduled work, and use-after-free.
- `CVE-2024-26939`: object active/retire lifetime race in i915 VMA handling.
- `CVE-2024-56549`: object/file lifetime mismatch with additional reference-count fix.
- `CVE-2023-6932`: RCU read-locked object freed by another thread.
- `CVE-2023-52438`: KASAN use-after-free involving VMA lifetime and RCU free.
- `CVE-2023-52447`: BPF inner map free deferred through RCU to avoid use-after-free.
- `CVE-2021-46929`: `call_rcu()` used to delay endpoint free and prevent use-after-free.

Estimate:

```text
raw public candidate pool: hundreds
after deduplication, Linux/upstream-source availability, and relevance filtering: likely 120-250 candidate records
after task normalization and source snapshot anchoring: likely 60-140 viable task_instances
after requiring strong dynamic reproduction only: likely far below 100 without a major reproduction campaign
```

Conclusion: 50-100 mixed-strength object-lifetime/refcount task instances are realistic. 100 fully reproduced strong-oracle tasks are not currently justified.

### 3. Strong vs weak / UNKNOWN separation

The first dataset must admit tasks only with explicit label strength.

| Label strength | Admission rule | Expected pilot role |
| --- | --- | --- |
| `dynamic` | Reproducer, crash, sanitizer output, source snapshot, fixed snapshot, and pre-patch FAIL / post-patch PASS evidence are available. | Strongest supervision and evaluation. |
| `codeql_conditional` | VulnSignal CodeQL/lifecycle validator produces `rule_matched`, `rule_not_matched`, or `rule_unknown` under a recorded rule ID. | Main evidence-level pilot supervision. |
| `patch_confirmed_weak` | Patch clearly changes lifecycle/refcount protocol, but no reproduced oracle and no completed rule check yet. | Candidate generation and weak supervision only. |
| `weak` | CVE/advisory/commit text suggests object lifetime but source, line anchors, or rule facts are incomplete. | Discovery queue, not final model truth. |
| `UNKNOWN` | Source unavailable, build unavailable, object identity unresolved, tool facts incomplete, or rule does not apply cleanly. | Calibration and abstention training/evaluation. |

Do not balance the dataset by inventing non-vulnerable functions. Negatives should come from same-task hard negatives: nearby functions, same-file functions, callgraph/dataflow neighbors, CodeQL/checker `rule_not_matched` rows, and candidate locations near but not equal to the root-cause evidence.

### 4. Tool evidence feasibility

The source-code evidence can be generated with parser-backed and checker-backed tools. The pilot should not rely on grep-only event extraction.

| Evidence need | Primary tool | Feasibility | Notes |
| --- | --- | --- | --- |
| Source windows | Repository checkout plus parser-backed source-window extractor | High | Raw source windows remain preserved for audit. |
| Protocol/API events | Coccinelle and Joern queries | High for known lifecycle APIs; medium for custom wrappers | Emit `alloc`, `get`, `put`, `kref_put`, `kfree`, `call_rcu`, `queue_work`, `cancel_work`, `flush_work`, publish/remove, lock/unlock events. |
| Structured fact/path records | Joern CPG/CFG/DDG exports, SVF when available | Medium-high | Good for source anchors, calls, dataflow-like graph records, path nodes, and callback cues. Hard cases still need UNKNOWN handling. |
| Evidence-level validation | CodeQL lifecycle validators | Medium | Primary validation tool for candidate evidence level; blocked runs become `rule_unknown`. |
| Linux semantic patterns | Coccinelle report mode | Medium | Supplemental evidence for known API misuse and wrapper patterns; false positives require audit. |
| Function pointers / indirect callbacks | SVF pointer analysis, Joern graph exports | Medium | Useful for hard cases, but not first-line truth. |
| RCU/workqueue async edges | CodeQL/Coccinelle/Joern facts plus rule-specific bridge edges | Medium | Can capture registration and source anchors; cannot prove runtime interleavings alone. |
| Dynamic oracle | syzkaller, KASAN/KCSAN, project reproducers | Medium for selected seeds; expensive at scale | Strong labels require reproduction budget. |

Local feasibility evidence already exists in:

- `docs/feasibility/hardcase_tool_feasibility/README.md`

That experiment validated source-anchored extraction for wrappers, macro-expanded calls, workqueue-like events, RCU registration, function-pointer call sites, Joern graph export, and SVF indirect-call target resolution on controlled fixtures.

Relevant tool references:

- CodeQL C/C++ data flow docs: <https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/>
- CodeQL C/C++ built-in queries: <https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/c-cpp-built-in-queries>
- Coccinelle in Linux docs: <https://docs.kernel.org/dev-tools/coccinelle.html>
- SVF technical docs: <https://github-wiki-see.page/m/SVF-tools/SVF/wiki/Technical-documentation>

## Admission Funnel for the First 100

Use this process before training:

1. Query public sources for CVEs/issues with object-lifetime/refcount terms.
2. Deduplicate by CVE, upstream commit, subsystem, and root-cause function.
3. Keep only C/C++ source with public repository access and source snapshot identifiers.
4. Classify candidate family:
   - `kref_refcount`
   - `rcu_lifetime`
   - `async_work_lifetime`
   - `publish_remove_lifetime`
   - `uaf_lifecycle_general`
5. Create one `task_instance` per source snapshot plus rule/advisory/crash question.
6. Generate candidates from patch hunks, crash stack frames, CodeQL paths, same-function windows, same-file related functions, callgraph/dataflow neighbors, and hard negatives.
7. Run lifecycle fact extraction and record missing evidence as UNKNOWN.
8. Assign label strength only after evidence review.

Target composition for the first dataset:

| Bucket | Target count | Label expectation |
| --- | ---: | --- |
| kref/refcount mismatch | 20-30 | mix of `codeql_conditional`, `patch_confirmed_weak`, `dynamic` |
| RCU lifetime / delayed free | 15-25 | mix of `codeql_conditional`, `dynamic`, `UNKNOWN` |
| workqueue/timer/callback lifetime | 15-25 | mix of `codeql_conditional`, `patch_confirmed_weak`, `UNKNOWN` |
| publish/remove/list lifetime | 15-25 | mix of `codeql_conditional`, `patch_confirmed_weak`, `UNKNOWN` |
| general UAF lifecycle with source anchors | 20-30 | mix of `dynamic`, `patch_confirmed_weak`, `UNKNOWN` |

The target is intentionally overlapping; final dataset construction must deduplicate and cap per subsystem to avoid overfitting to one kernel area.

## Blockers and Stop Conditions

Block model training if any of these remain true:

- Fewer than 50 task instances have public source snapshots and candidate-location rows.
- Fewer than 25 task instances have either `dynamic` or `codeql_conditional` labels.
- CodeQL/lifecycle extraction cannot emit source-anchored protocol/API events for at least the known APIs in the pilot rule suite.
- More than half of accepted tasks are patch/advisory text only with no source anchors.
- Train/test splits are not project-disjoint or time-disjoint enough to prevent patch memorization.
- Candidate windows are hand-picked instead of generated by the pipeline.

## Confidence

Confidence: **medium-high for building a 50-task pilot**, **medium for reaching 100 mixed-strength task instances**, and **low for reaching 100 strong dynamic-oracle-only tasks without a reproduction campaign**.

Recommended next step:

```text
Build a source-admission spreadsheet/JSONL for the first 150 raw candidate records,
then promote only the first 100 records that survive source snapshot, candidate generation,
CodeQL fact extraction, and label-strength review.
```
