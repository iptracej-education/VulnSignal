# VulnSignal Execution Plan

## Strategic Objective

Build a tool-grounded candidate-ranking dataset and model pipeline for real vulnerability research. VulnSignal ranks suspicious source-code locations and preserves evidence strength; it does not train a generic vulnerable/non-vulnerable function classifier.

## Current Status

Current phase: **Phase 1A - 20-task object-lifetime/refcount smoke dataset**.

Do not start neural model training yet. The immediate goal is to prove that real public source records can be converted into task instances, candidate locations, source windows, CodeQL/lifecycle facts, and label-strength records.

Progress:

| Area | Status | Evidence |
| --- | --- | --- |
| Proposal and project framing | Complete | `docs/PROPOSAL.md` |
| Hard-case extraction feasibility | Complete | `docs/feasibility/hardcase_tool_feasibility/README.md` |
| Object-lifetime pilot viability gate | Complete enough to proceed | `docs/feasibility/object_lifetime_pilot_viability/README.md` |
| 100-task dataset | Not started | Must first pass the 20-task smoke gate. |
| Neural ranker | Blocked | Requires stable dataset rows, baselines, and leakage controls. |

## Immediate Priority

Build the first **20 admitted object-lifetime/refcount task instances** before scaling to 100.

Required smoke-dataset outputs:

```text
reports/e022_object_lifetime_smoke/source_acquisition_manifest.jsonl
reports/e022_object_lifetime_smoke/raw_candidate_sources.jsonl
reports/e022_object_lifetime_smoke/task_instances.jsonl
reports/e022_object_lifetime_smoke/candidate_locations.jsonl
reports/e022_object_lifetime_smoke/source_windows.jsonl
reports/e022_object_lifetime_smoke/protocol_api_sequences.jsonl
reports/e022_object_lifetime_smoke/structured_facts_paths.jsonl
reports/e022_object_lifetime_smoke/labels.jsonl
reports/e022_object_lifetime_smoke/dataset_card.md
```

## Phase 0 - Project Setup and Feasibility Gates

Status: **complete for planning; keep updated as evidence changes**.

Completed:

1. Keep prior experiment references as historical evidence only when they support vocabulary, leakage control, or evidence-packet design.
2. Maintain VulnSignal primary documents.
3. Keep README focused on VulnSignal as tool-grounded candidate ranking.
4. Maintain roadmap and architecture diagrams.
5. Validate hard-case extraction tooling for wrappers, callbacks, RCU-like registration, workqueue-like events, graph exports, and indirect-call facts.
6. Validate that a 50-100 mixed-strength object-lifetime/refcount pilot is plausible, while blocking the stronger unsupported claim of 100 fully reproduced dynamic-oracle refcount vulnerabilities.

Open:

- Keep `scripts/check_vulnsignal_alignment.py` passing after every planning or documentation update.

## Phase 1 - Object-Lifetime Source Admission

Status: **in progress next**.

Goal: Build a raw pool of at least 150 candidate source records, then promote only records that survive provenance, source snapshot, and relevance checks.

Primary seed sources:

1. NVD keyword searches for Linux object-lifetime/refcount/UAF/RCU records.
2. Linux kernel upstream commit references from CVE records.
3. syzkaller/syzbot records when a public reproducer, crash log, or fix link exists.
4. OSS-Fuzz / ClusterFuzz only when the case matches object-lifetime-like C/C++ memory safety.
5. CVEfixes / MoreFixes / OSV / GHSA as candidate expansion and weak provenance, not final truth alone.

Source-admission fields:

```text
source_record_id
source_family
cve_or_issue_id
project
repository_url
vulnerable_commit_or_version
fixed_commit
affected_files
candidate_family
evidence_urls
reproducer_available
build_metadata_available
license_or_usage_note
initial_label_strength
admission_status
rejection_reason
```

Candidate families:

```text
kref_refcount
rcu_lifetime
async_work_lifetime
publish_remove_lifetime
uaf_lifecycle_general
```

Phase 1 exit gate:

- At least 150 raw candidate records collected.
- At least 50 records have public source snapshot anchors.
- At least 20 records are admitted for smoke dataset construction.
- No admitted record depends only on vague advisory text.

## Phase 1A - 20-Task Smoke Dataset

Status: **current active phase**.

Goal: Build 20 task instances end to end before attempting the 100-task dataset.

For each admitted task:

1. Resolve vulnerable and fixed source snapshots where available.
2. Create one `task_instance`.
3. Generate candidate locations from patch hunks, crash stack frames, CodeQL paths, same-function windows, same-file related functions, callgraph/dataflow neighbors, and hard negatives.
4. Extract bounded source windows.
5. Run initial CodeQL/lifecycle fact extraction for known APIs:

```text
kref_get
kref_put
refcount_inc
refcount_dec_and_test
get_device
put_device
call_rcu
kfree_rcu
queue_work
cancel_work_sync
flush_work
kfree
```

6. Emit protocol/API sequences and structured fact/path rows.
7. Assign label strength:

```text
dynamic
codeql_conditional
patch_confirmed_weak
weak
UNKNOWN
```

Smoke gate:

- 20/20 admitted tasks have source snapshot records.
- 20/20 admitted tasks have generated candidate locations.
- 15+ tasks have source windows.
- 10+ tasks have CodeQL/lifecycle facts.
- 5+ tasks have `dynamic` or `codeql_conditional` labels.
- 0 tasks rely only on vague text claims.

If this gate fails, do not scale to 100. Either reduce the pilot target, expand the family scope, or improve source/tool extraction first.

## Phase 2 - 100-Task Mixed-Strength Pilot Dataset

Status: **blocked until Phase 1A passes**.

Goal: Scale from the smoke dataset to 100 mixed-strength object-lifetime/refcount task instances and 5,000-10,000 candidate locations.

The dataset should explicitly accommodate imperfect evidence:

- strong dynamic labels get the highest supervision weight
- CodeQL/checker-conditional labels are valid under recorded rule IDs
- patch-confirmed weak labels are used carefully with reduced weight
- weak rows support discovery but not final vulnerability-truth claims
- UNKNOWN rows train abstention and calibration, not false negatives

Target composition:

| Bucket | Target count |
| --- | ---: |
| kref/refcount mismatch | 20-30 |
| RCU lifetime / delayed free | 15-25 |
| workqueue/timer/callback lifetime | 15-25 |
| publish/remove/list lifetime | 15-25 |
| general UAF lifecycle with source anchors | 20-30 |

Phase 2 exit gate:

- At least 50 task instances have public source snapshots and generated candidate locations.
- At least 25 task instances have `dynamic` or `codeql_conditional` labels.
- At least 100 task instances are admitted with explicit label strength, or the scope is formally revised.
- Train/test splits prevent source, project, time, and patch leakage.

## Phase 3 - CodeQL Fact Backbone and Lifecycle Rules

Status: **started in feasibility; production version not complete**.

Goal: Convert source snapshots into source-anchored protocol/API event rows and structured fact/path records.

Required outputs:

```text
protocol_api_sequences.jsonl
structured_facts_paths.jsonl
codeql_rule_runs.jsonl
tool_run_manifest.jsonl
```

Initial fact families:

- allocation/free/destroy calls
- reference acquire/release calls
- lock/unlock and concurrency events
- source/sink and dataflow paths
- alias and object-identity candidates
- async publish/cancel/lifetime events
- RCU registration/free events

Stop condition:

- Do not proceed to ranking experiments if CodeQL/lifecycle extraction cannot emit source-anchored protocol/API events for the known pilot APIs.

## Phase 4 - Candidate Generation and Labels

Status: **blocked until smoke tasks exist**.

Goal: Generate candidate locations automatically and attach label-strength records.

Candidate origins:

- crash stack frame lines
- patch hunk lines
- same-function nearby windows
- same-file related functions
- CodeQL path nodes
- callgraph/dataflow neighbors
- hard negatives near evidence

Label construction:

- `dynamic`: reproduced crash/oracle with pre-patch FAIL and post-patch PASS.
- `codeql_conditional`: tool-grounded rule result under a recorded rule and fact set.
- `patch_confirmed_weak`: patch changes lifecycle/refcount protocol but no reproduced oracle.
- `weak`: source/advisory suggests relevance but evidence is incomplete.
- `UNKNOWN`: missing build, missing source, unresolved object identity, incomplete facts, or rule mismatch.

## Phase 5 - Baseline Ranking

Status: **blocked until Phase 1A has dataset rows**.

Before neural training, run these baselines:

- random ranking
- crash-stack proximity ranking
- patch-proximity ranking
- CodeQL alert/path ranking
- source-text TF-IDF or BM25 ranking
- API-token ranking

Proceed only if the dataset and baselines are stable enough to expose whether a neural ranker adds value.

## Phase 6 - Neural Ranker

Status: **blocked**.

Train only after the dataset builder, fact extraction, candidate generation, labels, and baselines are stable.

Initial model:

- source encoder
- protocol/API sequence encoder
- fact/path encoder
- optional context encoder
- fusion layer
- ranking head
- evidence-selection head
- rule/object heads
- UNKNOWN/calibration head

No neural model claim is allowed without baseline comparison, label-strength reporting, and leakage checks.

## Phase 7 - Evaluation

Status: **blocked until model and baselines exist**.

Use strict project-disjoint, time-disjoint, vulnerability-family-disjoint, and held-out evaluation splits where possible.

Evaluation must report:

- top-k localization
- MRR / nDCG
- evidence selection precision/recall
- UNKNOWN calibration
- validation-guidance quality when oracle links exist
- review-budget reduction
- metrics separated by label strength

Never report weak or UNKNOWN rows as final vulnerability-detection accuracy.

## Non-Negotiable Rules

- No LLM consensus as ground truth.
- No regex-only evidence as ground truth.
- No function-level vulnerable/non-vulnerable framing as the primary dataset.
- No reward model until tool-grounded ranking works.
- No model claims without baseline and oracle provenance.
- No 100-task claim unless source admission, candidate generation, and label-strength review support it.
