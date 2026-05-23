# VulnSignal Execution Plan

## Strategic Objective

Build a tool-grounded candidate-ranking dataset and model pipeline for real vulnerability research. VulnSignal ranks suspicious source-code locations and preserves evidence strength; it does not train a generic vulnerable/non-vulnerable function classifier.

## Current Status

Current phase: **Phase 1B - 60-task evidence grounding smoke**.

Do not start neural model training yet. The immediate goal is to prove that real public source records can be converted into task instances, candidate locations, source windows, CodeQL/lifecycle facts, graph/callback facts, and label-strength records.

Progress:

| Area | Status | Evidence |
| --- | --- | --- |
| Proposal and project framing | Complete | `docs/PROPOSAL.md` |
| Hard-case extraction feasibility | Complete | `docs/feasibility/hardcase_tool_feasibility/README.md` |
| Object-lifetime pilot viability gate | Complete enough to proceed | `docs/feasibility/object_lifetime_pilot_viability/README.md` |
| 20-task smoke dataset | Materialized with partial tool grounding | `reports/e022_object_lifetime_smoke/dataset_card.md` |
| 60-task materialization | Complete for patch/source windows; tool grounding partial | `reports/e022_object_lifetime_smoke/materialization_60_report.md` |
| 60-task Joern graph/callback evidence | Partial for selected CodeQL-conditional candidates | `reports/e022_object_lifetime_smoke/joern_graph_fact_summary_60.json` |
| Current dataset status autosave | Complete for current 60-task status | `docs/project/VULNSIGNAL_CURRENT_DATASET_STATUS.md` |
| 100-task dataset | Blocked | Must first broaden CodeQL/object/path extraction and 60-task rule validation. |
| Neural ranker | Blocked | Requires stable dataset rows, baselines, and leakage controls. |

## Immediate Priority

Generalize tool-fact extraction and rule validation over the **60-task materialized dataset** before scaling to 100. The row-count checkpoint is passed; evidence coverage is now the blocker.

Required smoke-dataset outputs:

```text
reports/e022_object_lifetime_smoke/source_acquisition_manifest.jsonl
reports/e022_object_lifetime_smoke/raw_candidate_sources.jsonl
reports/e022_object_lifetime_smoke/source_snapshots.jsonl
reports/e022_object_lifetime_smoke/task_instances.jsonl
reports/e022_object_lifetime_smoke/candidate_locations.jsonl
reports/e022_object_lifetime_smoke/source_windows.jsonl
reports/e022_object_lifetime_smoke/patch_hunks.jsonl
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

Status: **in progress**.

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

Status: **materialized; keep as the regression baseline for extraction changes**.

Goal: Build 20 task instances end to end before attempting the 100-task dataset.

Current proof seed:

```text
5 raw candidate sources
20 source snapshot records
20 task instances
15 additional admitted-for-extraction task candidates
20 total task candidates with NVD records and reachable primary patch URLs
20 task candidates materialized to patch metadata and affected C-file lists
51 patch-anchored candidate locations
100 weak hard-negative candidate locations
151 base candidate locations
692 expanded candidate locations after CodeQL lifecycle-fact, CodeQL-nearby, and patch-context candidate expansion
11 task candidates with fixed-view Kbuild-backed CodeQL lifecycle facts
10 task candidates with both vulnerable-view and fixed-view Kbuild-backed CodeQL lifecycle facts
20 vulnerable/fixed lifecycle fact comparison rows
51 extracted patch hunks
51 patch-anchored vulnerable/fixed source windows fetched from public commit refs
692 source windows including weak hard negatives and expansion candidates
10 CodeQL source-window fixture protocol/API rows
20 CodeQL source-window fixture lifecycle-call fact rows
3 fixed-view full-source Kbuild-backed CodeQL fact rows for `vs-smoke-T0005`
4 recorded conditional promotion rules
6 positive codeql_conditional labels
12 scoped codeql_conditional_negative labels
31 Coccinelle lifecycle matches across 19 vulnerable/fixed source-window view runs
9 Coccinelle wrapper-candidate matches across 9 vulnerable/fixed source-window view runs
Joern CFG/DDG/CPG14 exports for 12 source-window files covering the 6 promoted candidates
4 selected Joern graph facts for the 60-task CodeQL-conditional candidates, including 1 resolved RCU callback edge
automated failure-analysis rows for all 51 patch-anchored candidates
automated rule-gap triage rows for all 51 patch-anchored candidates
normalized multi-view model-input artifacts for AST/expression, object identity, lifecycle/API events, CFG/order, alias/dataflow, callback/async, and rule-validation views
0 dynamic labels
```

This is now an admission/provenance proof, a parser-backed CodeQL source-window fixture probe, a 20-task patch/source-window materialization, a hard-negative generation pass, a Kbuild-backed CodeQL extraction attempt across all 20 candidates, a first conditional label-promotion pass, an automated secondary-tool evidence pass, and a rule-gap triage pass. It passes the materialization part of the smoke gate and now passes the minimum conditional-label count. It still does not pass a dynamic-oracle gate because 0 tasks have reproduced pre-patch FAIL / post-patch PASS evidence, 9 tasks still lack full-source facts, and one task has fixed-view facts but a vulnerable-parent build failure.

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
- 10+ tasks have full-source CodeQL/lifecycle facts.
- 5+ tasks have `dynamic` or `codeql_conditional` labels.
- 0 tasks rely only on vague text claims.

If this gate fails, do not scale to 100. Either reduce the pilot target, expand the family scope, or improve source/tool extraction first.

Current smoke-gate decision:

- Materialization gate: passed for 20/20 tasks.
- Source-window gate: passed for 20/20 tasks.
- Fixed-view tool-fact gate: passed at 11/20 tasks.
- Vulnerable/fixed comparison gate: partially passed at 10/20 tasks.
- Strong-label gate: passed for conditional labels at 6 candidate rows across 4 tasks.
- Dynamic-oracle gate: failed at 0 reproduced FAIL/PASS labels.
- Secondary-tool automation gate: passed for Coccinelle window matching and Joern graph export.
- Failure-analysis gate: passed for all 51 patch-anchored candidates.
- Wrapper-candidate lane: passed; 9 Coccinelle parser-backed wrapper-candidate matches were captured as candidate-only evidence.
- Rule-gap triage gate: passed for all 51 patch-anchored candidates; 15 need new rule plus tool extraction, 7 need secondary-tool promotion policy, 23 should remain weak or be replaced for now, and 6 are already covered.
- Multi-view bridge gate: partial; candidate-level normalized views exist, object identity exists for the first CodeQL-covered tasks, and selected Joern graph/callback facts exist, but object/path/callback coverage is still narrow.

Next work must therefore focus on improving tool-derived normalization, graph/path extraction, callback extraction, and rule coverage together. The first candidate-density expansion added 164 CodeQL lifecycle-fact anchors, 326 CodeQL-nearby weak contrast candidates, and 51 patch-context candidates, raising the smoke set from 151 to 692 rows without promoting label truth. The 60-task expansion reached 2,321 rows, so new weak rows are not the bottleneck. The useful immediate rule work is wrapper/API ontology mapping, callback handoff rules, generalized RCU deferred-release rules, object identity, graph/path views, and Kbuild or secondary-tool lanes. Additional checker rules, dynamic-oracle evidence, and remaining Kbuild profiles still matter, but new rules must be backed by tool-derived evidence rather than patch-text categories alone.

## Phase 1B - 60-Task Admission And Materialization Expansion

Status: **materialized; tool extraction in progress**.

Goal: Convert validated admission-backlog records into materialized task/source/candidate artifacts while preserving the same evidence boundaries used in Phase 1A.

Current admission backlog:

```text
411 reusable NVD/kernel.org discovery-pool candidates
90 top automated discovery candidates selected for validation
29/90 automated discovery candidates patch-validated for materialization
11/15 earlier NVD/kernel.org next-batch candidates patch-validated
40 new validated admission-backlog tasks
20 existing materialized smoke tasks
60 materialized task instances
269 patch hunks and patch-anchored candidates
534 weak nearby hard-negative candidates
803 combined candidate locations and source windows
2,321 expanded candidate locations and source windows
389 CodeQL/Coccinelle operation-role facts across 27 tasks
221 CodeQL AST/expression facts across 4 tasks
221 CodeQL object-identity facts across 4 tasks, with 194 tool-expression identities and 27 unresolved identities
15 60-task rule-validation rows
2 codeql_conditional positive labels
4 scoped codeql_conditional_negative labels
100 Coccinelle lifecycle matches across 57 source-window view runs
68 Coccinelle wrapper-candidate matches across 47 source-window view runs
65 candidates blocked before materialization because the patch was reachable but current lifecycle signals were missing
```

Backlog family mix:

| Family | Validated backlog tasks |
| --- | ---: |
| kref/refcount | 13 |
| concurrency lifetime | 12 |
| async work/timer/callback lifetime | 8 |
| RCU lifetime | 5 |
| publish/remove lifetime | 2 |

Phase 1B output targets:

```text
task_admission_backlog_validated.jsonl
source_acquisition_manifest_60.jsonl
source_snapshots_60.jsonl
task_instances_60.jsonl
patch_hunks_60.jsonl
candidate_locations_60.jsonl
source_windows_60.jsonl
labels_60.jsonl
tool_run_manifest_60.jsonl
```

Phase 1B gates:

- 60-task materialization must produce task/source/candidate rows before model training. **Passed with 60 tasks, 269 patch candidates, 803 candidates after weak hard negatives, and 2,321 candidates after density expansion and CodeQL fact-anchor expansion.**
- No newly admitted task may be promoted beyond `patch_confirmed_weak` without CodeQL/checker, Coccinelle-policy, graph/path, or dynamic-oracle evidence.
- The 65 blocked candidates should remain in the discovery pool, not the materialization backlog, until the ontology or validation signals improve.
- The 20-task smoke set remains the regression baseline for wrapper/API ontology, Coccinelle, Joern, CodeQL, and multi-view artifact changes.

Candidate-scale checkpoint:

The current 60-task expanded dataset has 2,321 candidate locations after weak hard-negative generation, patch-context expansion, parser-backed Coccinelle lifecycle/wrapper candidate expansion, and Kbuild-backed CodeQL fact-anchor expansion. If we use a CLeVeR-like scale of roughly 1,600 vulnerable/non-vulnerable samples as a minimum sanity checkpoint, VulnSignal has passed that row-count checkpoint. This comparison is only a scale check: CLeVeR-style examples are not the same unit as VulnSignal task-grouped candidate rows.

Before any serious baseline-training claim, create:

```text
scale_checkpoint_1600_candidates:
  50-75 task_instances
  1,600+ candidate_locations
  candidate rows grouped by task_id
  label_strength recorded for every labeled row
  missing-view mask recorded for every candidate row
  no global vulnerable/non-vulnerable function-label claim
```

At the current 60-task average of 38.7 candidates per task, the row-count checkpoint is passed. The next implementation goal is not more weak candidate rows. It is Joern-first structural extraction, Coccinelle lifecycle/API extraction, CodeQL validation-attempt records for applicable candidate/rule pairs, callback-aware rule validation, and stronger tool-backed label coverage.

The candidate-level model-input scaffold now exists as `reports/e022_object_lifetime_smoke/candidate_representation_index_60.jsonl`. It has 2,321 rows, one per `(task_instance, candidate_location)`, and links source windows, labels, AST/expression facts, object-identity facts, protocol/API event facts, CFG/order facts, DFG/DDG facts, callback/async facts, and rule evidence when available. Missing views are explicit masks.

## Phase 2 - 100-Task Mixed-Strength Pilot Dataset

Status: **blocked until Phase 1B Joern/Coccinelle representation extraction and CodeQL validation-attempt records pass**.

Goal: Scale from the smoke dataset to 100 mixed-strength object-lifetime/refcount task instances and 5,000-10,000 candidate locations.

The dataset should explicitly accommodate imperfect evidence:

- strong dynamic labels get the highest supervision weight
- CodeQL/checker-conditional labels are valid under recorded rule IDs and validation-attempt outcomes
- patch-confirmed weak labels are used carefully with reduced weight
- weak rows support discovery but not final vulnerability-truth claims
- UNKNOWN rows train abstention and calibration, not false negatives
- negative subtype metadata supports sampling, weighting, evaluation, and audit; it is not a vulnerability class

Target composition:

| Bucket | Target count |
| --- | ---: |
| kref/refcount mismatch | 20-30 |
| RCU lifetime / delayed free | 15-25 |
| workqueue/timer/callback lifetime | 15-25 |
| publish/remove/list lifetime | 15-25 |
| general UAF lifecycle with source anchors | 20-30 |

Phase 2 exit gate:

- At least 1,600 candidate rows exist before any serious baseline-training claim.
- At least 50 task instances have public source snapshots and generated candidate locations.
- At least 25 task instances have `dynamic` or `codeql_conditional` labels.
- Candidate generation averages at least 25 candidates per task before claiming the path to 5,000-10,000 candidates.
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

Negative subtype metadata:

- `easy_negative`
- `weak_nearby_hard_negative`
- `same_api_hard_negative`
- `checker_pass_hard_negative`
- `fixed_version_analog`
- `unknown_or_unproven`

These subtypes guide sampling and evaluation. `UNKNOWN` rows must not be silently converted into negative labels.

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

Initial training recipe:

- Train as candidate ranking grouped by `task_id`.
- Start with weighted pairwise margin ranking loss.
- Use rotating relevant negatives from the same task, rule family, API/sink, file/function, subsystem, fixed-version analogs, and CodeQL/checker `rule_not_matched` candidates.
- A starting group is 1 positive, 1 easy/wide negative, 2 hard negatives, and 2 verified/conditional hard negatives when available.
- Do not generate all possible positive-negative pairs; cap positive reuse per epoch.
- Add auxiliary contrastive learning only after the ranking baseline works.

Overfitting controls:

- split by task/project/CVE/clone before pair generation
- deduplicate source windows and patch variants
- freeze most transformer layers initially and train adapters plus ranking head first
- early stop on project/CVE-disjoint validation
- evaluate hard-negative-only performance

Official inference modes:

- `tool_grounded`: source, generated candidates, and generated tool facts; strongest VulnSignal claim but still evidence ranking until validation
- `few_shot_description_assisted`: new rule description plus a few positives/hard negatives; adaptation mode needing later validation
- `description_only_zero_shot`: CLeVeR-like prompt/query ranking; exploratory only

## Phase 7 - Evaluation

Status: **blocked until model and baselines exist**.

Use strict project-disjoint, time-disjoint, vulnerability-family-disjoint, and held-out evaluation splits where possible.

Evaluation must report:

- top-k localization
- MRR / nDCG
- hard-negative-only Recall@k and MRR
- false positives by negative subtype
- evidence selection precision/recall
- evidence-chain overlap
- UNKNOWN calibration
- project/CVE-disjoint test performance
- validation-guidance quality when oracle links exist
- review-budget reduction
- metrics separated by label strength

Never report weak or UNKNOWN rows as final vulnerability-detection accuracy.

Required ablations:

- source only
- source + facts
- source + facts + descriptions
- without object identity
- without lifecycle/API events
- without graph/path facts
- without verifier-guided post-training
- SARD transfer-risk study only if externally required and only after the Linux baseline is stable; it is not a default ablation

## Phase 8 - Verifier-Guided Post-Training

Status: **future work; blocked until Phase 6 ranking baseline works**.

Goal: improve beyond CLeVeR-style description alignment by using verifier outcomes as preference supervision.

Preference examples:

- CodeQL/checker `rule_matched` candidate > rule-scoped `rule_not_matched` candidate
- dynamic-oracle-linked candidate > same-file distractor
- CodeQL-path-supported candidate > weak nearby hard negative
- root-cause candidate > patch-nearby UNKNOWN
- strong evidence > weak evidence
- UNKNOWN should abstain, not become negative

Exit gate:

- preference data is produced from checker/oracle/rule outcomes, not from LLM agreement
- hard-negative-only ranking improves over the Phase 6 ranker
- UNKNOWN calibration does not regress

## Non-Negotiable Rules

- No LLM consensus as ground truth.
- No regex-only evidence as ground truth.
- No function-level vulnerable/non-vulnerable framing as the primary dataset.
- No reward model until tool-grounded ranking works.
- No model claims without baseline and oracle provenance.
- No 100-task claim unless source admission, candidate generation, and label-strength review support it.
