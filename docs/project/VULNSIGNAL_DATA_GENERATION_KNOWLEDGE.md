# VulnSignal Data Generation Knowledge

This document records lessons from dataset construction so the pipeline can scale without rediscovering the same rules and failure modes.

## Current Evidence Boundary

Strong labels must come from executable or tool-run evidence. Patch hunks and advisories can admit a task and seed candidates, but they do not create final truth.

Current label strengths used in the smoke dataset:

- `dynamic`: reproduced pre-patch FAIL and post-patch PASS. Not available yet.
- `codeql_conditional`: a recorded rule over tool facts and source windows passed under explicit preconditions.
- `codeql_conditional_negative`: a candidate was cleared only for a specific rule. This is not a global safe-code label.
- `patch_confirmed_weak`: public patch/advisory anchors a candidate, but no checker rule has passed.
- `weak`: useful training contrast or context, not truth.
- `UNKNOWN`: missing or incomplete evidence.

## Promotion Rules Proven In The 20-Task Smoke Set

The first promotion pass is implemented in `reports/e022_object_lifetime_smoke/promote_codeql_conditional_labels.py`.

### `VS-LIFE-KREF-LOCK-001`

Purpose: promote a candidate when an unlocked `kref_put` in the vulnerable view is replaced by `kref_put_mutex` in the fixed view.

Required evidence:

- vulnerable CodeQL fact: `callee=kref_put`, `role=release_ref`
- fixed CodeQL fact: `callee=kref_put_mutex`, `role=release_ref_locked`
- same task, file, candidate-local function, and candidate line window
- patch hunk adds `kref_put_mutex` and removes `kref_put`

Smoke result:

- promoted `vs-smoke-C20-0007`
- promoted `vs-smoke-C20-0008`
- promoted `vs-smoke-C20-0009`

Scaling note: line-window matching is necessary. Function-only matching over-promotes repeated lifecycle calls in the same function.

### `VS-LIFE-REF-LIVE-001`

Purpose: promote a candidate when an unchecked refcount acquire in the vulnerable view is replaced by a live-object acquire in the fixed view.

Required evidence:

- vulnerable CodeQL fact: `callee=refcount_inc`, `role=acquire_ref_unchecked`
- fixed CodeQL fact: `callee=refcount_inc_not_zero`, `role=acquire_ref_if_live`
- same task, file, function, and candidate line window
- patch hunk adds `refcount_inc_not_zero` and removes `refcount_inc`

Smoke result:

- promoted `vs-smoke-C20-0018`

Scaling note: this rule is useful for timer/refcount and publish/use-after-free patterns, but it requires both vulnerable and fixed views to build.

### `VS-LIFE-RCU-DEFER-001`

Purpose: promote a candidate when immediate release after RCU-list deletion is replaced by deferred release through `call_rcu`.

Required evidence:

- fixed CodeQL fact: `callee=call_rcu`, `role=defer_free_rcu`
- candidate source window shows vulnerable-side `list_del_rcu` and immediate release token such as `llsec_key_put`
- candidate line window contains the fixed `call_rcu` call

Smoke result:

- promoted `vs-smoke-C20-0043`

Scaling note: function guesses from patch hunk headers can be wrong when a patch inserts a new callback helper. This rule must allow line-window matching in addition to function matching.

### `VS-LIFE-REF-INSERT-001`

Purpose: promote a candidate when a fixed view inserts a live-object acquire that is absent in the vulnerable view.

Required evidence:

- fixed CodeQL fact: `callee=refcount_inc_not_zero`, `role=acquire_ref_if_live`
- vulnerable view lacks a matching candidate-window live acquire
- patch hunk inserts `refcount_inc_not_zero`

Smoke result:

- promoted `vs-smoke-C20-0047`

Scaling note: this is weaker than `VS-LIFE-REF-LIVE-001` because it may not have a vulnerable-side extracted unsafe acquire. Keep it as `codeql_conditional`, not `dynamic`, and prefer the replacement rule when both sides expose facts.

## Negative Label Policy

The smoke pipeline creates scoped hard negatives only after a positive rule passes.

Current rule:

- If a nearby hard-negative candidate is anchored to a promoted positive candidate, and its local source window does not contain the trigger terms for that positive rule, it can be labeled `codeql_conditional_negative`.

Boundary:

- This does not mean the candidate is safe.
- It only means the candidate did not satisfy that specific checker rule.
- These rows are useful for ranking contrast, not for vulnerability absence claims.

## Current Smoke Promotion Counts

As of the first promotion pass:

- 6 positive `codeql_conditional` labels
- 12 `codeql_conditional_negative` scoped negative labels
- 45 remaining `patch_confirmed_weak` labels
- 88 remaining `weak` labels
- 0 `dynamic` labels

## Automated Evidence Lanes Added

The 20-task smoke evidence pass is now automated by:

```text
reports/e022_object_lifetime_smoke/run_evidence_automation_20.py
```

The default automation runs:

1. tool capability detection
2. lifecycle rule promotion
3. Coccinelle semantic-pattern matching over candidate windows
4. promotion failure analysis
5. rule-gap triage for unpromoted candidates
6. Joern graph export for promoted candidate windows
7. multi-view artifact generation

The CodeQL v2 query runner is available but not run by default because it should be executed against fresh view-specific databases:

```text
VS_RUN_CODEQL_V2=1 VS_CODEQL_V2_TASK=vs-smoke-T0005 python3 reports/e022_object_lifetime_smoke/run_evidence_automation_20.py
```

### Rule Specs

Rule definitions now live under:

```text
rules/lifecycle/
```

The promotion runner reads JSON rule specs instead of embedding rule definitions in Python. Scaling should add or revise these rule specs, not add one-off promotion code.

### Coccinelle Lane

Coccinelle runs the semantic patch:

```text
reports/e022_object_lifetime_smoke/coccinelle_patterns/lifecycle_calls.cocci
```

Current smoke result:

- 102 vulnerable/fixed source-window view runs
- 19 matched view runs
- 31 lifecycle matches

Coccinelle evidence is useful as an independent tool signal, especially when full Kbuild-backed CodeQL extraction is blocked. The current policy does not promote Coccinelle-window-only matches to strong positive labels without an explicit rule policy.

The semantic patch now captures additional async/timer/RCU anchors:

```text
INIT_WORK
queue_work
schedule_work
flush_work
cancel_work_sync
destroy_workqueue
timer_setup
mod_timer
del_timer / del_timer_sync
kfree_rcu
synchronize_rcu
list_add_rcu
```

Smoke impact: the added timer rule found `mod_timer` in the IGMP timer/refcount candidate and increased lifecycle matches from 29 to 31. This is supporting evidence only.

### Coccinelle Wrapper-Candidate Lane

Coccinelle also runs a separate wrapper-candidate semantic patch:

```text
reports/e022_object_lifetime_smoke/coccinelle_patterns/wrapper_candidates.cocci
reports/e022_object_lifetime_smoke/run_coccinelle_wrapper_probe.py
reports/e022_object_lifetime_smoke/coccinelle_wrapper_candidate_matches_20.jsonl
reports/e022_object_lifetime_smoke/coccinelle_wrapper_candidate_summary.json
```

Current smoke result:

- 102 vulnerable/fixed source-window view runs
- 9 matched view runs
- 9 wrapper-candidate matches

This lane records parser-backed wrapper candidates such as subsystem `_put`, `_get`, `_hold`, `_release`, and `_drop_ref` calls. It intentionally emits `wrapper_candidate_only` evidence. It does not mean the wrapper is semantically confirmed as acquire/release, and it cannot promote labels without a separate wrapper rule policy.

Wrapper/API ontology now lives in:

```text
rules/ontology/lifecycle_api_ontology.json
```

This ontology normalizes parser-backed tool outputs into model-facing operation categories such as `api_family`, `operation_class`, `security_axis`, and `lifecycle_stage`. Known wrapper examples include `sock_hold`, `sock_put`, `zcrypt_card_put`, `ip_ma_put`, `eventfd_ctx_put`, and `llsec_key_put`.

Boundary: ontology mapping is not helper semantics. It helps the model learn generalized operation roles, but label promotion still requires helper-body facts, a recorded rule, graph/path facts, or another tool-backed validation path.

### Rule-Gap Triage Lane

The smoke pipeline now derives a rule-engineering report:

```text
reports/e022_object_lifetime_smoke/derive_rule_gap_report_20.py
reports/e022_object_lifetime_smoke/rule_gap_report_20.jsonl
reports/e022_object_lifetime_smoke/rule_gap_report_20_summary.json
```

This report does not promote labels. It separates missing rule coverage from missing tool evidence and records whether a candidate should be kept weak, replaced, routed through a secondary tool policy, or used to design a new rule.

Current rule-gap result over 51 patch-anchored candidates:

- 6 candidates are already covered by current rule policy.
- 8 candidates have no parser-backed lifecycle signal and should remain weak or be replaced.
- 15 candidates need a new rule plus tool extraction.
- 7 candidates have secondary-tool evidence and need an explicit secondary-tool promotion policy.
- 23 candidates are currently weak or replace candidates.

Top engineering categories:

- 31 candidates still have full-source CodeQL tool-lane gaps.
- 14 candidates look like cleanup/post-free pointer nulling; keep this outside the core refcount-positive label path unless a tool-backed rule is defined.
- 3 candidates have Coccinelle wrapper-candidate evidence and need wrapper/API ontology mapping before they can support stronger rules.
- 4 candidates suggest callback ref handoff rules needing callback graph or path facts.
- 3 candidates suggest generalized RCU deferred-release rules.

Policy boundary: patch/source-window text in this report is for rule-engineering triage only. Wrapper/API categories should come from the Coccinelle wrapper-candidate lane or another tool-backed source before they become model-visible operation facts. No rule-gap category can promote label strength.

### Joern Lane

Joern now parses promoted candidate source windows and exports:

- CFG
- DDG
- CPG14

Current smoke result:

- 6 promoted candidates
- 12 vulnerable/fixed source-window files
- 51 exported files for each graph representation

These exports are for automated graph cross-checking of order/path-sensitive rules. They are not final truth by themselves.

### CodeQL V2 Lane

`ExtractLifecycleSourceFactsV2.ql` compiles and emits:

- call role
- callee
- enclosing function
- source file and line range
- first three argument expressions where CodeQL can render them

Current limitation: CodeQL `Expr.toString()` may abbreviate complex argument expressions, for example `& ...`. Therefore object identity should be cross-checked with source-window or graph facts before being used for promotion.

### SVF Lane

SVF binaries are available under:

```text
.tools/SVF/Release-build/bin/
```

SVF is not yet wired into the smoke automation because it requires LLVM bitcode generated from buildable translation units. The next automated step for SVF is a Kbuild/Clang bitcode profile, not source-window snippets.

### Dynamic Oracle Lane

The current environment does not expose `syz-manager` or `qemu-system-x86_64` on `PATH`. Dynamic syzkaller/KASAN/KCSAN evidence is therefore blocked in this environment, but this is an environment/tooling blocker, not a dataset-design blocker.

Recorded status:

```text
reports/e022_object_lifetime_smoke/tool_capability_status.json
```

## Admission Expansion Toward 50-75 Tasks

The next scaling step is now evidence-gated admission, not label promotion. The automation added:

```text
reports/e022_object_lifetime_smoke/discover_nvd_lifetime_candidates.py
reports/e022_object_lifetime_smoke/validate_next_task_admissions.py
reports/e022_object_lifetime_smoke/build_validated_admission_backlog.py
```

Commands used:

```bash
python3 reports/e022_object_lifetime_smoke/validate_next_task_admissions.py
VS_NVD_MAX_OUTPUT_ROWS=90 VS_NVD_DELAY_SECONDS=6.2 python3 reports/e022_object_lifetime_smoke/discover_nvd_lifetime_candidates.py
VS_ADMISSION_INPUT=task_admission_candidates_nvd_discovered.jsonl VS_ADMISSION_OUTPUT_PREFIX=task_admission_candidates_nvd_discovered_patch_validation python3 reports/e022_object_lifetime_smoke/validate_next_task_admissions.py
python3 reports/e022_object_lifetime_smoke/build_validated_admission_backlog.py
```

Current outputs:

```text
task_admission_candidates_next_validation.jsonl
task_admission_candidates_next_summary.json
task_admission_candidates_nvd_discovered.jsonl
task_admission_candidates_nvd_discovered_pool.jsonl
task_admission_candidates_nvd_discovered_summary.json
task_admission_candidates_nvd_discovered_patch_validation_validation.jsonl
task_admission_candidates_nvd_discovered_patch_validation_summary.json
task_admission_backlog_validated.jsonl
task_admission_backlog_validated_summary.json
```

Admission results:

- The earlier 15-candidate next batch produced 11 materialization-ready tasks and 4 reachable-patch rows with no current lifecycle signal.
- Automated NVD discovery found 411 reusable Linux/kernel.org candidates after excluding already known CVEs.
- The top 90 automated discovery rows produced 29 materialization-ready tasks and 61 reachable-patch rows with no current lifecycle signal.
- The combined validated backlog has 40 new tasks.
- The pilot size is now 60 materialized tasks, which is inside the 50-75 task target band.
- No label strength was promoted. Every backlog row is admission-only until source-window and tool-fact extraction runs complete.

Materialization commands:

```bash
python3 reports/e022_object_lifetime_smoke/materialize_60_admission_dataset.py
python3 reports/e022_object_lifetime_smoke/generate_hard_negatives_60.py
VS_OUTPUT_SUFFIX=_60 VS_SOURCE_WINDOWS_INPUT=source_windows_60_materialized.jsonl VS_COCCI_MATCH_OUTPUT=coccinelle_window_lifecycle_matches_60.jsonl VS_COCCI_SUMMARY_OUTPUT=coccinelle_window_lifecycle_summary_60.json python3 reports/e022_object_lifetime_smoke/run_coccinelle_window_probe.py
VS_OUTPUT_SUFFIX=_60 VS_SOURCE_WINDOWS_INPUT=source_windows_60_materialized.jsonl VS_COCCI_WRAPPER_OUTPUT=coccinelle_wrapper_candidate_matches_60.jsonl VS_COCCI_WRAPPER_SUMMARY=coccinelle_wrapper_candidate_summary_60.json python3 reports/e022_object_lifetime_smoke/run_coccinelle_wrapper_probe.py
python3 reports/e022_object_lifetime_smoke/write_60_status_report.py
```

Density and readiness commands:

```bash
python3 reports/e022_object_lifetime_smoke/expand_candidate_generation_60.py
VS_OUTPUT_SUFFIX=_60 VS_CANDIDATE_INPUT=candidate_locations_60_expanded.jsonl VS_SOURCE_WINDOW_INPUT=source_windows_60_expanded.jsonl VS_CODEQL_FACT_INPUTS=NONE VS_COCCI_LIFECYCLE_INPUT=coccinelle_window_lifecycle_matches_60.jsonl VS_COCCI_WRAPPER_INPUT=coccinelle_wrapper_candidate_matches_60.jsonl VS_JOERN_SUMMARY_INPUT=NONE VS_RULE_RUN_INPUT=NONE VS_EVIDENCE_PACKET_INPUT=NONE python3 reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py
python3 reports/e022_object_lifetime_smoke/profile_dataset_readiness_60.py
python3 reports/e022_object_lifetime_smoke/select_codeql_probe_batch_60.py
VS_TASK_INPUT=task_instances_60_materialized.jsonl VS_OUTPUT_DATASET_TAG=60 VS_OUTPUT_SUFFIX=_codeql_probe12 VS_USE_INPUT_CHANGED_FILES=1 VS_ONLY_TASKS=vs-smoke-T0049,vs-smoke-T0090,vs-smoke-T0076,vs-smoke-T0043,vs-smoke-T0026,vs-smoke-T0009,vs-smoke-T0111,vs-smoke-T0006,vs-smoke-T0015,vs-smoke-T0005,vs-smoke-T0027,vs-smoke-T0023 VS_RUN_CODEQL=1 python3 reports/e022_object_lifetime_smoke/full_source_probe/run_kbuild_codeql_pipeline.py
python3 reports/e022_object_lifetime_smoke/refresh_codeql_facts_from_existing_dbs.py
VS_DATASET_TAG=60 VS_FIXED_CODEQL_FACTS=full_source_codeql_facts_batch_codeql_probe12_arg0.jsonl VS_VULNERABLE_CODEQL_FACTS=full_source_codeql_facts_batch_codeql_probe4_vulnerable.jsonl python3 reports/e022_object_lifetime_smoke/promote_codeql_conditional_labels.py
python3 reports/e022_object_lifetime_smoke/expand_candidate_generation_60.py
VS_OUTPUT_SUFFIX=_60 VS_CANDIDATE_INPUT=candidate_locations_60_expanded.jsonl VS_SOURCE_WINDOW_INPUT=source_windows_60_expanded.jsonl VS_CODEQL_FACT_INPUTS=full_source_codeql_facts_batch_codeql_probe12_arg0.jsonl,full_source_codeql_facts_batch_codeql_probe4_vulnerable.jsonl VS_COCCI_LIFECYCLE_INPUT=coccinelle_window_lifecycle_matches_60.jsonl VS_COCCI_WRAPPER_INPUT=coccinelle_wrapper_candidate_matches_60.jsonl VS_JOERN_SUMMARY_INPUT=NONE VS_RULE_RUN_INPUT=codeql_conditional_rule_runs_60.jsonl VS_EVIDENCE_PACKET_INPUT=evidence_packets_60_codeql_conditional.jsonl python3 reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py
python3 reports/e022_object_lifetime_smoke/write_60_status_report.py
```

The report writer now auto-saves both:

```text
reports/e022_object_lifetime_smoke/materialization_60_report.md
docs/project/VULNSIGNAL_CURRENT_DATASET_STATUS.md
```

Materialization results:

- 60 materialized task instances.
- 269 patch hunks and patch-anchored candidate locations.
- 269 vulnerable/fixed source windows with 0 fetch failures.
- 534 weak nearby hard-negative candidates.
- 803 combined candidate locations, labels, and source windows.
- 2,321 expanded candidate locations, labels, and source windows.
- 100 Coccinelle lifecycle matches across 57 source-window view runs.
- 68 Coccinelle wrapper-candidate matches across 47 source-window view runs.
- 389 CodeQL/Coccinelle operation-role facts across 27 tasks.
- 221 CodeQL AST/expression facts across 4 tasks.
- 221 CodeQL object-identity facts across 4 tasks, with 194 tool-expression identities and 27 unresolved identities.
- 15 60-task rule-validation rows.
- 2 `codeql_conditional` positive labels and 4 scoped `codeql_conditional_negative` labels.
- A 12-task prioritized CodeQL probe batch was selected in `codeql_probe_batch_60.jsonl`.
- Most emitted labels remain `patch_confirmed_weak`, weak ranking contrast, or `UNKNOWN`; only the recorded rule-scoped rows are conditionally promoted.

Backlog family mix:

```text
kref_refcount: 13
concurrency_lifetime: 12
async_work_lifetime: 8
rcu_lifetime: 5
publish_remove_lifetime: 2
```

Knowledge gained:

- NVD plus kernel.org refs can supply enough source-backed object-lifetime tasks for a 50-75 task pilot.
- Patch reachability is not enough. A large number of reachable patches do not expose current lifecycle signals in changed lines and should stay out of materialization until the ontology or validation rules improve.
- Admission signals are useful for task selection, but they are weak provenance. Tool extraction still has to produce candidate-level source windows, CodeQL/Coccinelle/graph facts, and labels.
- The 20-task smoke set remains the regression baseline; the 40-task backlog should be materialized only after preserving the same evidence-boundary fields.
- The 60-task set now passes the 1,600-row candidate-count checkpoint and has partial CodeQL/object-identity extraction, but readiness profiling still blocks real dataset/training claims because graph/path, rule-validation, broader CodeQL coverage, and dynamic-oracle evidence are missing.
- The Kbuild/CodeQL runner now accepts `VS_TASK_INPUT=task_instances_60_materialized.jsonl` and `VS_OUTPUT_DATASET_TAG=60`. A no-CodeQL dry run confirmed the 60-task input path works without refetching patches when `VS_USE_INPUT_CHANGED_FILES=1`.
- The first 12-task Kbuild/CodeQL probe produced 110 lifecycle facts across 4 tasks. The query was then updated to emit `arg0`, `arg0_file`, and `arg0_line`; the refresh script reran only the query against existing CodeQL databases and produced 110 facts with `arg0`, including 96 usable tool-expression identities.

## Multi-View Normalization Bridge

The smoke dataset now has a generated bridge from tool evidence to model-facing views:

```text
reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py
reports/e022_object_lifetime_smoke/multiview_artifact_summary_20.json
reports/e022_object_lifetime_smoke/multiview_artifact_summary_60.json
```

Generated view artifacts:

- `ast_expression_facts.jsonl`
- `object_identity_facts.jsonl`
- `operation_role_facts.jsonl`
- `control_flow_order_facts.jsonl`
- `alias_dataflow_facts.jsonl`
- `callback_graph_facts.jsonl`
- `vulnerability_rule_instances.jsonl`
- `vulnerability_rule_validation.jsonl`

Current bridge counts:

- 227 AST/expression facts
- 227 object identity facts, with 204 unresolved and 23 tool-rendered expression identities
- 267 lifecycle/API operation role facts, including 9 wrapper-candidate-only operation facts
- 692 CFG/order rows
- 692 alias/dataflow rows
- 692 callback/async rows
- 21 rule instances and 21 rule-validation rows

Current 60-task bridge counts:

- 1,362 CodeQL representation facts from 10 existing DB snapshots
- 421 AST/expression facts
- 421 object identity facts, with 349 tool-expression identities and 72 unresolved identities
- 589 lifecycle/API operation-role facts from CodeQL and Coccinelle
- 3,053 CFG/order rows, including 732 CodeQL guard/CFG-order rows and 2 rows with selected parsed Joern graph support
- 2,321 alias/dataflow rows, including 2 rows with selected parsed DDG support
- 2,351 callback/async rows, including 30 CodeQL callback/async API rows and 1 row with a selected resolved RCU callback edge
- 4 selected Joern graph facts from Joern DOT output
- 15 rule instances and 15 rule-validation rows
- 2,321 candidate representation index rows, one per `(task_instance, candidate_location)`
- 166 candidate rows with at least one tool-grounded non-source view
- 2 `codeql_conditional` positive labels and 4 scoped `codeql_conditional_negative` labels

The bridge normalizes evidence into generalized model-visible fields such as `normalized_operation_role`, `api_family`, `operation_class`, `security_axis`, `lifecycle_stage`, `identity_status`, and `rule_family`. Raw `callee`, `object_expression`, `file`, `function`, and source-window text remain audit fields and should be masked or ablated during model training when testing memorization risk.

Important boundary: source, AST/expression, CFG/order, DFG/DDG/dataflow, lifecycle/API events, object identity, callback/async, and rule evidence are separate candidate-linked representations. They are not pre-combined into one giant graph for the default dataset. `candidate_representation_index_60.jsonl` links the separate artifacts by candidate ID and records missing-view masks. Cross-attention or gated fusion should learn the soft relationships among views. Tool-proven relationship edges may be added later as auxiliary validation evidence, not as required default inference input.

## Lessons For Scaling

1. Build both vulnerable and fixed views first. Without both views, most rules stay weak or UNKNOWN.
2. Candidate-local line windows are required. Function-level matching is too broad for repeated lifecycle calls.
3. CodeQL validation IDs and legacy CodeQL fact IDs are not globally unique across views unless the view is included. Use `view:fact_id` or `view:validation_id` references in evidence packets.
4. Patch hunk function guesses are not reliable around inserted helper functions, callbacks, and RCU patterns. Use line-window fallback.
5. Strong negative labels must be scoped to a rule. Do not train global non-vulnerable claims from nearby code.
6. A promotion rule should record failed runs as well as passed runs. Failed runs explain missing facts and guide the next extractor improvements.
7. Secondary tool evidence should be explicit. Coccinelle/Joern/SVF evidence can support promotion only when the rule policy says how it is allowed to do so.
8. Dynamic-oracle unavailability should be recorded as an environment/tooling blocker, not silently converted into weak static labels.
9. Normalize tool-derived evidence into generalized semantic fields before training.
10. Do not require manually built fine-grained cross-view edges for inference; use candidate-level alignment and missing-view masks.
11. Use rule-gap reports to choose rule work. Do not blindly add rules for every patch hunk.
12. Joern/Coccinelle should be the primary scalable extractor for AST/CFG/DDG/callback/API representation rows. CodeQL should be the primary evidence-level validator for applicable candidate/rule pairs. Blocked CodeQL validation is recorded as `rule_unknown`, not skipped validation.

## 60-Task Vulnerable/Fixed CodeQL Validation Pass

The first 60-task rule-validation pass used both fixed-view and vulnerable-view Kbuild-backed CodeQL facts as historical validation evidence:

```bash
VS_DATASET_TAG=60 VS_FIXED_CODEQL_FACTS=full_source_codeql_facts_batch_codeql_probe12_arg0.jsonl VS_VULNERABLE_CODEQL_FACTS=full_source_codeql_facts_batch_codeql_probe4_vulnerable.jsonl python3 reports/e022_object_lifetime_smoke/promote_codeql_conditional_labels.py
```

Outputs:

- `codeql_conditional_rule_runs_60.jsonl`
- `evidence_packets_60_codeql_conditional.jsonl`
- `labels_60_strengthened.jsonl`
- `strong_label_promotion_60_summary.json`

Result:

- 110 fixed-view CodeQL fact rows and 111 vulnerable-view CodeQL fact rows were available.
- 15 rule runs were recorded.
- 2 positive rule-scoped `codeql_conditional` labels were produced:
  - `vs-smoke-T0005` / `vs-smoke-C60-0018`: `VS-LIFE-REF-LIVE-001`, refcount live-acquire rule.
  - `vs-smoke-T0015` / `vs-smoke-C60-0043`: `VS-LIFE-RCU-DEFER-001`, RCU deferred-release rule.
- 4 scoped `codeql_conditional_negative` contrast labels were produced.
- 13 rule runs remained `not_promoted`.

Boundary: this pass proves the 60-task pipeline can produce recorded rule-validation rows, but it does not make the dataset training-ready. The rule coverage is narrow, CodeQL validation covers only 4 tasks so far, and Joern/Coccinelle graph/path/callback plus dynamic evidence is still missing for most candidates.

## Candidate-Scale Lesson

The 60-task expanded dataset currently has 2,321 candidate locations, or 38.7 candidates per task. This passes the CLeVeR-like 1,600-row checkpoint, but VulnSignal should treat that as 1,600 task-grouped candidate rows, not 1,600 independent vulnerable/non-vulnerable functions and not 1,600 confirmed bugs. Candidate count alone is not dataset quality.

The first 20-task expansion pass added:

- 164 CodeQL lifecycle-fact candidates with source windows extracted from local kernel checkouts
- 326 weak CodeQL-nearby contrast candidates
- 51 patch-context candidates around patch-anchored rows
- 215 new UNKNOWN labels

No new row was promoted to vulnerability truth by this step.

Candidate-density growth should remain provenance-backed. Useful candidate sources include:

- Joern path/graph/call-neighbor anchors
- CodeQL validator `rule_matched` anchors
- same-function nearby windows
- same-file related functions
- callgraph/dataflow neighbors
- wrapper/API seeds from Coccinelle or Joern facts
- RCU/callback/timer/workqueue anchors
- hard negatives near tool evidence

The 60-task expansion reached the 50-75 task and 1,600-row smoke checkpoints with every row carrying provenance, label strength when labeled, and missing-view status. The next target is evidence quality: broader Joern/Coccinelle representation extraction, mandatory CodeQL validation-attempt records for applicable rules, callback-aware rule validation, and more tool-backed labels.

## Negative Subtype Metadata

The current 60-task labels now include training-role and negative/unknown subtype metadata. This implements the policy that the dataset remains task-grouped and ranking-based, while negative examples are sampled and evaluated by subtype rather than treated as separate vulnerability classes.

Current generated counts:

- `positive_relevant`: 269 rows
- `negative_candidate`: 1,293 rows
- `unknown_abstention`: 759 rows
- `weak_nearby_hard_negative`: 530 rows
- `same_api_hard_negative`: 759 rows
- `checker_pass_hard_negative`: 4 rows
- `unknown_or_unproven`: 759 rows

Policy:

- `weak_nearby_hard_negative` rows are same-task ranking contrasts, not global safe-code labels.
- `same_api_hard_negative` rows are near parser-backed or CodeQL-backed lifecycle/API facts and should be sampled as harder contrasts.
- `checker_pass_hard_negative` rows are rule-scoped negatives produced only after a positive rule passes.
- `unknown_or_unproven` rows train abstention/calibration and must not be silently converted into negatives.

Implementation files:

- `generate_hard_negatives_60.py` emits `weak_nearby_hard_negative`.
- `promote_codeql_conditional_labels.py` emits `checker_pass_hard_negative` and fills missing `training_role` metadata.
- `expand_candidate_generation_60.py` emits `same_api_hard_negative` and `unknown_or_unproven`.

This metadata supports the first training recipe: task-grouped pairwise ranking with one positive, one easy/wide negative, two hard negatives, and two verified/conditional hard negatives when available. Positive reuse must be capped per epoch because pair expansion creates comparisons, not true positive diversity.

## Strategy Feedback Incorporated

The project direction is now explicit:

- Linux/CVE task instances remain the primary dataset foundation.
- SARD/CLeVeR-style function-level data is not planned for the current dataset. It is structurally mismatched with VulnSignal's task/candidate records and would likely double dataset-engineering effort.
- Tool-grounded evidence is the primary semantic anchor; vulnerability descriptions are auxiliary.
- Official inference modes are `tool_grounded`, `few_shot_description_assisted`, and `description_only_zero_shot`.
- Verifier-guided post-training is the main later-stage innovation beyond CLeVeR-style representation learning.
- UNKNOWN calibration is a first-class objective, not a cleanup detail.

## 60-Task Joern Graph/Callback Evidence Pass

The graph/path blocker is no longer completely untested. We ran Joern over the two `codeql_conditional` positive candidates and converted selected Joern DOT output into candidate-level graph facts:

```bash
VS_DATASET_TAG=60 python3 reports/e022_object_lifetime_smoke/summarize_joern_graph_facts.py

VS_OUTPUT_SUFFIX=_60 VS_CANDIDATE_INPUT=candidate_locations_60_expanded.jsonl VS_SOURCE_WINDOW_INPUT=source_windows_60_expanded.jsonl VS_CODEQL_FACT_INPUTS=full_source_codeql_facts_batch_codeql_probe12_arg0.jsonl,full_source_codeql_facts_batch_codeql_probe4_vulnerable.jsonl VS_COCCI_LIFECYCLE_INPUT=coccinelle_window_lifecycle_matches_60.jsonl VS_COCCI_WRAPPER_INPUT=coccinelle_wrapper_candidate_matches_60.jsonl VS_JOERN_SUMMARY_INPUT=joern_window_graph_summary_60.json VS_JOERN_GRAPH_FACT_INPUT=joern_graph_facts_60.jsonl VS_RULE_RUN_INPUT=codeql_conditional_rule_runs_60.jsonl VS_EVIDENCE_PACKET_INPUT=evidence_packets_60_codeql_conditional.jsonl python3 reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py

python3 reports/e022_object_lifetime_smoke/profile_dataset_readiness_60.py
python3 reports/e022_object_lifetime_smoke/write_60_status_report.py
```

Outputs:

- `joern_graph_facts_60.jsonl`
- `joern_graph_fact_summary_60.json`
- regenerated `control_flow_order_facts_60.jsonl`
- regenerated `alias_dataflow_facts_60.jsonl`
- regenerated `callback_graph_facts_60.jsonl`
- regenerated `vulnerability_rule_validation_60.jsonl`
- regenerated `dataset_readiness_60_profile.json`

Result:

- 4 Joern graph facts were emitted with 0 missed specs.
- 3 facts are `parsed_graph_fact_available`.
- 1 fact is `callback_edge_available`.
- `vs-smoke-C60-0018` now carries Joern support for:
  - fixed: `refcount_inc_not_zero -> mod_timer -> ip_ma_put`
  - vulnerable: `!mod_timer -> refcount_inc`
- `vs-smoke-C60-0043` now carries Joern support for:
  - fixed: `list_del_rcu -> call_rcu(... mac802154_llsec_key_del_rcu)` with callback body terms `llsec_key_put` and `kfree_sensitive`
  - vulnerable: `list_del_rcu -> llsec_key_put` without the deferred callback

Dataset impact:

- `graph_path_facts` readiness moved from `blocked` to `partial_pass`.
- The 60-task multiview bridge now records:
  - 2 candidate rows with parsed control-flow graph support
  - 2 candidate rows with parsed DDG support
  - 1 candidate row with a resolved RCU callback edge
  - 1 candidate row with supporting CPG available but callback unresolved
- Rule validation for `vs-smoke-C60-0043` now records `callback_graph_facts=callback_edge_available`.

Boundary:

- These rows are supporting Joern tool-output evidence, not final vulnerability truth.
- The current summarizer uses scoped specs for selected smoke candidates. This is acceptable for a feasibility pass, but it is not enough for scale.
- The next graph/path task is to replace scoped specs with generalized Joern/SVF/CodeQL query logic for RCU callbacks, timer/workqueue callbacks, object identity, and candidate-local path order.

## Next Rule Work

The next representation work comes before adding many more labels:

1. Improve CodeQL/SVF/Joern object identity extraction.
2. Keep adding normalized view fields from tool-emitted facts, not raw source regexes.
3. Add tool-proven relationship edges only when they are needed for validation or high-precision modes.
4. Then promote labels when the required views exist.

High-value rules to add next:

- wrapper-aware refcount rules for subsystem-specific acquire/release APIs
- callback ref handoff rules for callback traversal and callback completion paths
- generalized RCU deferred-release rules that require release or unlink context
- acquire/release imbalance inside a candidate-local path
- publish/remove without cancellation or flush
- timer/workqueue callback can run after object release

Each new rule must define:

- required vulnerable facts
- required fixed facts
- source-window or path preconditions
- candidate matching policy
- label strength produced
- failure reason when the rule cannot promote
