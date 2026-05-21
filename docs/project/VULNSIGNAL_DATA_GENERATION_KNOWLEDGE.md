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
- 29 lifecycle matches

Coccinelle evidence is useful as an independent tool signal, especially when full Kbuild-backed CodeQL extraction is blocked. The current policy does not promote Coccinelle-window-only matches to strong positive labels without an explicit rule policy.

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

## Multi-View Normalization Bridge

The smoke dataset now has a generated bridge from tool evidence to model-facing views:

```text
reports/e022_object_lifetime_smoke/build_multiview_artifacts_20.py
reports/e022_object_lifetime_smoke/multiview_artifact_summary_20.json
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
- 265 lifecycle/API operation role facts, including 9 wrapper-candidate-only operation facts
- 151 CFG/order rows
- 151 alias/dataflow rows
- 151 callback/async rows
- 21 rule instances and 21 rule-validation rows

The bridge normalizes evidence into generalized model-visible fields such as `normalized_operation_role`, `api_family`, `operation_class`, `security_axis`, `lifecycle_stage`, `identity_status`, and `rule_family`. Raw `callee`, `object_expression`, `file`, `function`, and source-window text remain audit fields and should be masked or ablated during model training when testing memorization risk.

Important boundary: the default dataset does not create an explicit object-operation or token-to-fact relationship graph for inference. Views are aligned by candidate ID, source location, tool provenance, and missing-view masks. Cross-attention should learn the soft relationships among views. Tool-proven relationship edges may be added later as auxiliary validation evidence, not as required default inference input.

## Lessons For Scaling

1. Build both vulnerable and fixed views first. Without both views, most rules stay weak or UNKNOWN.
2. Candidate-local line windows are required. Function-level matching is too broad for repeated lifecycle calls.
3. CodeQL fact IDs are not globally unique across views unless the view is included. Use `view:fact_id` references in evidence packets.
4. Patch hunk function guesses are not reliable around inserted helper functions, callbacks, and RCU patterns. Use line-window fallback.
5. Strong negative labels must be scoped to a rule. Do not train global non-vulnerable claims from nearby code.
6. A promotion rule should record failed runs as well as passed runs. Failed runs explain missing facts and guide the next extractor improvements.
7. Secondary tool evidence should be explicit. Coccinelle/Joern/SVF evidence can support promotion only when the rule policy says how it is allowed to do so.
8. Dynamic-oracle unavailability should be recorded as an environment/tooling blocker, not silently converted into weak static labels.
9. Normalize tool-derived evidence into generalized semantic fields before training.
10. Do not require manually built fine-grained cross-view edges for inference; use candidate-level alignment and missing-view masks.
11. Use rule-gap reports to choose rule work. Do not blindly add rules for every patch hunk.

## Candidate-Scale Lesson

The 20-task smoke dataset currently has 151 candidate locations, or 7.55 candidates per task. This proves the extraction path, but it is not enough for training. A CLeVeR-like scale of roughly 1,600 examples is a useful minimum row-count checkpoint, but VulnSignal should treat that as 1,600 task-grouped candidate rows, not 1,600 independent vulnerable/non-vulnerable functions and not 1,600 confirmed bugs.

To reach that checkpoint without weakening supervision, the next generator should increase candidate density per task:

- CodeQL path nodes and checker-result anchors
- same-function nearby windows
- same-file related functions
- callgraph/dataflow neighbors
- wrapper/API seeds from Coccinelle or CodeQL facts
- RCU/callback/timer/workqueue anchors
- hard negatives near tool evidence

The target for the next expansion is 50-75 tasks and at least 1,600 candidate rows, with every row carrying provenance, label strength when labeled, and a missing-view mask. Candidate count alone is not dataset quality.

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
