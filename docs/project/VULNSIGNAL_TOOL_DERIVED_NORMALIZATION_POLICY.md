# VulnSignal Tool-Derived Normalization Policy

VulnSignal keeps raw source windows for audit, but model-facing normalized records must come from tool-derived evidence whenever they affect label strength.

Default model inputs are aligned at the candidate level. That means the views share `task_id`, `candidate_id`, source location, runtime view, producer tool, and missing-view masks. The dataset should not require a hand-built fine-grained relationship graph between source tokens, AST nodes, object identities, API events, and graph nodes before the model can run.

## Rule

Do not promote labels from hand-normalized source text. A normalized record that participates in rule validation must cite:

- the producer tool
- the source representation used by that tool
- the original record or fact IDs
- the task, candidate, file, function, and view it belongs to
- the trust level and limitations

If the pipeline cannot prove an object identity or relation from a tool output, it must emit an explicit unknown value such as `UNKNOWN_OBJECT_ID` or a missing-view validation row. Unknown is valid data. Invented identity is not.

Cross-attention is expected to learn soft relationships among candidate-local views. Explicit object-operation, alias, callback, or path edges are optional auxiliary evidence only when a tool produces them. They are not required default inference inputs.

## Model-Visible Normalization

Normalization is still required. The goal is to prevent the model from learning only project names, function names, file paths, or specific API spellings.

Preferred model-visible fields include:

- `normalized_operation_role`, such as `acquire_ref_if_live`, `release_ref`, `defer_free_rcu`, or `timer_register`
- `api_family`, such as `refcount`, `kref`, `rcu`, `timer`, `workqueue`, or `allocator`
- `operation_class`, such as `acquire`, `release`, `free`, `defer_free`, `async_register`, or `async_enqueue`
- `security_axis`, such as `object_lifecycle`, `async_lifecycle`, or `memory_lifecycle`
- `lifecycle_stage`, such as `live_guard`, `unchecked_acquire`, `release`, `destroy`, or `deferred_release`
- `identity_status`, such as `tool_expression_identity` or `unresolved`
- missing-view status for facts that could not be generated

Raw fields such as `callee`, `object_expression`, `file`, `function`, and full source windows remain in the artifact for audit and debugging. They should be masked, ablated, or used with leakage controls during training unless an experiment explicitly measures the impact of exposing them.

## Accepted Tool Sources

| Representation | Accepted tools | Notes |
| --- | --- | --- |
| AST/expression facts | Joern CPG, Clang AST | Used for calls, arguments, member access, source locations, and expression structure. CodeQL-derived AST rows may exist in legacy smoke artifacts but are not the forward default. |
| Object identity facts | Joern CPG/DDG, SVF | Must identify the object through tool-visible expression, value-flow, alias, or graph evidence. |
| Lifecycle/API event facts | Coccinelle, Joern | Coccinelle can provide semantic API matches, but bounded-window matches are supporting evidence unless a rule policy allows promotion. |
| CFG/order facts | Joern CFG, Clang/LLVM when available | Used for candidate-local order and path constraints. |
| Dataflow/alias facts | Joern DDG/PDG, SVF | Required before claiming alias-aware or interprocedural object continuity. |
| Callback/async graph facts | Joern CPG/DDG, SVF | Required before claiming workqueue, timer, RCU callback, or indirect-call continuity. |
| CodeQL validation results | CodeQL validators under `validators/codeql/` | Primary validation tool for candidate evidence level. Emits `rule_matched`, `rule_not_matched`, or `rule_unknown`. |
| Rule results | VulnSignal rule runner over tool facts and CodeQL validation results | Rule instances must reference the tool facts and validation records they consumed. |
| Dynamic oracle evidence | syzkaller, KASAN, KCSAN, reproducers, fuzz tests | Required for `dynamic` labels. |

## Joern vs CodeQL Policy

Joern is the primary scalable representation extractor. It should produce
candidate-level AST, CFG, DDG/dataflow-like, callgraph, callback, and graph
neighborhood views without requiring a full Linux build. This keeps both
preprocessing and inference usable when Kbuild, architecture config, generated
headers, cross-compilers, or local compile environments are unavailable.

Coccinelle is the Linux semantic-pattern lane for lifecycle/API events and
wrapper/API evidence. Tree-sitter or similar parser-backed tools may support
source-window extraction and lightweight syntax anchors.

CodeQL is the primary validation tool for determining evidence level. For every
candidate with an applicable lifecycle/security rule, the pipeline must attempt
CodeQL validation first. Canonical CodeQL validators live under
`validators/codeql/` and attach candidate-level validation-attempt records:

- `rule_matched`: expected lifecycle protocol evidence was observed in the candidate window.
- `rule_not_matched`: the validator ran, but the rule evidence was not observed in the candidate window.
- `rule_unknown`: CodeQL could not validate the candidate because the database, source view, build metadata, Kconfig, architecture, generated headers, dependency, toolchain, or required facts were unavailable or incomplete.

Do not treat CodeQL `rule_not_matched` as globally safe code. It is only a
rule-scoped result under a specific source snapshot and build configuration.
Do not treat blocked CodeQL validation as optional or absent. It must be stored
as `rule_unknown` with a blocker reason.

Implementation priority:

1. Generalize Joern-first AST/CFG/DDG/callback extraction for candidate windows.
2. Keep Coccinelle lifecycle/API matching as a parser-backed semantic evidence lane.
3. Store CodeQL validators separately under `validators/codeql/`.
4. Attempt CodeQL validation first for applicable candidate/rule pairs and store the result in `codeql_validation_results.jsonl`.
5. Keep every missing or unsupported view as an explicit missing-view mask or `rule_unknown`.

## Strength Boundary

- `dynamic`: requires reproduced oracle behavior, usually pre-patch FAIL and post-patch PASS.
- `tool_crosschecked`: requires matching rule evidence across multiple tool-derived views, including object identity when the rule depends on an object.
- `codeql_conditional`: allowed when CodeQL/tool fact-delta rules pass but some stronger evidence, such as object identity or dynamic behavior, is still missing.
- `patch_confirmed_weak`: patch/advisory evidence only, with no rule validation.
- `weak`: ranking contrast or context only.
- `UNKNOWN`: missing build, missing tool facts, unresolved object identity, incomplete rule evidence, or unsupported vulnerability shape.

## Custom Logic Boundary

VulnSignal may use project code to join tool outputs, assign stable IDs, and record missing evidence. It must not use ad hoc source-token parsing as the basis for strong object identity, alias, callback, or vulnerability-truth claims.

Fallback mappings are allowed only as provisional records with `trust_level: "unknown"` or `trust_level: "supporting"`. They cannot promote a candidate to a stronger label without accepted tool evidence.
