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
| AST/expression facts | CodeQL, Clang AST, Joern CPG | Used for calls, arguments, member access, source locations, and expression structure. |
| Object identity facts | CodeQL, SVF, Joern CPG/DDG | Must identify the object through tool-visible expression, value-flow, alias, or graph evidence. |
| Lifecycle/API event facts | CodeQL, Coccinelle, Joern | Coccinelle can provide semantic API matches, but bounded-window matches are supporting evidence unless a rule policy allows promotion. |
| CFG/order facts | Joern CFG, CodeQL control-flow APIs | Used for candidate-local order and path constraints. |
| Dataflow/alias facts | SVF, CodeQL dataflow, Joern DDG/PDG | Required before claiming alias-aware or interprocedural object continuity. |
| Callback/async graph facts | SVF, CodeQL, Joern CPG/DDG | Required before claiming workqueue, timer, RCU callback, or indirect-call continuity. |
| Rule results | VulnSignal rule runner over tool facts | Rule instances must reference the tool facts they consumed. |
| Dynamic oracle evidence | syzkaller, KASAN, KCSAN, reproducers, fuzz tests | Required for `dynamic` labels. |

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
