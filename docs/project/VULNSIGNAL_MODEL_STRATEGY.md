# VulnSignal Model Strategy

## Primary model

The first VulnSignal model is a non-generative candidate ranker.

It may use a neural source encoder, a code language model, or language-model-assisted reranking. The boundary is not "no deep learning." The boundary is that model output is a ranked candidate proposal, not vulnerability truth.

Source-only language-model assistance is allowed as a baseline or assistant track. The main VulnSignal claim remains tool-grounded when Joern/Coccinelle representation evidence exists and CodeQL/checker validation-attempt records, checker results, or dynamic-oracle evidence determine label strength.

VulnSignal uses tool-grounded evidence as the primary semantic anchor for candidate ranking. Vulnerability-concept descriptions may be added as an auxiliary contrastive view, inspired by CLeVeR-style representation refinement, to improve low-sample and family-focused ranking. These descriptions can be rule/family descriptions, public advisory text, human-authored hypotheses, or LLM-assisted hypotheses. They remain weak guidance rather than ground truth.

The intended improvement over CLeVeR-style description-supervised representation learning is:

- tool-evidence-grounded representation
- Linux task-grouped candidate ranking
- verifier-guided post-training from checker/oracle outcomes
- explicit UNKNOWN calibration

SARD-style data is not planned for the current model path. It is mostly function-level C/C++ data, while VulnSignal is task/candidate based and depends on source snapshots, candidate rows, and tool-evidence views. A SARD conversion/pretraining lane would likely double engineering effort and may optimize for the wrong structure. Consider it only as a later transfer-risk study after the Linux baseline is stable.

## Model task

Input:

- candidate source slice
- normalized AST/expression facts
- normalized lifecycle/API event facts
- normalized object identity facts when a tool resolves them
- normalized CFG/order facts when available
- normalized DFG/DDG/dataflow and alias facts when available
- normalized callback/async facts when available
- optional crash/sanitizer context
- retrieved similar fixes
- protocol rule candidates
- optional vulnerability-concept descriptions
- missing-view mask

Output:

- suspiciousness score
- affected object
- protocol/rule class
- evidence fact selection
- mutation/test guidance class
- confidence / UNKNOWN

## Representation Boundary

Each input view must be normalized enough for the model to generalize, but the dataset should not hand-build all fine-grained relationships among views.

AST, CFG, and DFG/DDG are separate dataset representations, not one pre-combined representation. The dataset should keep source windows, AST/expression facts, CFG/order facts, DFG/DDG/dataflow facts, lifecycle/API events, object identity, callback/async facts, and rule evidence as distinct candidate-linked views. The model then fuses their embeddings through typed query-bank cross-attention or gated fusion.

Required explicit alignment is candidate-level: `task_id`, `candidate_id`, file/function/line range, view, producer tool, extraction rule, and missing-view mask. Model-visible fields should prefer generalized semantic tokens such as `operation_role`, `api_family`, `operation_class`, `security_axis`, `lifecycle_stage`, `identity_status`, and `rule_family`. Raw callee names, object expressions, file paths, and source text remain available for audit, but they should be masked, ablated, or treated carefully in model training to reduce memorization.

Cross-attention then learns soft relationships among source tokens, AST/call facts, lifecycle events, object-identity facts, CFG/order facts, DFG/DDG/dataflow facts, callback facts, and rule evidence. Tool-proven relationship edges can be added later as auxiliary validation evidence, but they are not required default inference inputs.

Joern CPG can be the source artifact for multiple structural views because it contains syntax, control-flow, and data-flow information. VulnSignal should still export those views separately where possible. Keeping them separate enables source-only, source+AST, source+CFG, source+DFG, and source+tool-evidence ablations, and prevents the proposal from hiding weak coverage inside one opaque "graph" input.

## Representation refinement

The refinement design should not be described as novel only because it uses cross-attention. Multi-view source/graph/description refinement already exists in prior work. The VulnSignal-specific design is to use a typed evidence-query bank where tool-derived evidence provides the strongest query signals.

Typed query groups:

- `Q_rule`: rule result, rule family, or CodeQL/checker validation outcome
- `Q_path`: Joern, SVF, or checker path facts
- `Q_event`: lifecycle/API event sequence around the candidate
- `Q_object`: object-identity or alias facts when a tool resolves them
- `Q_context`: task brief, crash/advisory text, checker question, or benchmark context
- `Q_description`: optional vulnerability-concept description, including human-authored or LLM-assisted hypotheses when no tool-grounded or public evidence is available

Key/value views:

- `K,V_source`: source-window token and line embeddings
- `K,V_ast`: AST/expression fact embeddings
- `K,V_event`: lifecycle/API event embeddings
- `K,V_cfg`: CFG/order embeddings when available
- `K,V_dfg`: DFG/DDG/dataflow, alias, or object-flow embeddings when available
- `K,V_callback`: callback/async graph embeddings when available
- `K,V_context`: task context and optional description embeddings

Tool-grounded queries are the primary semantic anchors. Description and hypothesis queries are auxiliary and lower confidence. Availability masks and evidence-strength weights must prevent missing tool views or weak hypothesis views from being treated as strong validation.

## Model architecture options

### Option A - Two-tower ranker

```text
Source encoder + Joern/Coccinelle representation encoder + CodeQL validation encoder -> fusion -> ranking score
```

Good first implementation.

Concrete first-model embedding design:

- source window encoder: code-token embeddings, line-position embeddings, candidate-span markers
- AST/expression encoder: expression-kind embeddings, call/callee-family embeddings, argument-position embeddings, source-location embeddings
- CFG/order encoder: statement or basic-block embeddings, branch-condition embeddings, local order-position embeddings, and control-edge-type embeddings
- DFG/DDG/dataflow encoder: def-use embeddings, value-flow embeddings, alias-status embeddings, object-flow embeddings, and data-dependence edge embeddings
- lifecycle/API event encoder: operation-role embeddings, API-family embeddings, operation-class embeddings, lifecycle-stage embeddings
- object identity encoder: identity-status embeddings, `UNKNOWN_OBJECT_ID`, and tool-resolved object IDs when available
- fact/path encoder: fact-kind embeddings, predicate embeddings, edge-type embeddings, path-position embeddings
- context encoder: task brief, crash/advisory text, optional agent-view summaries
- vulnerability-concept encoder: optional text embeddings for rule/family descriptions, CVE/advisory descriptions, human-authored hypotheses, or LLM-assisted concept summaries allowed by split policy
- fusion: typed query-bank cross-attention or gated fusion over source, AST/expression, CFG/order, DFG/DDG/dataflow, lifecycle/API, object identity, fact/path, callback/async, context, vulnerability-concept, and agent-view embeddings
- missing-view mask: allows source-only ablation without pretending it is tool-grounded

### Option B - Heterogeneous graph ranker later ablation

This is not required for the first model. Use it only after the separate-view ranker works and only as an ablation to test whether a graph encoder improves ranking.

Nodes: source lines, functions, variables, AST nodes, Joern/Coccinelle fact nodes, CodeQL validation nodes, crash stack frames, protocol rule nodes.

Edges: AST parent/child, local/global dataflow, call graph, source-line adjacency, crash-stack relation, candidate relation.

### Option C - Cross-attention fusion model

Encoders: source slice encoder, fact/path encoder, error report encoder, retrieval context encoder.

Heads: location ranking, protocol rule, evidence selection, mutation guidance, uncertainty.

This is the most likely research model after the first two-tower baseline. It should be compared against simpler baselines before making an improvement claim.

## Training objectives

Overall objective:

```text
L_total =
  L_rank
  + lambda_contrast * L_contrast
  + lambda_rule * L_rule
  + lambda_object * L_object
  + lambda_evidence * L_evidence
  + lambda_pref * L_pref
  + lambda_unknown * L_unknown
```

All ranking losses are grouped by `task_id`; candidates from unrelated tasks are not compared as one global binary class table.

`L_contrast` is an auxiliary representation-alignment loss. It should align a candidate with matching tool evidence, rule concept, path evidence, vulnerable/fixed contrast, or allowed vulnerability-concept description, and push it away from mismatched evidence or descriptions.

### Location ranking loss

Use pairwise or listwise ranking.

Positive candidates:

- root-cause locations
- fix-hunk lines/functions
- dynamic oracle-linked lines
- CodeQL source/sink paths

Hard negatives:

- easy/wide negatives
- nearby functions
- same API but not root cause
- same file non-root cause
- fixed-version non-buggy analogs
- CodeQL/checker `rule_not_matched` or checker-cleared candidates
- UNKNOWN or unproven candidates for abstention, not negative classification

Ranking loss:

- weighted pairwise margin loss or listwise softmax loss grouped by `task_id`
- task-balanced sampling so large tasks do not dominate
- hard-negative upweighting by negative subtype

Examples:

```text
L_pair = weight_negative * max(0, margin_negative - score(positive) + score(negative))

L_list = -log exp(score(positive)) / sum_candidate exp(score(candidate))
```

Initial negative subtype weights:

| Negative subtype | Weight | Margin |
| --- | ---: | ---: |
| easy negative | 0.5 | 0.2 |
| hard negative | 1.0 | 0.5 |
| verified or conditional hard negative | 1.5 | 0.7 |

Initial training groups should contain one positive candidate, one easy/wide negative, two hard negatives, and two verified/conditional hard negatives when available. Negatives rotate within the same task, same rule family, same API/sink, same file/function, same subsystem, fixed-version analogs, and CodeQL/checker `rule_not_matched` candidates. Do not generate all possible pairs; cap positive reuse per epoch.

### Protocol rule classification

Predict mechanism, not generic CWE.

Examples:

- use-after-free
- out-of-bounds write
- missing bounds check
- missing ref acquire
- missing cancel/flush before destroy
- missing rollback cleanup
- null dereference

### Evidence fact selection

Predict which facts support the predicted rule or candidate explanation.

Use binary cross-entropy over candidate-linked fact IDs, with masking when no fact view is available.

### Contrastive alignment

Use contrastive learning to make the fused candidate representation closer to matching evidence/concept views and farther from mismatched views.

Positive pairs:

- candidate source window plus matching tool-grounded evidence
- candidate plus matching rule instance or path evidence
- vulnerable candidate plus its patch-linked or oracle-linked evidence
- candidate plus allowed vulnerability-concept description or `hypothesis_only` concept view

Negative pairs:

- candidate plus unrelated rule evidence
- candidate plus evidence from another task
- nearby hard negative plus vulnerable evidence
- fixed-version analog plus vulnerable evidence
- candidate plus description from another vulnerability family

One standard option is InfoNCE:

```text
L_contrast =
  -log exp(sim(z_candidate, z_positive) / temperature)
       / sum_evidence exp(sim(z_candidate, z_evidence) / temperature)
```

This loss supports representation learning; it does not create vulnerability truth or promote weak labels by itself.

### Verifier-guided preference loss

After the task-grouped ranking baseline works, add preference training from checker/oracle outcomes.

Examples:

- CodeQL/checker `rule_matched` candidate > rule-scoped `rule_not_matched` candidate
- dynamic-oracle-linked candidate > same-file distractor
- CodeQL-path-supported candidate > weak nearby hard negative
- root-cause candidate > patch-nearby UNKNOWN
- strong evidence > weak evidence
- UNKNOWN should abstain, not become negative

One standard option:

```text
L_pref = -log sigmoid(beta * (score(supported) - score(rejected)))
```

This is a later-stage objective, not the first baseline.

### Mutation guidance

Predict test direction: entrypoint, input field, syscall/API region, parser branch, object state condition.

### Confidence and UNKNOWN calibration

Predict when evidence is insufficient.

Use calibration loss or abstention-style objective so `UNKNOWN` is learned as a first-class outcome, not as a discarded row.

## Assistant model role

General-purpose language models are not the primary model or truth source.

Allowed later roles:

- source-window encoding or reranking
- explanation generation
- report summarization
- rule/evidence natural-language rendering
- optional distillation target after tool-grounded data exists

Disallowed primary role:

- general-purpose language model as ground truth
- language-model-only vulnerability classifier
- language-model-first training before dataset/oracle is stable

## Inference modes

Report inference mode explicitly.

- `tool_grounded`: supported vulnerability families with source windows and tool-derived evidence views. This is the main VulnSignal result.
- `few_shot_description_assisted`: new rule description plus a few positives and hard negatives are used for adaptation. This needs later checker/oracle validation.
- `description_only_zero_shot`: human-authored or LLM-assisted vulnerability hypothesis used as a CLeVeR-like query without tool-grounded rule evidence. This is exploratory hypothesis-prior ranking and can guide hypothesis-based checks, but it is not validation.
