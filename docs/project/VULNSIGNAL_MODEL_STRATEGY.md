# VulnSignal Model Strategy

## Primary model

The first VulnSignal model is a non-generative candidate ranker.

It may use a neural source encoder, a code language model, or language-model-assisted reranking. The boundary is not "no deep learning." The boundary is that model output is a ranked candidate proposal, not vulnerability truth.

Source-only language-model assistance is allowed as a baseline or assistant track. The main VulnSignal claim remains tool-grounded when CodeQL facts, checker results, or dynamic-oracle evidence validate labels.

VulnSignal uses tool-grounded evidence as the primary semantic anchor for candidate ranking. Vulnerability-concept descriptions may be added as an auxiliary contrastive view, inspired by CLeVeR-style representation refinement, to improve low-sample and family-focused ranking. These descriptions can be rule/family descriptions, public advisory text, human-authored hypotheses, or LLM-assisted hypotheses. They remain weak guidance rather than ground truth.

## Model task

Input:

- candidate source slice
- normalized AST/expression facts
- normalized lifecycle/API event facts
- normalized object identity facts when a tool resolves them
- normalized CFG/order, alias/dataflow, and callback/async graph facts when available
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

Required explicit alignment is candidate-level: `task_id`, `candidate_id`, file/function/line range, view, producer tool, extraction rule, and missing-view mask. Model-visible fields should prefer generalized semantic tokens such as `operation_role`, `api_family`, `operation_class`, `security_axis`, `lifecycle_stage`, `identity_status`, and `rule_family`. Raw callee names, object expressions, file paths, and source text remain available for audit, but they should be masked, ablated, or treated carefully in model training to reduce memorization.

Cross-attention then learns soft relationships among source tokens, AST/call facts, lifecycle events, object-identity facts, CFG/order facts, graph facts, and rule evidence. Tool-proven relationship edges can be added later as auxiliary validation evidence, but they are not required default inference inputs.

## Representation refinement

The refinement design should not be described as novel only because it uses cross-attention. Multi-view source/graph/description refinement already exists in prior work. The VulnSignal-specific design is to use a typed evidence-query bank where tool-derived evidence provides the strongest query signals.

Typed query groups:

- `Q_rule`: rule result, rule family, or checker outcome
- `Q_path`: CodeQL, Joern, SVF, or checker path facts
- `Q_event`: lifecycle/API event sequence around the candidate
- `Q_object`: object-identity or alias facts when a tool resolves them
- `Q_context`: task brief, crash/advisory text, checker question, or benchmark context
- `Q_description`: optional vulnerability-concept description, including human-authored or LLM-assisted hypotheses when no tool-grounded or public evidence is available

Key/value views:

- `K,V_source`: source-window token and line embeddings
- `K,V_ast`: AST/expression fact embeddings
- `K,V_event`: lifecycle/API event embeddings
- `K,V_graph`: CFG, dataflow, alias, callback, or object-flow graph embeddings when available
- `K,V_context`: task context and optional description embeddings

Tool-grounded queries are the primary semantic anchors. Description and hypothesis queries are auxiliary and lower confidence. Availability masks and evidence-strength weights must prevent missing tool views or weak hypothesis views from being treated as strong validation.

## Model architecture options

### Option A - Two-tower ranker

```text
Source encoder + CodeQL fact encoder -> fusion -> ranking score
```

Good first implementation.

Concrete first-model embedding design:

- source window encoder: code-token embeddings, line-position embeddings, candidate-span markers
- AST/expression encoder: expression-kind embeddings, call/callee-family embeddings, argument-position embeddings, source-location embeddings
- lifecycle/API event encoder: operation-role embeddings, API-family embeddings, operation-class embeddings, lifecycle-stage embeddings
- object identity encoder: identity-status embeddings, `UNKNOWN_OBJECT_ID`, and tool-resolved object IDs when available
- fact/path encoder: fact-kind embeddings, predicate embeddings, edge-type embeddings, path-position embeddings
- context encoder: task brief, crash/advisory text, optional agent-view summaries
- vulnerability-concept encoder: optional text embeddings for rule/family descriptions, CVE/advisory descriptions, human-authored hypotheses, or LLM-assisted concept summaries allowed by split policy
- fusion: typed query-bank cross-attention or gated fusion over source, AST/expression, lifecycle/API, object identity, fact/path, graph, context, vulnerability-concept, and agent-view embeddings
- missing-view mask: allows source-only ablation without pretending it is tool-grounded

### Option B - Heterogeneous graph ranker

Nodes: source lines, functions, variables, AST nodes, CodeQL fact nodes, crash stack frames, protocol rule nodes.

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

- nearby functions
- same API but not root cause
- same file non-root cause
- fixed-version non-buggy analogs

Ranking loss:

- pairwise margin loss or listwise softmax loss grouped by `task_id`
- task-balanced sampling so large tasks do not dominate
- hard-negative upweighting for same-file, same-function, and CodeQL-neighbor candidates

Examples:

```text
L_pair = max(0, margin - score(positive) + score(negative))

L_list = -log exp(score(positive)) / sum_candidate exp(score(candidate))
```

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
- `compositional_few_or_zero_shot`: new rule or family described using known evidence types such as acquire, release, callback, lock, dereference, or bounds-check events. This may generalize across familiar schemas but still requires later checker/oracle validation.
- `description_only_zero_shot`: human-authored or LLM-assisted vulnerability hypothesis used as the query without tool-grounded rule evidence. This is exploratory hypothesis-prior ranking and can guide hypothesis-based checks, but it is not validation.
