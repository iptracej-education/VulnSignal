# VulnSignal Model Strategy

## Primary model

The first VulnSignal model is a non-generative candidate ranker.

It may use a neural source encoder, a code language model, or language-model-assisted reranking. The boundary is not "no deep learning." The boundary is that model output is a ranked candidate proposal, not vulnerability truth.

Source-only language-model assistance is allowed as a baseline or assistant track. The main VulnSignal claim remains tool-grounded when CodeQL facts, checker results, or dynamic-oracle evidence validate labels.

## Model task

Input:

- candidate source slice
- CodeQL facts
- optional crash/sanitizer context
- retrieved similar fixes
- protocol rule candidates

Output:

- suspiciousness score
- affected object
- protocol/rule class
- evidence fact selection
- mutation/test guidance class
- confidence / UNKNOWN

## Model architecture options

### Option A - Two-tower ranker

```text
Source encoder + CodeQL fact encoder -> fusion -> ranking score
```

Good first implementation.

Concrete v0 embedding design:

- source window encoder: code-token embeddings, line-position embeddings, candidate-span markers
- fact/path encoder: fact-kind embeddings, predicate embeddings, object-ID embeddings, edge-type embeddings, path-position embeddings
- context encoder: task brief, crash/advisory text, optional agent-view summaries
- fusion: cross-view attention or gated fusion over source, fact/path, context, and agent-view embeddings
- missing-view mask: allows source-only ablation without pretending it is tool-grounded

### Option B - Heterogeneous graph ranker

Nodes: source lines, functions, variables, AST nodes, CodeQL fact nodes, crash stack frames, protocol rule nodes.

Edges: AST parent/child, local/global dataflow, call graph, source-line adjacency, crash-stack relation, candidate relation.

### Option C - Cross-attention fusion model

Encoders: source slice encoder, fact/path encoder, error report encoder, retrieval context encoder.

Heads: location ranking, protocol rule, evidence selection, mutation guidance, uncertainty.

## Training objectives

Overall objective:

```text
L_total =
  L_rank
  + lambda_rule * L_rule
  + lambda_object * L_object
  + lambda_evidence * L_evidence
  + lambda_unknown * L_unknown
```

All ranking losses are grouped by `task_id`; candidates from unrelated tasks are not compared as one global binary class table.

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
