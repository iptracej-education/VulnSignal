# Proposal: VulnSignal - Tool-Grounded Candidate Ranking for Vulnerability Research

## Introduction

VulnSignal proposes a tool-grounded dataset and deep-learning pipeline for vulnerability research. It does not train a generic vulnerable/non-vulnerable function classifier; it ranks suspicious source-code locations inside a real investigation, predicts likely violated rules, selects supporting evidence, and reports uncertainty.

The first implementation focuses on C/C++ object lifecycle, concurrency, and memory-safety bugs, starting with Linux-style object lifetime and refcount patterns. The dataset foundation is public Linux/CVE task instances with source snapshots, patch or advisory anchors, generated candidate snippets, scalable tool-derived representations, and sparse CodeQL validation records when buildable validation is available.

Tool-grounded means every model row links back to source anchors, generated representation records, evidence provenance, and explicit missing-evidence status. Joern, Coccinelle, and parser-backed tools generate scalable representations. CodeQL is a sparse high-confidence validator for selected rules: when attempted, it records `rule_matched`, `rule_not_matched`, or `rule_unknown` with blocker substatus. The model is a proposer, not a judge, and final validation still requires checker/oracle evidence or explicit `UNKNOWN`.

Core workflow:

```text
input artifacts:
  source snapshot + generated evidence + candidate source locations

model outputs:
  ranked file/function/line windows
  likely rule, affected object, supporting evidence, and validation guidance

validation records:
  optional CodeQL/checker rule_matched, rule_not_matched, or rule_unknown
```

## Problem Statement/Background/Motivation/Related Works

Source-code machine learning has moved from token-only models toward multi-representation learning. Surveys on source-code representations and vulnerability analysis, GNN-based vulnerability detectors, code-language-model work, and systems such as CLeVeR show that tokens, ASTs, CFGs, DFGs, program graphs, code property graphs, and vulnerability descriptions each expose different signals. The lesson is useful, but it is not enough by itself: "source plus graph plus attention" does not create vulnerability truth.

Most ML vulnerability-detection datasets still frame the task as function-level vulnerable/non-vulnerable classification. That is a poor match for real vulnerability research. A reviewer usually starts with a project snapshot, patch/advisory/checker question, crash clue, or rule family, then must:

1. locate relevant code inside a large project
2. compare many plausible file/function/line candidates
3. reason across object lifetime, control flow, data flow, callbacks, and API protocol
4. identify evidence that supports or weakens the claim
5. decide what needs validation and what remains unknown

VulnSignal treats this as task-local candidate ranking. The dataset unit is not "one function = vulnerable or not"; it is one investigation task with many candidate code snippets. Ranking is the right learning target because it matches reviewer workflow, handles naturally imbalanced data, and measures whether the model can surface useful candidates within a limited review budget.

Tool-grounding gives the model higher-confidence suspicious-code candidates while keeping the ranking auditable. Each candidate links back to a source version, concrete location, generated representation records, and available validation evidence. CodeQL is valuable but sparse in C/C++ systems code because build, Kconfig, architecture, generated-header, and toolchain requirements are real constraints. Therefore `rule_unknown` is a first-class result with substatus, not a silent skip or negative label. LLM-assisted workflows can help read code, draft hypotheses, summarize evidence, and rerank candidates, but an LLM-only result is not reproducible validation. VulnSignal assumes LLM output is auxiliary unless it is tied back to source anchors and tool records.

Tool-derived multiple representations strengthen inference by giving the model normalized evidence channels beyond raw source tokens. Joern, Coccinelle, SVF/LLVM, Clang/Tree-sitter, and CodeQL-derived validation can expose lifecycle/API order, object identity, control flow, data flow, callbacks, graph neighborhoods, and rule evidence. When these views agree, the ranker can assign higher confidence to suspicious candidates; when views are missing or conflicting, it should preserve uncertainty. Therefore, VulnSignal's core research question is whether these abstractions improve suspicious-location ranking beyond source-only baselines.


## Objectives/Project Ideas/Research Contributions

The model is not trained to answer:

```text
Is this function vulnerable?
```

It is trained to answer:

```text
Which existing source-code locations should be inspected first?
What object or protocol is implicated?
Which lifecycle/security rule may be violated?
What evidence supports the candidate explanation?
What validation evidence should be tried next?
What remains UNKNOWN?
```

Primary contributions:

1. A dataset built around tasks (vulnerability investigations) and candidates (code snippets), rather than function-level vulnerable/non-vulnerable labels.
2. A sparse CodeQL validation process that applies selected vulnerability rules when buildable validation is available and records matched, not matched, or unknown with blocker substatus as high-confidence evidence.
3. A candidate-ranking model that uses source code, static-analysis representations, sparse validator evidence, and missing-evidence masks to rank suspicious code snippets, identify likely violated rules, select supporting evidence, and report uncertainty.
4. An evaluation of whether tool-derived abstract representations improve suspicious-location ranking for selected vulnerability families.

## Project Execution Map

VulnSignal has four execution tracks:

1. Dataset construction: collect public source artifacts, create vulnerability-investigation tasks, generate candidate code snippets, and attach source/evidence provenance.
2. Representation extraction: use Joern, Coccinelle, and parser-backed static analysis to turn each candidate code snippet into model inputs.
3. Sparse validation: run CodeQL/checker validation where practical, record matched/not matched/unknown with substatus, and preserve unavailable validation as explicit uncertainty.
4. Model training and evaluation: train a candidate-ranking model, evaluate top-k suspicious-location ranking, and report uncertainty instead of claiming source-only vulnerability truth.

Detailed JSONL schemas and pipeline steps are maintained in the dataset strategy and design documents, not repeated here.

## Methodology

### Task and Candidate Definitions

A task is one vulnerability-research investigation. We call it a task because candidates are ranked inside one project, source snapshot, and validation question.

Task row columns:

```text
task_id, project, source_snapshot, vulnerability_family, validation_question
```

A candidate is one existing code snippet to inspect inside a task. We call it a candidate because it is only a review target, not generated code and not a confirmed bug.

Candidate row columns:

```text
candidate_id, task_id, file, function, line_start, line_end, bucket, evidence_status
```

Example:

```json
{
  "candidate_id": "C7",
  "task_id": "T1",
  "file": "parser.c",
  "function": "parse_chunk",
  "line_start": 210,
  "line_end": 235
}
```

Candidate buckets are evidence-dependent. A task may produce candidates from crash frames, patch hunks, same-function snippets, same-file functions, CodeQL path nodes, callgraph/dataflow neighbors, and hard negatives. Missing evidence creates no bucket rows or an explicit `UNKNOWN`; the pipeline must not fabricate candidates.

In practice, tasks and candidates are stored as two linked tables: `task_instances.jsonl` has one row per investigation, and `candidate_locations.jsonl` has many candidate rows linked by `task_id`.

### Dataset

VulnSignal is a derived dataset, not a downloaded vulnerable/non-vulnerable table. The initial source basis is public Linux/CVE artifacts with source snapshots, patches or advisories, source anchors, generated candidate code snippets, scalable representation records, and sparse CodeQL validation records when available.

The current active dataset phase is `real_dataset_30_cve`, backed by the E030 evidence-grounded 30-CVE build. Its current snapshot contains 30 CVE tasks, 1,233 candidate locations, 1,233 source-window records, 1,233 labels, 30 mechanism profiles, 87 evidence targets, 709 protocol/evidence representation rows, 432 CodeQL validation attempts, 270 CodeQL validation rows, and 14 reviewed non-CodeQL source-validation rows. Evidence status is mixed but mostly strong: 29 tasks now have reviewed `strong_tool_evidence`, while T0024 remains completed at `medium` because the current CodeQL extractor/build path exposes no usable futex/mempolicy target-function facts.

The first model-ready E030 package is built under `reports/e030_evidence_grounded_dataset_30/model_ready/`. It contains 1,233 joined candidate rows, 1,793 ordered evidence-preference pairs, a deterministic task-grouped split of 21 train / 3 validation / 6 test tasks, and explicit missing-view masks. Joern representation tables add AST/CFG candidate-view rows for all candidates, DDG support for 444 candidates, callback/API support for 24 candidates, and lifecycle operation/object support for 79 candidates. Fixed source remains audit-only; only vulnerable/current source windows are model-visible.

The first source-only and multi-view baselines have also been run on this package. Source-only uses only vulnerable/current source text and reaches strict held-out test MRR 0.5977, Hit@1 0.5000, Hit@10 0.8333, and nDCG@10 0.5782 over primary/supporting strong positives. The no-build full static-view baseline uses source, protocol/API, vulnerable-view Joern AST/CFG/DDG/callback/lifecycle features, and missing-view masks; it reaches MRR 0.8667, Hit@1 0.8333, Hit@10 1.0000, and nDCG@10 0.7922 without using fixed-source Joern rows or CodeQL/source-validation result fields. Validation-assisted results are kept as an offline diagnostic, not default inference.

The dataset is expected to be imbalanced and mixed-strength. It records label value, label strength, evidence source, and `UNKNOWN` explicitly instead of forcing balanced vulnerable/non-vulnerable labels.

Each CVE/task also needs a mechanism profile before a rule can produce stronger evidence. The rule-development chain is: CVE/task mechanism -> evidence targets -> CodeQL query search/adaptation -> validation result -> evidence strength. Before writing custom QL, VulnSignal searches existing CodeQL C/C++ queries, CWE query coverage, CodeQL libraries, and local validators; a separate security-research review pass challenges the CVE mechanism and edge cases.

### Model Input Format

Each model row is one candidate code snippet linked to one task. The model uses three input groups:

| Input group | What it contains | Purpose |
| --- | --- | --- |
| Source code | The candidate file/function/line snippet with span markers | Lets the model read the actual code under review. |
| Tool-grounded linked tables | Task rows, candidate rows, sparse CodeQL/checker validation rows, labels, evidence strength, and `UNKNOWN` reasons | Connects the code snippet to the investigation and available validation evidence. |
| Representations | Protocol/API events, AST facts, CFG/order facts, DFG/DDG/dataflow facts, graph/path facts, and optional agent-view text | Tests whether tool-derived abstractions improve ranking beyond source code alone. |

This representation layer is a core research component. For each vulnerability family, VulnSignal evaluates which abstract views help the model rank suspicious candidate snippets.

All inputs are joined by `task_id` and `candidate_id`. Missing rows are recorded explicitly; the pipeline does not fabricate evidence. The E030 model-ready package materializes this join as `model_inputs.jsonl`, `source_view_representations.jsonl`, `evidence_view_representations.jsonl`, `missing_view_masks.jsonl`, `task_splits.jsonl`, and `pairwise_ranking_pairs.jsonl`.

### Protocol/API Event Extraction Tooling

Protocol/API events and several fact/path records above must come from parser-backed or checker-backed tools, not grep-only matching or invented traces. Joern is the primary representation extractor; Coccinelle, SVF/LLVM, Tree-sitter, and Clang tooling may add focused views when useful. CodeQL is reserved for sparse validation: attempted rules record `rule_matched`, `rule_not_matched`, or `rule_unknown` with source anchors and blocker substatus. Missing CodeQL validation is not fabricated as negative evidence.

Patch-to-rule classes such as `patch_signature_rule`, `patch_derived_protocol_rule`, `path_object_rule`, and `exploratory_generated_rule` describe rule origin only. Evidence strength comes from what the query proves for the CVE mechanism: weak API/patch signal, medium protocol/object evidence, strong tool evidence, or `UNKNOWN`.

### Data Processing

The pipeline creates linked JSONL tables for source acquisition, tasks, candidates, source snippets, representation records, sparse CodeQL validation results, optional oracle/agent records, and labels. Candidate rows are generated by tools and audited by humans; they are not hand-labeled one by one.

Splits should avoid source, patch, label, and validation leakage. Labels remain candidate-level: relevant, non-root-cause, or `UNKNOWN`, with negative subtypes used only for sampling and evaluation. For E030, pair generation is performed after the deterministic task-grouped split so candidates from one CVE task do not cross train/validation/test boundaries.

### DL Model/Architecture

VulnSignal uses a non-generative multi-view candidate ranker. It scores existing candidate snippets inside a task; it does not decide final vulnerability truth.

| Component | Design |
| --- | --- |
| Encoders | Separate encoders for source code, tool-grounded linked tables, and tool-derived representations. |
| Fusion | Cross-attention or gated fusion combines the views. Tool-grounded evidence is the main semantic anchor; description or agent text is weak auxiliary input when used. |
| Masks | Missing-view masks and evidence-strength weights prevent absent or weak evidence from being treated as strong validation. |
| Heads | Ranking score, likely rule/protocol, affected object, selected evidence, and confidence/`UNKNOWN`. |

The main architecture question is whether tool-derived abstract representations improve task-local suspicious-location ranking beyond source code alone. Training losses and staged training are described below.

### Training

Training is grouped by `task_id`: candidates are compared inside the same investigation, not as one global vulnerable/non-vulnerable table. This is how VulnSignal handles imbalance, hard negatives, mixed evidence strength, and `UNKNOWN` rows.

The model is trained with a weighted multi-task objective:

$$
L_{\text{total}} = L_{\text{rank}} + \lambda_{\text{contrast}}L_{\text{contrast}} + \lambda_{\text{rule}}L_{\text{rule}} + \lambda_{\text{object}}L_{\text{object}} + \lambda{\text{evidence}}L_{\text{evidence}} + \lambda_{\text{pref}}L_{\text{pref}} + \lambda_{\text{unknown}}L_{\text{unknown}}
$$

The first baseline should use task-local weighted pairwise ranking:

$$
L_{\text{pair}}
= w_n \max(0,\; m_n - s(c^+) + s(c^-))
$$

Contrastive learning aligns candidate representations with matching tool evidence or allowed vulnerability-concept descriptions:

$$
L_{\text{contrast}} = -\log \frac{\exp(\mathrm{sim}(z_c, z_e^+) / \tau)}{\exp(\mathrm{sim}(z_c, z_e^+) / \tau)+\sum_{e^-}\exp(\mathrm{sim}(z_c, z_e^-) / \tau)}
$$

After the ranking baseline works, verifier-guided post-training can use CodeQL/checker outcomes as preferences:

$$
L_{\text{pref}} = -\log \sigma\left(\beta\left(s(c_{\text{supported}}) - s(c_{\text{rejected}})\right)\right)
$$

The training sequence is: source-only baseline, source plus representation views, contrastive alignment, verifier-guided preference training, and `UNKNOWN` calibration. Positive reuse must be capped, and splits must be made before pair generation.

### Testing

Testing separates model-visible inputs from hidden truth.

| Visible at inference | Hidden for evaluation only |
| --- | --- |
| source snapshot, selected vulnerability families, task context, generated candidates, source snippets, representation rows, available CodeQL/checker validation-attempt rows, optional agent views | ground-truth labels, root-cause location, fixed source, patch answer, oracle/fuzz/reproducer outcomes, label-source fields |

Default inference should not require CodeQL compilation. The no-build path ranks candidates from source, Joern/Coccinelle, and other scalable representations. CodeQL can be run asynchronously for dataset construction, offline evaluation, or optional top-k validation. Source-only mode is allowed as a baseline, but it must be reported as `source_only`, not as the primary tool-grounded result.

## Evaluation

Evaluation focuses on ranking quality, evidence quality, and uncertainty, not binary accuracy.

The baseline/evaluation contract is defined in `docs/project/VULNSIGNAL_BASELINE_EVALUATION.md`. In short, each baseline ranks candidates within one CVE task. The target order is primary strong evidence first, supporting strong evidence next, patch-weak or weak nearby evidence after that, with UNKNOWN kept as unresolved rather than false. Metrics are reviewer-facing: how quickly a reviewer sees strong evidence in the ranked list.

| Area | Metrics |
| --- | --- |
| Ranking | top-k localization, MRR, nDCG, hard-negative Recall@k |
| Evidence | selected-fact precision/recall, evidence-chain overlap, rule/object accuracy |
| Reliability | `UNKNOWN` calibration, false positives by negative subtype, project/CVE-disjoint performance |
| Review cost | number of evidence packets inspected before finding a validated candidate |

Required baselines are random ranking, source-only ranking, proximity ranking, API-token/source-text ranking, and CodeQL/checker-only ranking. Required ablations compare source only, source plus representations, source plus descriptions, and removal of object, lifecycle/API, CFG/DFG/path, or verifier-guided views.

Results must be reported by rule family, project split, label strength, representation availability, candidate-density bucket, and CodeQL validation outcome. Weak or `UNKNOWN` rows must not be used to claim final vulnerability-detection accuracy.

## Challenges/Ethical Considerations & Risks

- Weak labels: keep weak and `UNKNOWN` labels explicit.
- Leakage: hide patch, oracle, and label-source fields during inference.
- Source-only or LLM overclaiming: report source-only results as baselines, not tool-grounded validation.
- Human review overload: audit top-k packets and stratified samples, not every candidate row.
- Sparse checker coverage: record `rule_unknown` with blocker substatus and use it for uncertainty, not positive or negative truth.
- Dual-use risk: frame outputs as defensive candidate prioritization, not exploit proof.

## Deliverables

| Deliverable | Output |
| --- | --- |
| Public proposal documents | `README.md`, `PROPOSAL.md`, and `DOCUMENT_INDEX.md` |
| Dataset pipeline | task/candidate schemas, representation extraction, sparse CodeQL validation records, labels |
| Inference pipeline | source ingestion, candidate generation, no-build representation generation, top-k ranking packets, optional asynchronous validation |
| Models | random/source-only/proximity/checker baselines and multi-view neural ranker |
| Report | top-k localization, evidence quality, `UNKNOWN` calibration, and review-budget analysis |

## Candidate Original Data Sources

- OSS-Fuzz / ClusterFuzz public disclosed issues
- OSV.dev
- GitHub Advisory Database
- CVEfixes
- MoreFixes after license/storage review
- Magma-style benchmark tasks after repository/license review
- CyberGym-style tasks for held-out evaluation or schema inspiration

Implementation resources:

- Python and PyTorch for model prototypes
- Joern/Coccinelle for scalable representation extraction
- CodeQL for sparse high-confidence validation evidence and checker-backed conditional labels when buildable validation is available
- Git/source indexing tools for source-window and candidate generation
- Earlier object-lifetime scripts and reports for object-lifetime vocabulary and evidence-packet discipline
