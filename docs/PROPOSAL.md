# Proposal: VulnSignal - Checker-Grounded Candidate Ranking for Vulnerability Research

## Introduction

VulnSignal proposes a checker-grounded dataset and deep-learning pipeline for vulnerability research. The project does not train a generic vulnerable/non-vulnerable function classifier. Instead, it learns to rank suspicious source-code locations inside a real vulnerability-research task, predict likely protocol or security-rule hypotheses, select supporting evidence, and report uncertainty when proof is incomplete. Checker-grounded means labels and evidence come from CodeQL, rule checkers, crashes, reproducers, fuzz tests, or patch-confirmed behavior.

The initial vulnerability-family focus is C/C++ object lifecycle, concurrency, and memory-safety bugs. The first pilot emphasizes Linux-style object lifetime and refcount patterns, including use-after-free, publish-after-free, missing acquire/release, cancel/flush-before-destroy, and related concurrency-sensitive lifecycle rules. After the first pilot validates the dataset and evidence pipeline, the initial expansion may add bounds checks, double-free, null/error-path cleanup, and parser/input-validation memory-safety families.

The core workflow is:

```text
input artifacts:
  source snapshot + generated evidence + candidate source locations

model outputs:
  ranked file/function/line windows
  likely rule, affected object, supporting evidence, and test guidance

validation outputs:
  checker/oracle-backed PASS, FAIL, or UNKNOWN
```

The model is a proposer, not a judge. CodeQL/checker results, dynamic oracles, evidence-backed patch behavior, or explicit `UNKNOWN` determine label strength.

## Problem Statement/Background/Motivation/Related Works

Most machine-learning vulnerability-detection projects train on function-level C/C++ datasets with vulnerable/non-vulnerable labels. These datasets are useful for representation-learning benchmarks, but they usually do not reproduce the workflow of vulnerability researchers:

1. locating relevant code inside a large project
2. reasoning across call paths, object lifetimes, dataflow, and protocol rules
3. forming a concrete vulnerability hypothesis
4. identifying evidence that supports or weakens the hypothesis
5. suggesting a test, fuzz target, or mutation direction
6. validating the claim through a dynamic oracle or trusted checker

Recent agentic vulnerability-research systems and benchmarks, such as MDASH-style workflows and CyberGym-style task environments, are not simple classifiers. They use task setup, source context, semantic grounding, validation, proof, and feedback. VulnSignal adopts that architectural lesson but narrows the scope to one trainable operation: candidate ranking.

Earlier object-lifetime work in the source repository showed a clear limitation: ranking code by rough labels, source-text patterns, lightweight object-flow signals, or agreement between language models does not prove that a bug exists. VulnSignal therefore requires each training example to point back to a real source version, a specific code location, machine-checkable facts when available, and validation evidence such as a checker result, crash, reproducer, fuzz test, or explicit `UNKNOWN` when the evidence is incomplete.

This proposal is not trying to cover every vulnerability class at once. It starts where the repository already has evidence and terminology: object lifecycle, refcount, concurrency, and memory-safety protocols in C/C++ systems code. That scope is narrow enough to define checkable rules, but broad enough to grow beyond a single Linux refcount demonstration.

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
What evidence supports the hypothesis?
What test or mutation direction should be tried?
What remains UNKNOWN?
```

Primary contributions:

1. A research direction that treats ML for vulnerability research as high-confidence candidate proposal, not generic function-level vulnerability classification.
2. A system design that combines source code, checker facts, runtime evidence, and patch evidence to rank suspicious locations for review.
3. A dataset design that preserves real project context, source versions, candidate locations, evidence provenance, and uncertainty.
4. A model target focused on proposing where to inspect, what rule may be violated, what object may be affected, and what evidence should be checked next.
5. A validation policy that separates model suggestions from vulnerability truth, requiring checkers, crashes, reproducers, fuzz tests, patch-confirmed behavior, or explicit `UNKNOWN`.
6. A human-audit workflow that helps reviewers inspect a small ranked set of evidence-backed candidates instead of manually validating thousands of raw locations.

## Project Execution Map

The project has two related but separate pipelines.

### Dataset-construction pipeline

This pipeline converts an original public artifact, such as a CVE record, crash report, patch, benchmark case, or checker rule, into structured training records. Each step records where the source came from, what investigation task it creates, which code locations should be considered, what source text and evidence are attached, and what label strength can be trusted.

```text
original dataset record
  -> source_acquisition_manifest.jsonl
  -> task_instances.jsonl
  -> candidate_locations.jsonl
  -> source_windows.jsonl
  -> codeql_facts.jsonl / oracle_runs.jsonl / agent_views.jsonl
  -> labels.jsonl
```

### Inference evidence pipeline

This pipeline is used after training on a new source snapshot. It automatically proposes candidate locations, extracts the needed source context and checker facts, ranks the candidates, and produces a small review packet for humans or downstream validation.

```text
new source snapshot
  -> candidate generator
  -> source window extractor
  -> CodeQL/checker fact builder, when using checker-grounded mode
  -> optional agent-view generator
  -> candidate ranker
  -> top-k review packet
```

At inference time, labels, fixed source, patch truth, known root cause, and oracle results are hidden unless the runtime pipeline executes the checker or oracle.

We also keep a source-code-only mode. This mode can be integrated into LLM-agent workflows as a hypothesis engine that suggests suspicious locations, likely rules, and review questions. However, source-code-only suggestions are not validation; checker/oracle evidence is still required for `PASS`, `FAIL`, or `UNKNOWN` labels.

## Methodology

### Task and Candidate Definitions

A task is one vulnerability-research investigation:

```text
one project + one source snapshot + one crash/rule/advisory/checker question
```

A candidate location is one existing file/function/line window to inspect. It is not a generated program, mutated source variant, or confirmed bug.

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

Candidate buckets are evidence-dependent, not mandatory. A task may produce candidates from crash frames, patch hunks, same-function windows, same-file functions, CodeQL path nodes, callgraph/dataflow neighbors, and hard negatives. Missing evidence produces no bucket rows or explicit `UNKNOWN`, not fabricated candidates.

### Dataset

VulnSignal is not one downloaded vulnerable/non-vulnerable dataset. It is a derived dataset built from original source artifacts with explicit provenance.

| Source family | Original artifacts | VulnSignal use | Admission rule |
| --- | --- | --- | --- |
| Executable-oracle bugs | Public OSS-Fuzz/ClusterFuzz disclosed issues; Magma-style benchmark tasks after review | Primary train/evaluation seeds | Strong only when source snapshot, reproducer/fuzz input, build/test command, and pre-patch FAIL / post-patch PASS evidence are available. |
| CodeQL/checker tasks | Selected source snapshots plus VulnSignal CodeQL/lifecycle/security rules | Primary conditional labels | Conditional when CodeQL database metadata, query/rule ID, normalized facts, source anchors, and PASS / FAIL / UNKNOWN result are present. |
| Patch/advisory sources | OSV, GHSA, CVEfixes, MoreFixes, project security patches | Candidate expansion and weak provenance | Weak or UNKNOWN unless upgraded by checker/oracle/before-after evidence. Patch hunk alone is never strong truth. |
| Held-out tasks | CyberGym-style packets or separate benchmark tasks | Evaluation only by default | Keep held out unless an uncontaminated split is explicit. |

Initial scale targets:

```text
object_lifetime_pilot:
  50-100 task_instances
  5,000-10,000 candidate_locations
  one rule family
  schema + checker validation only

first_multi_family_dataset:
  300 task_instances
  20,000 candidate_locations
  object lifetime + bounds + double-free/null/error-path families
  CodeQL/checker conditional labels plus reproduced dynamic-oracle evidence
```

The 300-task target is not credible if interpreted as 300 strong Linux object-lifetime/refcount vulnerabilities from one source. It should be treated as the first multi-family C/C++ dataset target after the object-lifetime pilot validates the pipeline.

These datasets will be naturally imbalanced: most candidate locations are not the confirmed root cause, and many will remain `UNKNOWN`. Later training and evaluation sections mitigate this with task-level ranking losses, hard-negative sampling, explicit `UNKNOWN` calibration, and top-k review metrics instead of global balanced binary classification.

### Data Processing

Required derived files:

- `source_acquisition_manifest.jsonl`: original source name, original record ID, source URL/path, revision IDs, artifact hashes, license/usage note, and split eligibility.
- `task_instances.jsonl`: one investigation with source family, project, snapshot commit, build/test metadata, oracle/checker availability, and split policy.
- `candidate_locations.jsonl`: existing file/function/line windows generated before ranking.
- `source_windows.jsonl`: bounded source snippets and token windows for each candidate.
- `codeql_facts.jsonl`: normalized fact/path records keyed by fact ID and source anchor.
- `oracle_runs.jsonl`: executable evidence rows such as command, exit code, sanitizer/crash output, pre-patch result, post-patch result, and reproducibility status.
- `agent_views.jsonl`: optional LLM-agent summaries, hypotheses, affected-object guesses, review questions, and test ideas.
- `labels.jsonl`: candidate-level label value, label strength, label source, evidence references, limitations, and explicit `UNKNOWN`.

Candidate rows and source windows should be generated by the pipeline, not hand-created by humans. Humans audit the generation quality, leakage risk, rule definitions, and ambiguous evidence.

Splits:

- project-disjoint where possible
- time-disjoint where possible
- source-family-disjoint or rule-family-disjoint for stress testing
- CyberGym-style held-out evaluation by default
- no fixed-source, patch-label, label-source, or oracle-result leakage into inference features

VulnSignal accepts imbalanced data. It should not manufacture a globally balanced vulnerable/non-vulnerable dataset. Negatives come from same-task hard negatives, checker PASS rows, non-root-cause candidates, callgraph/dataflow neighbors, and UNKNOWN rows.

### DL Model/Architecture

The model does not generate a final vulnerability report. It reads each task's candidate code locations and available evidence, then scores which locations should be inspected first. It can combine multiple inputs, such as source-code windows, CodeQL/checker facts, crash or patch evidence, and optional LLM-agent summaries. In architecture terms, this is a non-generative multi-view candidate ranker.

The model may use a neural source encoder, code language model, or language-model-assisted reranking. In this proposal, a neural source encoder means the learned part of the model that converts source code into numeric embeddings. Examples include a CodeBERT-style code language model, a transformer over code tokens and lines, a smaller token/line encoder, or a graph/code-structure encoder if AST, callgraph, or dataflow structure is added later. The boundary is not "no deep learning"; the boundary is that model output is not vulnerability truth.

Input views:

- source window tokens and candidate-span markers
- CodeQL/checker fact/path records when available
- task context such as crash/advisory/rule brief
- optional agent views such as summaries and hypotheses

Embedding design:

Each input source has its own encoder that turns that input into numeric embeddings. The model then combines those embeddings with cross-attention or gated fusion.

- source window encoder: code-token embeddings, line-position embeddings, candidate-span embeddings
- fact/path encoder: fact-kind embeddings, predicate embeddings, object-ID embeddings, edge-type embeddings, path-position embeddings
- context encoder: task brief, crash/advisory text, checker question
- agent-view encoder: optional generated summaries and hypotheses

Fusion:

- cross-attention between input views, where source code, checker facts, task context, and optional agent summaries can attend to each other
- gated fusion, where the model learns how much weight to give each input view, especially when some evidence is missing or weaker
- missing-view masks so source-only ablations are allowed without pretending to be checker-grounded

Prediction heads:

The model uses a shared fused representation for each candidate, then applies separate prediction heads for different outputs. The heads are not independent models: the ranking head identifies which locations matter most, while the rule, object, evidence, guidance, and uncertainty heads add explanations and validation cues for those ranked locations.

- location ranking score
- rule family / protocol hypothesis
- affected object
- evidence fact selection
- test/fuzz/mutation guidance
- confidence / UNKNOWN

Loss function:

The model is trained with a weighted multi-task loss:

$$
L_{\text{total}}
= L_{\text{rank}}
+ \lambda_{\text{rule}} L_{\text{rule}}
+ \lambda_{\text{object}} L_{\text{object}}
+ \lambda_{\text{evidence}} L_{\text{evidence}}
+ \lambda_{\text{unknown}} L_{\text{unknown}}
$$

The $\lambda$ values are tunable scalar weights that control how much each auxiliary loss contributes relative to candidate ranking.

`L_rank` trains candidate ordering within the same task. `L_rule` trains likely rule or protocol prediction. `L_object` trains affected-object prediction. `L_evidence` trains supporting-fact selection. `L_unknown` trains confidence calibration and abstention when evidence is incomplete.

### Training

During training, each batch contains one or more tasks and their candidate locations. The model computes all prediction heads, combines their losses into $L_{\text{total}}$, and backpropagates the combined loss through the shared encoders, fusion layers, and heads.

The ranking component, $L_{\text{rank}}$, is computed within each `task_id`; candidates from unrelated tasks are not compared as one global binary class table. This helps with imbalance because the model compares candidates inside the same investigation task, while hard-negative sampling, label-strength weighting, and `UNKNOWN` calibration prevent the many negative or uncertain rows from dominating training.

In the first implementation, $L_{\text{rank}}$ will use one ranking objective, either pairwise or listwise:

$$
L_{\text{rank}} = L_{\text{pair}}
$$

or

$$
L_{\text{rank}} = L_{\text{list}}
$$

Pairwise loss compares a positive candidate with a negative candidate:

$$
L_{\text{pair}}
= \max(0,\; m - s(c^+) + s(c^-))
$$

Listwise loss ranks all candidates within the same task:

$$
L_{\text{list}}
= -\log
\frac{\exp(s(c^+))}
{\sum_{c \in C_t} \exp(s(c))}
$$

A later implementation may combine both:

$$
L_{\text{rank}}
= \alpha L_{\text{pair}} + (1-\alpha)L_{\text{list}}
$$

where $\alpha$ is a tunable mixing weight.

Auxiliary losses:

- rule/object classification cross-entropy trains the rule-family head and affected-object head when the dataset identifies the violated rule or implicated object.
- evidence fact selection binary cross-entropy trains the evidence head to select supporting CodeQL/checker facts, path nodes, crash frames, or patch-linked facts from the candidate's evidence set.
- UNKNOWN/confidence calibration or abstention-style objective trains the model to lower confidence when evidence is incomplete, conflicting, or outside the checker/oracle coverage.

Training implementation can use PyTorch. The first implementation should prioritize:

1. source-only baseline
2. source + fact/path ranker
3. source + fact/path + context ranker
4. optional agent-view reranker

Hyperparameter tuning should be modest at first: candidate window size, maximum candidates per task, encoder size, fusion method, hard-negative sampling weight, loss weights, and top-k review budget. Optuna or a similar search tool should be used only after the baseline pipeline produces reliable validation results.

### Testing

Testing must distinguish inference inputs from evaluation-only truth.

Inference inputs:

- source snapshot for target project/version
- task brief, rule family, crash/advisory text, or checker question when available
- generated candidate-location rows with source windows
- CodeQL/checker fact rows if the evaluated model was trained to use them
- optional agent views if the evaluated model was trained to use them

Hidden evaluation-only fields:

- ground-truth labels
- root-cause location
- patch diff and fixed source
- oracle result and post-patch behavior
- label-source fields that reveal the answer

Source-only mode is allowed as a baseline or assistant track, but must be reported as `source_only`, not as the primary checker-grounded VulnSignal result.

## Evaluation

Primary metrics:

- top-k localization: whether the validated root-cause or checker-FAIL candidate appears in top 1, 3, 5, or 10
- MRR / mean reciprocal rank
- nDCG over label strength and candidate relevance
- evidence fact precision/recall when fact-level evidence is available
- rule-family and affected-object accuracy for validated labels
- UNKNOWN calibration and abstention quality
- reviewer-effort reduction: evidence packets inspected before finding validated candidates

Required baselines:

- random candidate ranking
- source-only neural or language-model-assisted ranker
- crash-stack proximity ranking
- patch-proximity ranking
- API-token/source-text ranker
- CodeQL path/checker-only ranking

Evaluation must report results by source family, rule family, project split, label strength, and availability of CodeQL/checker facts.

## Challenges/Ethical Considerations & Risks

Risks and mitigations:

- **Weak labels masquerading as truth:** patch/advisory-only rows remain weak or UNKNOWN unless upgraded by checker/oracle evidence.
- **Dataset leakage:** fixed source, patch labels, oracle results, and label-source metadata are excluded from inference features.
- **Overclaiming source-only LLM output:** language models may assist ranking and explanation, but cannot create final truth.
- **Unmanageable human review:** humans audit top-k packets and stratified samples, not all 20,000+ candidate rows.
- **Insufficient object-lifetime scale:** object-lifetime/refcount is a pilot family; a 300-task dataset requires broader C/C++ memory-safety families.
- **Licensing/provenance problems:** source admission records must include source, license/usage note, and artifact hashes.
- **Checker incompleteness:** CodeQL/checker results are conditional truth under explicit facts and rules; incomplete facts become UNKNOWN.
- **Dual-use security risk:** outputs should be framed as defensive research assistance, not exploit automation; evaluation should emphasize validation and responsible handling.

## Deliverables

1. `docs/PROPOSAL.md` with the final project proposal.
2. Detailed architecture PNG: `diagrams/vulnsignal_detailed_architecture.png`.
3. Compact visual deck: `docs/slides/vulnsignal_compact_visual_deck.html`.
4. Detailed dataset deck: `docs/slides/vulnsignal_dataset_development.html`.
5. Dataset schema definitions for task instances, candidates, source windows, facts, oracle runs, labels, and agent views.
6. Dataset-construction pipeline prototype for the object-lifetime pilot.
7. Inference evidence pipeline prototype for new source snapshots.
8. Baseline rankers: random, source-only, proximity, checker-only.
9. Multi-view neural candidate-ranker prototype.
10. Evaluation report with top-k localization, evidence quality, UNKNOWN calibration, and review-budget analysis.

## Project Plan and Tasks

### Phase 0 - Proposal and alignment

- Finalize `docs/PROPOSAL.md`.
- Keep the compact and detailed slide decks aligned with the proposal.
- Maintain the VulnSignal alignment gate.

### Phase 1 - Object-lifetime pilot dataset

- Select 50-100 object-lifetime/refcount tasks.
- Build source acquisition manifest.
- Generate candidate locations and source windows.
- Create initial CodeQL/lifecycle facts and checker rules.
- Produce labels with `dynamic`, `codeql_conditional`, `weak`, or `UNKNOWN` strength.

### Phase 2 - Inference pipeline

- Build source snapshot ingestion.
- Build candidate generator.
- Build source-window extractor.
- Integrate CodeQL/checker fact generation when available.
- Add optional agent-view generation.
- Emit top-k review packets.

### Phase 3 - Model baselines

- Implement random, source-only, proximity, and checker-only rankers.
- Train source-only neural ranker.
- Train source + fact/path ranker.
- Compare missing-view and source-only ablations.

### Phase 4 - First multi-family dataset

- Expand beyond object lifetime into bounds, double-free, null/error-path, and parser/input-validation families.
- Target 300 tasks and 20,000 candidate locations.
- Maintain project/rule/source-family split discipline.

### Phase 5 - Evaluation and reporting

- Report top-k localization and MRR/nDCG.
- Report evidence selection and UNKNOWN calibration.
- Report review-budget results.
- Document failure cases and source-family limitations.

## Resources

Primary project docs:

- `docs/project/VULNSIGNAL_VISION.md`
- `docs/project/VULNSIGNAL_DATASET_STRATEGY.md`
- `docs/project/VULNSIGNAL_MODEL_STRATEGY.md`
- `docs/project/VULNSIGNAL_CODEQL_FACT_SCHEMA.md`
- `docs/project/VULNSIGNAL_GROUND_TRUTH_POLICY.md`
- `docs/slides/vulnsignal_dataset_development.html`
- `docs/slides/vulnsignal_compact_visual_deck.html`

Candidate original data sources:

- OSS-Fuzz / ClusterFuzz public disclosed issues
- OSV.dev
- GitHub Advisory Database
- CVEfixes
- MoreFixes after license/storage review
- Magma-style benchmark tasks after repository/license review
- CyberGym-style tasks for held-out evaluation or schema inspiration

Implementation resources:

- Python and PyTorch for model prototypes
- CodeQL for fact extraction and checker-backed conditional labels
- Git/source indexing tools for source-window and candidate generation
- Earlier object-lifetime scripts and reports for object-lifetime vocabulary and evidence-packet discipline

# NOTE

## What track are you choosing?

Engineering-oriented research prototype. The work builds a dataset pipeline, inference evidence pipeline, and deep-learning candidate-ranker, while preserving research controls around truth, leakage, and evaluation.

## What is your data source?

The data source is a derived VulnSignal dataset built from public original artifacts: OSS-Fuzz/ClusterFuzz public cases, CodeQL/checker-generated tasks, OSV/GHSA/CVEfixes/MoreFixes metadata for weak candidate expansion, and held-out CyberGym-style tasks for evaluation only by default.

## Summarize the status of your data and what cleaning is needed.

The repository has object-lifetime evidence and VulnSignal strategy docs, but not a finished VulnSignal dataset. Cleaning requires source admission records, deduplication, source snapshot anchoring, line/function normalization, fact normalization, leakage removal, label-strength assignment, and split policy enforcement.

## Summarize the structure of your data and what models/techniques work with it.

The primary unit is `(task_instance, candidate_location)`. Each task has many candidate source windows, optional CodeQL/checker facts, optional context, optional agent views, and separate labels. Suitable techniques include source-code encoders, fact/path encoders, cross-view attention, listwise/pairwise ranking, multi-task auxiliary heads, and calibration/abstention objectives.

## What is your overall goal with this project?

The overall goal is to build a credible checker-grounded candidate-ranking framework that helps vulnerability researchers inspect the right source locations first, while avoiding vague ML vulnerability-detection claims.

## Anything else you want to note about your project?

The proposal intentionally blocks overclaiming. A source-only LLM-assisted track is useful, but it is a weaker assistant or baseline. The core VulnSignal claim requires generated evidence, candidate ranking, checker/oracle validation, explicit `UNKNOWN`, and bounded human audit.
