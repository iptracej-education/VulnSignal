# Proposal: VulnSignal - Tool-Grounded Candidate Ranking for Vulnerability Research

## Introduction

VulnSignal proposes a tool-grounded dataset and deep-learning pipeline for vulnerability research. The project does not train a generic vulnerable/non-vulnerable function classifier. Instead, it learns to rank suspicious source-code locations inside a real vulnerability-research task, predict likely protocol or security-rule candidates, select supporting evidence, and report uncertainty when proof is incomplete. Tool-grounded means labels and evidence come from CodeQL validation attempts, rule checkers, crashes, reproducers, fuzz tests, or patch-confirmed behavior. At inference time, the model produces evidence-grounded ranking; validation truth still requires validator/oracle evidence or an explicit `UNKNOWN`.

The initial vulnerability-family focus is C/C++ object lifecycle, concurrency, and memory-safety bugs. The first pilot emphasizes Linux-style object lifetime and refcount patterns, including use-after-free, publish-after-free, missing acquire/release, cancel/flush-before-destroy, and related concurrency-sensitive lifecycle rules. After the first pilot validates the dataset and evidence pipeline, the initial expansion may add bounds checks, double-free, null/error-path cleanup, and parser/input-validation memory-safety families.

The core workflow is:

```text
input artifacts:
  source snapshot + generated evidence + candidate source locations

model outputs:
  ranked file/function/line windows
  likely rule, affected object, supporting evidence, and validation guidance

validation outputs:
  CodeQL/checker rule_matched, rule_not_matched, or rule_unknown
  dynamic-oracle FAIL/PASS when executable evidence exists
```

The model is a proposer, not a judge. CodeQL/checker results, dynamic oracles, evidence-backed patch behavior, or explicit `UNKNOWN` determine label strength.

CodeQL is the primary validation tool for evidence level. For every candidate with an applicable lifecycle/security rule, the pipeline should attempt CodeQL validation first. If CodeQL runs, the candidate receives `rule_matched` or `rule_not_matched`. If CodeQL cannot run because of build metadata, Kconfig, architecture, generated-header, dependency, or toolchain problems, the candidate receives `rule_unknown` with a blocker reason. This is not an optional validation skip; it is an explicit evidence-level outcome.

## Problem Statement/Background/Motivation/Related Works

Most machine-learning vulnerability-detection projects train on function-level C/C++ datasets with vulnerable/non-vulnerable labels. These datasets are useful for representation-learning benchmarks, but they usually do not reproduce the workflow of vulnerability researchers:

1. locating relevant code inside a large project
2. reasoning across call paths, object lifetimes, dataflow, and protocol rules
3. forming a concrete vulnerability claim
4. identifying evidence that supports or weakens the claim
5. suggesting evidence-derived validation guidance
6. validating the claim through a dynamic oracle or trusted checker

Recent agentic vulnerability-research systems and benchmarks, such as MDASH-style workflows and CyberGym-style task environments, are not simple classifiers. They use task setup, source context, semantic grounding, validation, proof, and feedback. VulnSignal adopts that architectural lesson but narrows the scope to one trainable operation: candidate ranking.

Earlier object-lifetime work in the source repository showed a clear limitation: ranking code by rough labels, source-text patterns, lightweight object-flow signals, or agreement between language models does not prove that a bug exists. VulnSignal therefore requires each training example to point back to a real source version, a specific code location, machine-checkable facts when available, and validation evidence such as a checker result, crash, reproducer, fuzz test, or explicit `UNKNOWN` when the evidence is incomplete.

Recent source-code representation work also shows that this project should not claim novelty from "source plus graph plus attention" alone. Systems such as CLeVeR use vulnerability descriptions, code/graph representations, representation refinement, and zero-shot-style matching to improve vulnerability representation learning. VulnSignal uses that lesson, but the main research direction is different: tool-grounded evidence is the primary semantic anchor for candidate ranking. Vulnerability-concept descriptions may be added as an auxiliary contrastive view, inspired by CLeVeR, to improve low-sample and family-focused ranking. These descriptions may also include human-authored or LLM-assisted hypotheses when no tool-grounded or public evidence is available, but they remain weak guidance rather than ground truth.

The intended improvement over CLeVeR-style description-supervised representation learning is not description matching alone. VulnSignal combines tool-evidence-grounded representation, Linux task-grouped candidate ranking, verifier-guided post-training from checker/oracle outcomes, and explicit UNKNOWN calibration. SARD-style datasets are not part of the current plan because they are mostly collections of C/C++ functions, while VulnSignal is built around `(task_instance, candidate_location)` records with source snapshots, candidate rows, and tool evidence. Using SARD would likely double dataset-engineering effort and may train the wrong problem structure. The primary dataset foundation remains Linux/CVE task instances with patch/source anchors and tool-derived evidence.

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
What evidence supports the candidate explanation?
What validation evidence should be tried next?
What remains UNKNOWN?
```

Primary contributions:

1. A research direction that treats ML for vulnerability research as high-confidence candidate proposal, not generic function-level vulnerability classification.
2. A system design that uses source code and tool-generated facts for ranking, while keeping runtime evidence and patch evidence as label, validation, and evaluation artifacts.
3. A dataset design that preserves real project context, source versions, candidate locations, evidence provenance, and uncertainty.
4. A candidate-refinement design that uses typed tool-evidence queries, optional vulnerability-concept descriptions, missing-view masks, and evidence-strength weights to align source, AST, event, graph, and context views.
5. A training objective that combines task-local candidate ranking with auxiliary contrastive learning, evidence selection, rule/object prediction, validation-guidance prediction, and uncertainty calibration.
6. A model target focused on proposing where to inspect, what rule may be violated, what object may be affected, and what evidence should be checked next.
7. A validation policy that separates model suggestions from vulnerability truth, requiring checkers, crashes, reproducers, fuzz tests, patch-confirmed behavior, or explicit `UNKNOWN`.
8. A human-audit workflow that helps reviewers inspect a small ranked set of evidence-backed candidates instead of manually validating thousands of raw locations.

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
  -> protocol_api_sequences.jsonl / structured_facts_paths.jsonl
  -> oracle_runs.jsonl / oracle_candidate_links.jsonl
  -> validation_guidance_labels.jsonl / agent_views.jsonl
  -> labels.jsonl
```

### Inference evidence pipeline

This pipeline is used after training on a new source snapshot. It automatically proposes candidate locations, extracts the needed source context and static tool facts, ranks the candidates, and produces a small review packet for humans or downstream validation.

The default inference mode runs all supported vulnerability families within the configured VulnSignal scope and reports both per-family and merged rankings. Explicit family selection is still supported for cost control, tool availability, focused patch review, controlled evaluation, validation-budget management, and excluding immature families from reported results.

Each top-k review packet should include a ranking rationale. The rationale must link back to selected input evidence, such as source-window signals, protocol/API events, structured fact/path records, missing or weak evidence, and suggested validation actions. It is evidence-linked ranking support, not a free-form claim that the candidate is vulnerable.

```text
new source snapshot
  -> candidate generator
  -> source window extractor
  -> Joern/Coccinelle/parser-backed fact builders
  -> CodeQL/checker validation attempt for applicable rules
  -> optional agent-view generator
  -> candidate ranker
  -> top-k review packet
```

At inference time, labels, fixed source, patch truth, known root cause, and oracle results are hidden unless the runtime pipeline executes the checker or oracle.

We also keep a source-code-only mode. This mode can be integrated into LLM-agent workflows as a triage assistant that suggests suspicious locations, likely rules, and review questions. Downstream investigators may use VulnSignal's ranked candidates and evidence to construct hypotheses for further investigation, but hypothesis construction is outside the core ranker output. Source-code-only suggestions are not validation; CodeQL/checker validation or executable-oracle evidence is still required for stronger labels.

Inference must be reported by one of three official modes:

- `tool_grounded`: source snapshot, generated candidates, source windows, and generated tool facts. This is the strongest and primary VulnSignal claim, but the output remains evidence-grounded ranking until a checker/oracle validates it.
- `few_shot_description_assisted`: a new rule or family description plus a few positives and hard negatives are used for adaptation. This is useful for adding new vulnerability families, but still needs later tool/checker validation.
- `description_only_zero_shot`: a human-authored or LLM-assisted vulnerability description is used as a CLeVeR-like query for exploratory ranking. This is not validation and must not be reported as the primary VulnSignal result.

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
| CodeQL/checker tasks | Selected source snapshots plus VulnSignal CodeQL/lifecycle/security rules | Primary validation/evidence-level labels | Conditional when CodeQL database metadata, query/rule ID, source anchors, and `rule_matched` / `rule_not_matched` / `rule_unknown` result are present. If CodeQL cannot run, the row is still admitted only with explicit `rule_unknown` and blocker provenance. |
| Patch/advisory sources | OSV, GHSA, CVEfixes, MoreFixes, project security patches | Candidate expansion and weak provenance | Weak or UNKNOWN unless upgraded by checker/oracle/before-after evidence. Patch hunk alone is never strong truth. |
| Held-out tasks | CyberGym-style packets or separate benchmark tasks | Evaluation only by default | Keep held out unless an uncontaminated split is explicit. |

Initial scale targets:

```text
scale_checkpoint_1600_candidates:
  50-75 task_instances
  1,600+ candidate_locations
  task-grouped candidate rows
  label strength + missing-view masks on all model rows
  no global vulnerable/non-vulnerable function classifier claim

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

The roughly 1,600-sample scale used by related representation-learning systems such as CLeVeR is a useful minimum scale sanity check, but it is not directly comparable to VulnSignal. VulnSignal's unit is a candidate row grouped under a task, not an independent function-level vulnerable/non-vulnerable example. The current expanded smoke dataset has 2,321 candidate locations across 60 materialized tasks after adding weak hard negatives, patch-context rows, parser-backed Coccinelle lifecycle/wrapper candidates, and Kbuild-backed CodeQL fact candidates. This passes the 50-75 task and 1,600-row smoke checkpoints, and partial CodeQL/object-identity extraction plus limited rule validation now works, but it is still not a trainable baseline dataset until graph/path facts, broader CodeQL coverage, callback-aware rules, and stronger tool-backed labels are available.

These datasets will be naturally imbalanced and mixed-strength: most candidate locations are not the confirmed root cause, and many tasks will have conditional, weak, or `UNKNOWN` evidence rather than reproduced dynamic proof. This is not an exception to hide; it is the normal shape of real vulnerability-research data. VulnSignal therefore stores label value, label strength, evidence source, limitations, and UNKNOWN reason separately. Later training and evaluation sections mitigate this with task-level ranking losses, label-strength weighting, hard-negative sampling, explicit `UNKNOWN` calibration, and top-k review metrics instead of global balanced binary classification.

### Model Input Format

Each training example is a candidate-level multi-view record. The primary unit is `(task_instance, candidate_location)`. The model does not consume the whole project as one long sequence. Instead, each candidate can be represented by source window sequences, protocol/API sequences, AST/expression facts, CFG/order facts, DFG/DDG/dataflow facts, structured fact/path records, task context text, and optional agent-view JSONL data. Oracle, fuzz, reproducer, and patch evidence are stored as hidden supervision and evaluation evidence unless the same kind of evidence is generated at inference time.

Source windows are not read directly from raw repository files by the model. A preprocessing step extracts a bounded file/function/line region, tokenizes it, adds line-position features, and marks the candidate span. The model consumes this prepared token/line sequence. Protocol/API event sequences capture ordered lifecycle or security-relevant events around a candidate, such as acquire, release, refcount update, publish, cancel work, or destroy. AST/expression facts capture syntax-level call and expression structure. CFG/order facts capture branch/order structure around the candidate. DFG/DDG/dataflow facts capture def-use, value-flow, alias, and object-flow support when a tool can extract them. Structured fact/path records capture typed facts and relations, such as call edges, dataflow edges, object-flow links, path nodes, and rule hits. Task context is consumed as short text. Optional agent-view JSONL data may be consumed only when the same agent-view generator is available during inference and does not include hidden label truth. This allows the model to support source-code-only mode, tool-grounded mode, and multi-view mode without changing the dataset unit.

AST, CFG, and DFG are therefore not optional decoration. They are core structural views for multi-view learning. They are marked as missing when the representation lane is unavailable, and they become stronger model inputs only when produced by Joern, SVF, Clang/LLVM, or another parser-backed analysis tool. CodeQL output is reserved for validation/evidence-level records by default, not as the primary representation source. The current smoke implementation still contains earlier CodeQL-derived representation artifacts, but the forward path should not depend on CodeQL for representation coverage. It should not claim full AST+CFG+DFG coverage until these views are generated for the intended candidate set.

These views should stay separate in the dataset and be fused in the model. A Joern CPG may be the source artifact for multiple structural views, but VulnSignal should still emit separate AST, CFG, DFG/DDG, callback, event, and rule-evidence records when possible. This keeps ablations honest and lets the model learn which structural evidence actually improves candidate ranking.

The dataset should not force every fine-grained relationship into a hand-built graph before the model sees it. The required explicit alignment is candidate-level and provenance-level: task ID, candidate ID, source location, view, tool, extraction rule, and missing-view mask. Each view should still be normalized into generalized semantic fields, such as operation role, API family, operation class, security axis, lifecycle stage, identity status, and rule family, so the model does not only memorize project-specific names. Within that candidate record, cross-attention should learn soft relationships between source tokens, AST/call facts, lifecycle/API events, object-identity facts when available, CFG/order facts, DFG/DDG/dataflow facts, callback facts, and rule evidence. This is similar to parallel language data: sentence pairs are aligned at the example level, while token-to-token alignment is learned. Tool-proven object-operation edges, alias edges, callback edges, and rule validations are still valuable, but they are validation or high-precision auxiliary views, not mandatory hand-authored supervision for every example.

### Protocol/API Event Extraction Tooling

Protocol/API sequences are ordered, source-anchored events such as acquire, release, refcount increment/decrement, allocate, free, lock, unlock, publish, schedule work, cancel work, and destroy object. They are meant to expose what lifecycle or security-relevant operations occur around a candidate location. Structured fact/path records are a separate input view: they describe typed relationships such as call edges, dataflow edges, object-flow links, path nodes, and rule hits. Both views must be produced by approved parser-backed or checker-backed tools, not by grep-only API matching or a custom regex parser.

The first scalable implementation should use **Joern/code property graphs** as the primary representation extractor for AST, CFG, DDG/dataflow-like records, call neighborhoods, and graph/path views. This avoids making dataset construction and inference depend on Linux Kbuild, architecture configuration, generated headers, cross-compilers, and local compile environments. Joern output is representation evidence, not vulnerability truth.

For Linux-specific protocol checks, **Coccinelle** can be used as a supplemental tool because the Linux kernel already supports `coccicheck`, semantic patches, and report-mode output with file/line/column locations. Coccinelle results may generate candidate locations or supporting evidence, but they are not final truth without a recorded rule, source anchor, and validation policy.

**CodeQL custom C/C++ queries** are the primary validation tool for evidence level, not the default representation backbone. CodeQL validators implement lifecycle protocol rules and attach candidate-level `rule_matched`, `rule_not_matched`, or `rule_unknown` records. A blocked CodeQL run must be recorded as `rule_unknown` with blocker provenance rather than silently skipped. Canonical validator queries are stored in `validators/codeql/`; smoke queries under `reports/` are experimental. **SVF/LLVM** remains important for deeper pointer/value-flow and alias-sensitive extraction when buildable LLVM bitcode is available. **Tree-sitter** may help with lightweight source navigation, but it should not be treated as semantic evidence because it primarily provides concrete syntax trees. **Clang LibTooling/AST Matchers** remains a fallback for compiler AST-level extraction when a CodeQL query is not expressive enough.

Rejected extraction sources include grep-only matching, regex-only parser mimicry, unanchored LLM summaries, and manually invented protocol traces. If an event cannot be tied to a source file, function, line range, extraction tool, and extraction rule ID, it should not be used as tool-grounded data.

### Data Processing

Required derived files:

- `source_acquisition_manifest.jsonl`: original source name, original record ID, source URL/path, revision IDs, artifact hashes, license/usage note, and split eligibility.
- `task_instances.jsonl`: one investigation with source family, project, snapshot commit, build/test metadata, oracle/checker availability, and split policy.
- `candidate_locations.jsonl`: existing file/function/line windows generated before ranking.
- `source_windows.jsonl`: bounded source snippets and token windows for each candidate.
- `protocol_api_sequences.jsonl`: ordered lifecycle/API event sequences keyed by candidate, source anchor, extraction tool, and extraction rule ID.
- `structured_facts_paths.jsonl`: normalized fact/path records such as object-flow links, call edges, dataflow edges, path nodes, and rule hits keyed by fact ID and source anchor.
- `codeql_validation_results.jsonl`: candidate/rule validation-attempt records from CodeQL, including `rule_matched`, `rule_not_matched`, or `rule_unknown` plus blocker provenance when validation cannot run.
- `oracle_runs.jsonl`: executable evidence rows such as command, exit code, sanitizer/crash output, pre-patch result, post-patch result, and reproducibility status.
- `oracle_candidate_links.jsonl`: links between oracle artifacts and candidate locations, including link strength, link method, evidence references, and limitations.
- `validation_guidance_labels.jsonl`: optional hidden supervision for guidance quality, derived from historical crashes, reproducers, fuzz targets, checker runs, or patch-confirmed before/after behavior.
- `agent_views.jsonl`: optional LLM-agent summaries, affected-object guesses, review questions, and test ideas that are generated by the same pipeline used at inference.
- `labels.jsonl`: candidate-level label value, label strength, label source, evidence references, limitations, and explicit `UNKNOWN`.

Candidate rows and source windows should be generated by the pipeline, not hand-created by humans. Humans audit the generation quality, leakage risk, rule definitions, and ambiguous evidence.

Splits:

- project-disjoint where possible
- time-disjoint where possible
- source-family-disjoint or rule-family-disjoint for stress testing
- CyberGym-style held-out evaluation by default
- no fixed-source, patch-label, label-source, or oracle-result leakage into inference features

VulnSignal accepts imbalanced data. It should not manufacture a globally balanced vulnerable/non-vulnerable dataset. Negatives come from same-task hard negatives, rule-scoped `rule_not_matched` rows, non-root-cause candidates, callgraph/dataflow neighbors, and UNKNOWN rows.

The main target remains binary or ranking-based at the candidate level:

- positive or relevant candidate
- negative or non-root-cause candidate
- `UNKNOWN` when evidence is insufficient

Negative rows also carry subtype metadata for sampling, weighting, evaluation, and audit. These subtypes are not vulnerability classes:

- `easy_negative`
- `weak_nearby_hard_negative`
- `same_api_hard_negative`
- `checker_pass_hard_negative`
- `fixed_version_analog`
- `unknown_or_unproven`

### Oracle, Agent View, and Validation Guidance Policy

VulnSignal must keep three artifact roles separate:

- model-visible inputs: source windows, protocol/API sequences, AST/CFG/DFG/callback/path records, cleaned task context, and optional agent views generated by the same inference pipeline
- hidden supervision and evaluation evidence: root-cause labels, oracle outcomes, reproducer results, fuzz inputs, pre/post patch behavior, fixed source, and oracle-candidate links
- output artifacts: ranked review packets, selected evidence, uncertainty, and validation guidance for top candidates

Historical fuzz, crash, and reproducer artifacts are valuable, but they should usually train or evaluate the model instead of being shown to the model as ordinary input. If a public OSS-Fuzz, ClusterFuzz, Magma-style, or benchmark case includes a crashing input, stack trace, reproducer command, fuzz target, or fixed-version result, VulnSignal records it in `oracle_runs.jsonl` and links it to candidates through `oracle_candidate_links.jsonl`. Those links can supervise candidate ranking, evidence selection, and validation-guidance quality. They are hidden during normal inference because a new target project will not already have the answer.

Validation guidance is not generic fuzzing advice. It is a short, evidence-derived packet that explains what to try next for a ranked candidate and why. The first implementation should generate this guidance from rule-pack templates and selected evidence, with an optional learned head only when enough historical oracle links exist.

Each validation-guidance packet should include:

- `guidance_status`: `actionable`, `weak`, or `abstain`
- `evidence_basis`: selected source lines, protocol/API events, fact/path IDs, graph edges, or task-context fields that justify the guidance
- `missing_evidence`: facts or oracle results that would be needed before making a vulnerability claim
- `validation_goal`: the concrete condition to check, such as use-after-free reachability, missing refcount acquire, missing cancel/flush-before-destroy, double-free path, bounds failure, or null/error-path cleanup failure
- `entrypoint_or_target_hint`: candidate fuzz target, reproducer entrypoint, syscall/API path, parser input path, or checker query to try when this is known from the task context or extracted facts
- `state_sequence_to_exercise`: source-anchored lifecycle/API sequence that should be exercised, such as allocate -> publish -> release/free -> callback/use
- `instrumentation_hint`: sanitizer, checker, trace, or assertion direction, such as ASan/KASAN, KCSAN, UBSan, CodeQL query, Coccinelle rule, or project-specific test hook
- `fuzzer_target_export`: optional file/function/line or basic-block target set that an external fuzzer can use in its own fitness function
- `safety_and_scope`: sandbox/VM requirement, destructive side-effect warning when applicable, and a statement that the guidance is not proof of vulnerability
- `abstention_reason`: why guidance is not reliable when the packet is `weak` or `abstain`

VulnSignal should not fuzz every candidate. The ranker first reduces thousands of candidates to a top-k review set, then the guidance packet helps downstream checkers, fuzzers, or human reviewers choose focused validation actions. For fuzzing, the most defensible integration is target export: VulnSignal provides suspicious source locations and evidence context, and an external fuzzer uses those locations inside its own fitness function. For example, the fuzzer may prioritize inputs that increase normal coverage, reach a ranked function or basic block, reduce distance to a ranked candidate, or trigger a sanitizer/checker signal near the candidate. The fuzzer still owns testcase generation, mutation, coverage measurement, and crash detection. VulnSignal does not claim that its guidance proves a vulnerability or learns the fuzzer's mutation policy.

```text
external_fuzzer_fitness(input)
  = coverage_novelty
  + ranked_target_reach_bonus
  + distance_to_ranked_candidate_bonus
  + sanitizer_or_checker_signal_bonus
```

This fitness-function use is optional downstream validation support, not the core training objective. LLM agents may summarize evidence or draft a harness sketch, but LLM output cannot create labels, oracle truth, or vulnerability proof.

### DL Model/Architecture

The model does not generate a final vulnerability report. It reads each task's candidate code locations and model-visible evidence, then scores which locations should be inspected first. It can combine multiple inputs, such as source-code windows, protocol/API event sequences, AST/CFG/DFG/callback/path records, cleaned task context, and optional LLM-agent summaries. In architecture terms, this is a non-generative multi-view candidate ranker.

The model may use a neural source encoder, code language model, or language-model-assisted reranking. In this proposal, a neural source encoder means the learned part of the model that converts source code into numeric embeddings. Examples include a CodeBERT-style code language model, a transformer over code tokens and lines, a smaller token/line encoder, or a graph/code-structure encoder if AST, callgraph, or dataflow structure is added later. The boundary is not "no deep learning"; the boundary is that model output is not vulnerability truth.

Input views:

- source window sequence: tokenized bounded source region with candidate-span markers
- protocol/API sequences: ordered lifecycle/API events around the candidate
- AST/expression facts: syntax-level expression/call records derived from CodeQL, Joern, Clang, or equivalent parser-backed analysis
- CFG/order facts: control-flow and branch/order records around the candidate
- DFG/DDG/dataflow facts: def-use, value-flow, alias, and object-flow records when CodeQL, Joern, SVF, or LLVM can extract them
- structured fact/path records: call edges, dataflow edges, object-flow links, path nodes, and rule hits
- candidate-local structural neighborhoods: optional later derived views from AST/CFG/DFG/callgraph/object-flow facts, used for graph-encoder ablations only after the baseline works
- task context text: crash summary, advisory text, checker question, rule brief, or benchmark description
- vulnerability-concept descriptions: optional family/rule descriptions, human-authored hypotheses, or LLM-assisted hypotheses used as weak auxiliary concept views, not as validation truth
- optional agent-view JSONL data: LLM-agent summaries, affected-object guesses, review questions, and test ideas generated without hidden oracle or patch truth

Embedding design:

Each input source has its own encoder that turns that input into numeric embeddings. The model then combines those embeddings with cross-attention or gated fusion.

- source window encoder: code-token embeddings, line-position embeddings, candidate-span embeddings
- protocol/API sequence encoder: event-kind embeddings, API/function embeddings, object-role embeddings, event-order embeddings
- AST encoder: node-kind embeddings, expression-kind embeddings, argument-position embeddings, and source-anchor embeddings
- CFG encoder: basic-block or statement-node embeddings, branch-condition embeddings, edge-type embeddings, and local order-position embeddings
- DFG/DDG encoder: def-use/value-flow embeddings, alias-status embeddings, object-flow embeddings, and data-dependence edge embeddings
- structured fact/path encoder: fact-kind embeddings, predicate embeddings, object-ID embeddings, edge-type embeddings, path-position embeddings
- graph encoder: later-ablation encoder for node-type embeddings, edge-type embeddings, and neighborhood-position embeddings derived from AST/CFG/DFG/callgraph/object-flow facts; not required for the baseline model, and not part of the main dataset-readiness claim
- context encoder: text-token embeddings, source-family embeddings, rule-family embeddings, task-type embeddings
- vulnerability-concept encoder: text embeddings for rule/family descriptions, CVE/advisory descriptions, human-authored hypotheses, or LLM-assisted concept summaries when allowed by the split policy
- optional agent-view encoder: provenance embeddings and text-token embeddings for summaries, affected-object guesses, review questions, and test ideas

Fusion:

Cross-attention is used because each candidate has multiple input views that refer to the same code location from different perspectives. The model must learn how source tokens, protocol/API events, structured facts, graph neighborhoods, and task context align with each other. This helps the ranker distinguish normal API/event sequences from suspicious combinations of source code and tool-derived evidence.

- typed query bank, where rule results, path facts, lifecycle/API events, object-identity facts, and optional vulnerability descriptions form separate query groups
- typed query groups such as `Q_rule`, `Q_event`, `Q_object`, `Q_path`, `Q_context`, and `Q_description`
- tool-grounded queries are the primary semantic anchors; description queries are auxiliary and lower confidence
- cross-attention between input views, where source code, checker facts, task context, and optional agent summaries can attend to each other
- gated fusion, where the model learns how much weight to give each input view, especially when some evidence is missing or weaker
- evidence-strength weights so dynamic-oracle, checker-conditional, weak description, and UNKNOWN views do not carry the same supervision force
- missing-view masks so source-only ablations are allowed without pretending to be tool-grounded

Unlike description-only refinement, VulnSignal refines candidate representations with a typed query bank built from tool-grounded evidence, including rule results, path facts, lifecycle/API events, object-identity facts, and optional vulnerability or hypothesis descriptions. Cross-attention learns how these evidence queries align with source, AST, event, and graph views, while availability masks and evidence-strength weights prevent missing or weak views from being treated as strong validation.

Prediction heads:

The model uses a shared fused representation for each candidate, then applies separate prediction heads for different outputs. The heads are not independent models: the ranking head identifies which locations matter most, while the rule, object, evidence, guidance, and uncertainty heads add explanations and validation cues for those ranked locations.

- location ranking score
- rule family / protocol candidate
- affected object
- evidence fact selection
- ranking rationale over selected model-visible source, protocol/API, fact/path, graph, context, and agent-view inputs
- validation-guidance status and action category
- confidence / UNKNOWN

Loss function:

The model is trained with a weighted multi-task loss:

$$
L_{\text{total}}
= L_{\text{rank}}
+ \lambda_{\text{contrast}} L_{\text{contrast}}
+ \lambda_{\text{rule}} L_{\text{rule}}
+ \lambda_{\text{object}} L_{\text{object}}
+ \lambda_{\text{evidence}} L_{\text{evidence}}
+ \lambda_{\text{guidance}} L_{\text{guidance}}
+ \lambda_{\text{unknown}} L_{\text{unknown}}
$$

The $\lambda$ values are tunable scalar weights that control how much each auxiliary loss contributes relative to candidate ranking.

`L_rank` trains candidate ordering within the same task. `L_contrast` aligns candidate representations with matching tool evidence, rule concepts, vulnerable/fixed contrasts, and optional description views while pushing apart mismatched evidence. `L_rule` trains likely rule or protocol prediction. `L_object` trains affected-object prediction. `L_evidence` trains supporting-fact selection. `L_guidance` trains validation-guidance status or action-category prediction when historical oracle links provide supervision. `L_unknown` trains confidence calibration and abstention when evidence is incomplete.

Training should proceed in stages:

1. representation pretraining that aligns candidate code with rule, evidence, and optional description views
2. Linux task-grouped ranking where positives outrank relevant hard negatives inside the same task
3. verifier-guided post-training where checker/oracle outcomes create preference pairs
4. abstention calibration where incomplete evidence teaches confidence and `UNKNOWN`

### Training

During training, each batch contains one or more tasks and their candidate locations. The model computes all prediction heads, combines their losses into $L_{\text{total}}$, and backpropagates the combined loss through the shared encoders, fusion layers, and heads. The model is expected to learn under incomplete and uneven evidence, not under a perfect-label assumption.

The ranking component, $L_{\text{rank}}$, is computed within each `task_id`; candidates from unrelated tasks are not compared as one global binary class table. This helps with imbalance because the model compares candidates inside the same investigation task, while hard-negative sampling, label-strength weighting, and `UNKNOWN` calibration prevent the many negative or uncertain rows from dominating training. Strong dynamic labels can receive the highest supervision weight, CodeQL/checker-conditional labels can receive rule-scoped weight, weak patch/advisory rows can receive reduced weight, and UNKNOWN rows can train abstention instead of being forced into false negatives.

The first ranking baseline should use a weighted pairwise margin loss with rotating task-local negatives. A practical starting batch/group is one positive candidate, one easy or wide negative, two hard negatives, and two verified or conditional hard negatives when available. Negatives should be selected from the same task, same rule family, same API or sink, same file/function, same subsystem, fixed-version analogs, or CodeQL `rule_not_matched` candidates. Do not generate all possible positive-negative pairs; cap positive reuse per epoch to reduce memorization.

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
= w_n \max(0,\; m_n - s(c^+) + s(c^-))
$$

Here $w_n$ and $m_n$ depend on the negative subtype. Initial values can be:

| Negative subtype | Weight $w_n$ | Margin $m_n$ |
| --- | ---: | ---: |
| easy negative | 0.5 | 0.2 |
| hard negative | 1.0 | 0.5 |
| verified or conditional hard negative | 1.5 | 0.7 |

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
- evidence fact selection binary cross-entropy trains the evidence head to select supporting Joern/Coccinelle facts, CodeQL/checker validation records, path nodes, crash frames, or patch-linked facts from the candidate's evidence set.
- validation-guidance classification or multilabel binary cross-entropy trains the guidance head only when historical oracle links identify a useful validation target, entrypoint, sanitizer/checker direction, or abstention decision.
- UNKNOWN/confidence calibration or abstention-style objective trains the model to lower confidence when evidence is incomplete, conflicting, or outside the checker/oracle coverage.

Contrastive learning:

Contrastive learning is an auxiliary objective for multi-view alignment. Positive pairs can include a candidate source window with its matching tool-grounded evidence, rule instance, path evidence, vulnerable/fixed patch contrast, or allowed vulnerability-concept description. When no tool-grounded or public evidence exists, human-authored or LLM-assisted hypotheses may form weak concept pairs for exploratory training or ranking, but they must be marked as `hypothesis_only` and cannot promote label strength. Negative pairs can include unrelated rule evidence, evidence from another task, nearby hard negatives, fixed-version analogs, or description views from a different family.

One standard form is InfoNCE:

$$
L_{\text{contrast}}
=
-\log
\frac{
\exp(\mathrm{sim}(z_c, z_e^+) / \tau)
}{
\exp(\mathrm{sim}(z_c, z_e^+) / \tau)
+
\sum_{e^-}
\exp(\mathrm{sim}(z_c, z_e^-) / \tau)
}
$$

where $z_c$ is the candidate representation, $z_e^+$ is matching evidence or concept representation, $z_e^-$ is non-matching evidence, $\tau$ is the temperature, and $\mathrm{sim}$ is cosine similarity or a learned similarity score. This loss should not create labels by itself; it teaches representation alignment under the label-strength policy.

Verifier-guided post-training:

After the task-grouped ranking baseline works, VulnSignal should add preference training from checker/oracle outcomes. Examples:

- CodeQL/checker `rule_matched` candidate > rule-scoped `rule_not_matched` candidate
- dynamic-oracle-linked candidate > same-file distractor
- CodeQL-path-supported candidate > weak nearby hard negative
- root-cause candidate > patch-nearby UNKNOWN
- strong evidence > weak evidence
- UNKNOWN should abstain, not become negative

A standard preference loss can be:

$$
L_{\text{pref}}
= -\log \sigma\left(\beta\left(s(c_{\text{supported}}) - s(c_{\text{rejected}})\right)\right)
$$

where $\beta$ controls preference sharpness. This is a key differentiator from description-only representation learning, because the model is shaped by verifier outcomes instead of only semantic similarity.

Training implementation can use PyTorch. The first implementation should prioritize:

1. source-only baseline
2. source + fact/path ranker
3. source + fact/path + context ranker
4. source + tool-evidence query bank with contrastive alignment
5. optional vulnerability-concept description view
6. optional agent-view reranker

Hyperparameter tuning should be modest at first: candidate window size, maximum candidates per task, encoder size, fusion method, hard-negative sampling weight, loss weights, and top-k review budget. Optuna or a similar search tool should be used only after the baseline pipeline produces reliable validation results.

Overfitting controls are mandatory because positives are scarce. Split before pair generation by task, project, CVE, and clone family where possible. Deduplicate source windows and patch variants. Freeze most transformer layers initially and train adapters plus the ranking head first. Limit positive reuse per epoch, early-stop on project/CVE-disjoint validation, and evaluate hard-negative-only ranking. Pair expansion increases comparisons, not true positive diversity.

### Testing

Testing must distinguish inference inputs from evaluation-only truth.

Inference inputs:

- source snapshot for target project/version
- configured vulnerability-family set; by default, all supported families within the VulnSignal scope
- task brief, rule family, crash/advisory text, or checker question when available
- generated candidate-location rows with source windows
- Joern/Coccinelle representation rows if the evaluated model was trained to use structural/event views
- CodeQL/checker validation-attempt rows for applicable rules, with `rule_unknown` and blocker reason when validation cannot run
- optional agent views if the evaluated model was trained to use them

Hidden evaluation-only fields:

- ground-truth labels
- root-cause location
- patch diff and fixed source
- oracle result, fuzz/reproducer result, and post-patch behavior
- oracle-candidate links and validation-guidance labels
- label-source fields that reveal the answer

Source-only mode is allowed as a baseline or assistant track, but must be reported as `source_only`, not as the primary tool-grounded VulnSignal result.

## Evaluation

Primary metrics:

- top-k localization: whether the validated root-cause or CodeQL/checker `rule_matched` candidate appears in top 1, 3, 5, or 10
- MRR / mean reciprocal rank
- nDCG over label strength and candidate relevance
- hard-negative-only Recall@k and MRR
- false positives by negative subtype
- evidence fact precision/recall when fact-level evidence is available
- evidence-chain overlap
- rule-family and affected-object accuracy for validated labels
- validation-guidance quality when historical oracle links provide evaluation targets
- UNKNOWN calibration and abstention quality
- project/CVE-disjoint test performance
- reviewer-effort reduction: evidence packets inspected before finding validated candidates

Required baselines:

- random candidate ranking
- source-only neural or language-model-assisted ranker
- crash-stack proximity ranking
- patch-proximity ranking
- API-token/source-text ranker
- CodeQL path/checker-only ranking

Evaluation must report results by source family, rule family, project split, label strength, availability of Joern/Coccinelle representation views, and CodeQL/checker validation-attempt outcomes.

Mixed-strength data must be reported explicitly. Overall metrics are not enough: VulnSignal should show performance separately for `dynamic`, `codeql_conditional`, `patch_confirmed_weak`, `weak`, and `UNKNOWN` rows. Weak or UNKNOWN rows should not be used to claim final vulnerability-detection accuracy.

Required ablations:

- source only
- source + facts
- source + facts + descriptions
- without object identity
- without lifecycle/API events
- without CFG/DFG/path facts
- without verifier-guided post-training
- SARD transfer-risk study only if externally required and only after the Linux baseline is stable; it is not a default ablation

## Challenges/Ethical Considerations & Risks

Risks and mitigations:

- **Weak labels masquerading as truth:** patch/advisory-only rows remain weak or UNKNOWN unless upgraded by checker/oracle evidence.
- **Dataset leakage:** fixed source, patch labels, oracle results, fuzz/reproducer outcomes, oracle-candidate links, validation-guidance labels, and label-source metadata are excluded from inference features.
- **Generic fuzzing advice:** guidance must be derived from selected evidence and explicit missing evidence; otherwise the packet should abstain.
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
5. Dataset schema definitions for task instances, candidates, source windows, facts, oracle runs, oracle-candidate links, validation-guidance labels, labels, and agent views.
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
- Integrate Joern/Coccinelle representation generation.
- Integrate CodeQL/checker validation-attempt generation for applicable rules.
- Add optional agent-view generation.
- Emit top-k review packets with selected evidence, uncertainty, and validation guidance.

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

### Future Work - Exploit-primitive perspective annotation

After the core suspicious-location ranker is validated, VulnSignal may add an optional exploit-primitive perspective pass over top-ranked candidates. This pass would annotate candidates with possible impact-oriented perspectives, such as page-cache write/corruption, arbitrary write, controlled read/write, attacker-controlled use-after-free reuse, kernel memory disclosure, privilege-boundary crossing, or sandbox/container escape relevance.

This future pass is not exploit-chain construction and not proof of exploitability. It would be used only to prioritize validation by showing which ranked candidates may connect to higher-impact primitives. Checker/oracle evidence and human audit would still be required before making any vulnerability or exploitability claim.

## Resources

Primary project docs:

- `docs/project/VULNSIGNAL_VISION.md`
- `docs/project/VULNSIGNAL_DATASET_STRATEGY.md`
- `docs/project/VULNSIGNAL_MODEL_STRATEGY.md`
- `docs/project/VULNSIGNAL_CODEQL_VALIDATION_SCHEMA.md`
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
- Joern/Coccinelle for scalable representation extraction
- CodeQL for primary evidence-level validation and checker-backed conditional labels
- Git/source indexing tools for source-window and candidate generation
- Earlier object-lifetime scripts and reports for object-lifetime vocabulary and evidence-packet discipline

# NOTE

## What track are you choosing?

Engineering-oriented research prototype. The work builds a dataset pipeline, inference evidence pipeline, and deep-learning candidate-ranker, while preserving research controls around truth, leakage, and evaluation.

## What is your data source?

The data source is a derived VulnSignal dataset built from public original artifacts: OSS-Fuzz/ClusterFuzz public cases, Joern/Coccinelle-derived candidate representations, CodeQL/checker validation-attempt tasks, OSV/GHSA/CVEfixes/MoreFixes metadata for weak candidate expansion, and held-out CyberGym-style tasks for evaluation only by default.

## Summarize the status of your data and what cleaning is needed.

The repository has object-lifetime evidence and VulnSignal strategy docs, but not a finished VulnSignal dataset. Cleaning requires source admission records, deduplication, source snapshot anchoring, line/function normalization, fact normalization, leakage removal, label-strength assignment, and split policy enforcement.

## Summarize the structure of your data and what models/techniques work with it.

The primary unit is `(task_instance, candidate_location)`. Each task has many candidate source windows, Joern/Coccinelle representation views, CodeQL/checker validation-attempt records for applicable rules, optional context, optional agent views, and separate labels. Suitable techniques include source-code encoders, fact/path encoders, cross-view attention, listwise/pairwise ranking, multi-task auxiliary heads, and calibration/abstention objectives.

## What is your overall goal with this project?

The overall goal is to build a credible tool-grounded candidate-ranking framework that helps vulnerability researchers inspect the right source locations first, while avoiding vague ML vulnerability-detection claims.

## Anything else you want to note about your project?

The proposal intentionally blocks overclaiming. A source-only LLM-assisted track is useful, but it is a weaker assistant or baseline. The core VulnSignal claim requires generated evidence, candidate ranking, checker/oracle validation, explicit `UNKNOWN`, and bounded human audit.
