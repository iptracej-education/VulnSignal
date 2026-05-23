# VulnSignal

[![Project](https://img.shields.io/badge/Project-VulnSignal%20-blue)](https://github.com/iptracej-education/VulnSignal/)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Scope](https://img.shields.io/badge/Scope-C%2FC%2B%2B%20Systems%20Code-purple)](#vulnerability-family-scope)
[![Truth](https://img.shields.io/badge/Truth-Tool%2FOracle%20Grounded-brightgreen)](#truth-boundary)


VulnSignal is a tool-grounded vulnerability candidate-ranking framework for C/C++ systems code. It ranks suspicious source-code locations using source context, Joern/Coccinelle/parser-backed representations, optional CodeQL/checker validation, crash or patch evidence, and explicit uncertainty. It does not claim final vulnerability truth from model output alone. At inference time, tool-grounded means evidence-grounded ranking; truth still comes from checker/oracle validation or explicit `UNKNOWN`.

The initial vulnerability-family focus is object lifecycle, concurrency, and memory-safety bugs. The first pilot emphasizes Linux-style object lifetime and refcount patterns, including use-after-free, publish-after-free, missing acquire/release, cancel/flush-before-destroy, and related concurrency-sensitive lifecycle rules. The broader initial scope may add bounds checks, double-free, null/error-path cleanup, and parser/input-validation memory-safety families only after the evidence pipeline is validated.

Tool-grounded means labels and evidence come from executable tools or evidence-producing artifacts: CodeQL, lifecycle/security-rule checkers, Coccinelle, Joern, SVF, sanitizer crashes, reproducers, fuzz tests, or patch-confirmed behavior. Human-authored or LLM-assisted hypotheses may be used as weak concept views when tool evidence is unavailable, but they are not labels and not proof.

## Core Claim

VulnSignal treats vulnerability research as an evidence-ranking problem:

```text
source snapshot + candidate generator + semantic facts + checker/oracle evidence
  -> candidate file/function/line windows
  -> suspiciousness ranking
  -> affected-object prediction
  -> likely violated rule prediction
  -> evidence-chain selection
  -> rule_matched / rule_not_matched / rule_unknown when CodeQL validates it
  -> dynamic FAIL / PASS only when an executable oracle supplies it
```

The primary dataset unit is:

```text
(task_instance, candidate_location)
```

A task is one vulnerability-research investigation over a source snapshot, such as a crash, advisory, patch, checker rule, or known benchmark case. A candidate location is an existing source file/function/line window that the pipeline proposes for ranking. Candidate locations are not generated code, not mutated code, and not confirmed bugs.

## What VulnSignal Is

VulnSignal is:

- a dataset and model pipeline for ranking vulnerability candidate locations
- grounded in static tool representations, optional CodeQL/checker validation, dynamic oracles, patch evidence, and source snapshots
- designed for human-auditable triage rather than manual validation of every candidate
- initially focused on C/C++ object lifecycle, concurrency, and memory-safety families
- explicit about CodeQL `rule_matched`, `rule_not_matched`, `rule_unknown`, dynamic oracle results, weak labels, provenance, and split policy

The primary model is a non-generative or minimally generative multi-view ranker. It may use source encoders, fact/path encoders, evidence encoders, cross-view attention or gated fusion, candidate-ranking heads, rule heads, affected-object heads, evidence-selection heads, and uncertainty calibration losses.

The current research direction is not novelty from "source plus graph plus attention" alone. VulnSignal uses tool-grounded evidence as the primary semantic anchor for candidate ranking. Optional vulnerability-concept descriptions, inspired by CLeVeR-style representation refinement, may be used as weak auxiliary contrastive views for low-sample or exploratory ranking.

The intended improvement over CLeVeR-style description-supervised representation learning is tool-evidence-grounded representation plus Linux task-grouped ranking, verifier-guided post-training, and UNKNOWN calibration. SARD-style data is not part of the current plan: it is mostly function-level C/C++ examples, while VulnSignal's unit is `(task_instance, candidate_location)` with source snapshots, candidate rows, and tool evidence. Using SARD would likely double dataset-engineering effort and risk training the wrong structure. The primary dataset foundation is Linux/CVE task instances.

The model design uses typed evidence queries:

- rule/checker result queries
- path/fact queries
- lifecycle/API event queries
- object-identity queries
- task-context queries
- optional vulnerability-description or hypothesis queries

Those queries attend over source, AST/expression, lifecycle/API, fact/path, graph, and context views. Missing-view masks and evidence-strength weights prevent weak or absent evidence from being treated as strong validation.

## What VulnSignal Is Not

VulnSignal is not:

- a generic classifier that only outputs vulnerable / non-vulnerable
- a claim that source text or LLM agreement proves vulnerability truth
- a claim that description-only zero-shot ranking is validated vulnerability detection
- a replacement for CodeQL, dynamic oracles, fuzzers, sanitizers, or human audit
- a project centered on patch differences as the main abstraction
- a promise that object-lifetime/refcount alone can supply hundreds of strong tasks

## Vulnerability-Family Scope

The dataset is derived from original source artifacts, not invented labels. Accepted source families include:

- OSS-Fuzz or sanitizer/reproducer artifacts when source snapshots and crash evidence are available
- OSV, NVD, CVEfixes, MoreFixes, and similar advisory/patch datasets after source and license admission checks
- Magma-style benchmark tasks for controlled evaluation or training only when licensing and leakage rules allow it
- CodeQL/checker tasks created from selected source snapshots and explicit rule definitions

VulnSignal accepts imbalanced candidate-ranking data. It should not manufacture a globally balanced vulnerable/non-vulnerable dataset. Positive candidates are rare; most useful rows are negative or `UNKNOWN` candidates near plausible evidence.

Negative subtype metadata is used for sampling, weighting, evaluation, and audit, not as vulnerability classes. Current subtype names include `easy_negative`, `weak_nearby_hard_negative`, `same_api_hard_negative`, `checker_pass_hard_negative`, `fixed_version_analog`, and `unknown_or_unproven`.

## Dataset Direction

Each candidate can expose separate but linkable input views:

- source window sequence
- protocol/API lifecycle events
- AST/expression facts
- object identity facts
- operation-role facts
- CFG/order facts
- DFG/DDG/dataflow and alias facts
- callback/async facts
- vulnerability rule instances and validation rows
- candidate representation index rows with missing-view masks
- optional vulnerability-concept or hypothesis views

These are separate dataset representations, not one combined representation. A tool such as Joern may produce a combined CPG internally, but VulnSignal should export separate source, AST, CFG, DFG/DDG, lifecycle-event, callback, and rule-evidence views when possible. The model fuses those separate view embeddings later with cross-attention or gated fusion.

The dataset aligns views by `task_id`, `candidate_id`, source location, producer tool, extraction rule, and missing-view mask. The concrete model-input scaffold is `candidate_representation_index_60.jsonl`: one row per `(task_instance, candidate_location)` that links the source window, labels, tool facts, graph/path rows, rule evidence, and missing-view mask. It does not require manually built fine-grained cross-view relationship edges at inference time. The model should learn soft relationships among views; tool-proven edges may be added later only as auxiliary validation evidence.

The default scalable extraction lane is Joern plus Coccinelle and parser-backed static tools. CodeQL is now a validator lane: lifecycle protocol queries live under `validators/codeql/` and attach `rule_matched`, `rule_not_matched`, or `rule_unknown` flags to candidates when a buildable CodeQL database exists.

## Current Smoke Dataset

The active dataset phase is a 60-task object-lifetime/refcount materialization under:

```text
reports/e022_object_lifetime_smoke/
```

The generated status snapshot is saved in `docs/project/VULNSIGNAL_CURRENT_DATASET_STATUS.md` by `reports/e022_object_lifetime_smoke/write_60_status_report.py`.

Current generated state:

```text
60 materialized task instances
269 patch-anchored candidate locations
534 weak nearby hard-negative candidates
803 candidate locations after 60-task hard-negative generation
2,321 expanded candidate locations
2,321 expanded source windows
2,321 expanded labels
100 Coccinelle lifecycle matches across 57 vulnerable/fixed source-window view runs
68 Coccinelle wrapper-candidate matches across 47 vulnerable/fixed source-window view runs
589 CodeQL/Coccinelle operation-role facts across 27 tasks
1,362 CodeQL representation facts from 10 existing DB snapshots
421 AST/expression facts across 4 tasks
421 object-identity facts across 4 tasks, with 349 tool-expression identities and 72 unresolved identities
732 CodeQL guard/CFG-order rows
30 CodeQL callback/async API rows
0 CodeQL local-dataflow rows in the first representation pass
15 60-task rule-validation rows
2,321 candidate representation index rows
166 candidate rows with at least one tool-grounded non-source view
2 codeql_conditional positive labels
4 scoped codeql_conditional_negative labels
269 positive_relevant rows
1,293 negative_candidate rows
759 unknown_abstention rows
0 dynamic oracle labels
```

Candidate-scale status:

```text
2,321 candidate locations today
145.1% of a 1,600-candidate minimum training-scale checkpoint
current average: 38.7 candidates per task across 60 tasks
0 more candidate rows needed for the row-count checkpoint
```

The next admission backlog is tool/provenance-gated, not label-gated. The pipeline now has:

```text
411 reusable NVD/kernel.org discovery-pool candidates
90 top NVD/kernel.org discovery candidates selected for validation
29/90 automated discovery candidates patch-validated for materialization
11/15 earlier manually seeded NVD/kernel.org candidates patch-validated
40 total new validated admission-backlog tasks now materialized
65 candidates blocked before materialization because the patch was reachable but current lifecycle signals were missing
```

These rows are not strong labels. They are source-backed tasks now materialized into source snapshots, patch hunks, candidate locations, source windows, and weak labels. Tool-fact extraction and recorded rule validation are still required before any label strengthening.

The assumed CLeVeR-like scale of roughly 1,600 vulnerable/non-vulnerable samples is useful as a minimum sanity checkpoint, not as a directly comparable target. VulnSignal's unit is a candidate row grouped under a task, not an independent function-level label. The 60-task smoke set now passes the 1,600 candidate-row checkpoint with explicit task grouping, label strength, evidence provenance, and missing-view masks.

This does not make the dataset trainable yet. Candidate count alone is not dataset quality. The 60-task set now proves source-backed task scale, candidate-density feasibility, partial tool-derived object-identity extraction, guard/CFG and callback/API extraction, and limited rule validation. It still needs broader Joern-first AST/CFG/DDG/callback extraction, stronger lifecycle/API evidence, CodeQL validation where buildable, and stronger tool-backed label coverage before any serious model-training claim.

Current 20-task multi-view artifacts include:

```text
227 AST/expression facts
227 object identity facts
267 lifecycle/API operation-role facts
692 CFG/order rows
692 alias/dataflow rows
692 callback/async rows
21 vulnerability rule instances
21 vulnerability rule-validation rows
```

Coccinelle currently provides 100 lifecycle matches and 68 wrapper-candidate matches over the 60-task patch windows. Combined with the fixed/vulnerable Kbuild-backed CodeQL probes, the 60-task multiview bridge now has 389 operation-role facts and 15 rule-validation rows. Wrapper candidates are parser-backed hints only; they do not promote labels without a separate rule policy. The lifecycle pattern now captures additional async/timer/RCU anchors such as `mod_timer`, `queue_work`, `schedule_work`, `INIT_WORK`, `kfree_rcu`, and `synchronize_rcu` as supporting evidence.

The current blocker is not whether candidates can be created. The blocker is stronger evidence extraction: object identity, alias/dataflow, callback graph/path facts, dynamic oracle support, and broader tool-backed rule coverage.

Immediate evidence-grounding work:

- make Joern the primary scalable AST/CFG/DDG/callback representation extractor
- keep Coccinelle as the Linux lifecycle/API semantic-pattern lane
- use CodeQL validators only for candidate-level lifecycle protocol validation when a buildable database exists
- add wrapper/API ontology mapping, callback handoff rules, generalized RCU deferred-release rules, and object-identity extraction
- keep dynamic-oracle and reproducer evidence as the strongest label lane, but do not block all static conditional labels on dynamic reproduction
- report candidate count, task count, label strength, and missing-view coverage together; candidate count alone is not dataset quality

## Inference Modes

VulnSignal results must be reported by mode:

- `tool_grounded`: supported vulnerability families with source windows and tool-derived evidence views. This is the main VulnSignal claim, but it is still evidence ranking until checker/oracle validation.
- `few_shot_description_assisted`: a new rule description plus a few positives and hard negatives are used for adaptation. This is exploratory until validated.
- `description_only_zero_shot`: a human-authored or LLM-assisted vulnerability hypothesis is used as a CLeVeR-like query when tool-grounded or public evidence is unavailable. This can guide checks, but it is not validation.

## Truth Boundary

Model ranking is not vulnerability truth. Label strength comes from the evidence layer:

- `dynamic`: reproduced pre-patch FAIL / post-patch PASS or equivalent executable oracle evidence
- `codeql_conditional`: recorded checker/rule result under explicit preconditions
- `codeql_conditional_negative`: scoped negative for one rule, not global safe-code truth
- `patch_confirmed_weak`: patch/advisory/source hunk evidence without checker/oracle proof
- `UNKNOWN`: missing, incomplete, conflicting, or out-of-scope evidence

Source-only and description-only outputs are useful for triage and hypothesis generation, but they must not be reported as the primary tool-grounded result.

## Training Direction

The first model should train as task-grouped candidate ranking with weighted pairwise margin loss. Negatives rotate within the same task, rule family, API/sink, file/function, subsystem, fixed-version analogs, and CodeQL `rule_not_matched` candidates. Verifier-guided post-training is a later stage: preferences such as CodeQL `rule_matched` over rule-scoped `rule_not_matched`, dynamic-oracle-linked candidate over same-file distractor, and strong evidence over weak evidence should improve ranking after the baseline works.

## Human Review Boundary

The system must not require humans to validate 20k candidate locations one by one. For a 300-task initial target, human review should focus on compact packets such as the top 3-5 ranked candidates per task plus a small sampled set of negative or `UNKNOWN` candidates. The pipeline should preserve enough provenance for audit, but automation must create and rank the candidate queue.

## Key Documents

- [Proposal](docs/PROPOSAL.md)
- [Document Index](DOCUMENT_INDEX.md)
- [Vision](docs/project/VULNSIGNAL_VISION.md)
- [Architecture](docs/project/VULNSIGNAL_ARCHITECTURE.md)
- [Dataset Strategy](docs/project/VULNSIGNAL_DATASET_STRATEGY.md)
- [Model Strategy](docs/project/VULNSIGNAL_MODEL_STRATEGY.md)
- [Ground Truth Policy](docs/project/VULNSIGNAL_GROUND_TRUTH_POLICY.md)
- [CodeQL Fact Schema](docs/project/VULNSIGNAL_CODEQL_FACT_SCHEMA.md)
- [Dataset Generation Knowledge](docs/project/VULNSIGNAL_DATA_GENERATION_KNOWLEDGE.md)
- [Tool-Derived Normalization Policy](docs/project/VULNSIGNAL_TOOL_DERIVED_NORMALIZATION_POLICY.md)
- [Alignment Checklist](docs/project/VULNSIGNAL_ALIGNMENT_CHECKLIST.md)
- [20-Task Smoke Dataset Card](reports/e022_object_lifetime_smoke/dataset_card.md)
- [Compact Visual Deck](docs/slides/vulnsignal_compact_visual_deck.html)
- [Detailed Dataset Deck](docs/slides/vulnsignal_dataset_development.html)

## Alignment Gate

Run this before committing future VulnSignal documentation changes:

```bash
python3 scripts/check_vulnsignal_alignment.py
python3 reports/e022_object_lifetime_smoke/run_evidence_automation_20.py
```

The alignment gate blocks vague ML vulnerability-detection framing, stale project naming, ambiguous small-model diagram language, and claims that model output alone establishes vulnerability truth. The smoke automation regenerates current evidence artifacts and should complete before dataset-pipeline commits.
