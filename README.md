# VulnSignal

[![Project](https://img.shields.io/badge/Project-VulnSignal%20-blue)](https://github.com/iptracej-education/VulnSignal/)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Scope](https://img.shields.io/badge/Scope-C%2FC%2B%2B%20Systems%20Code-purple)](#vulnerability-family-scope)
[![Truth](https://img.shields.io/badge/Truth-Tool%2FOracle%20Grounded-brightgreen)](#truth-boundary)


VulnSignal is a tool-grounded vulnerability candidate-ranking framework for C/C++ systems code. It ranks suspicious source-code locations using source context, CodeQL/checker facts, crash or patch evidence, and explicit uncertainty. It does not claim final vulnerability truth from model output alone.

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
  -> PASS / FAIL / UNKNOWN only when a checker or oracle supplies it
```

The primary dataset unit is:

```text
(task_instance, candidate_location)
```

A task is one vulnerability-research investigation over a source snapshot, such as a crash, advisory, patch, checker rule, or known benchmark case. A candidate location is an existing source file/function/line window that the pipeline proposes for ranking. Candidate locations are not generated code, not mutated code, and not confirmed bugs.

## What VulnSignal Is

VulnSignal is:

- a dataset and model pipeline for ranking vulnerability candidate locations
- grounded in CodeQL/checker facts, dynamic oracles, patch evidence, and source snapshots
- designed for human-auditable triage rather than manual validation of every candidate
- initially focused on C/C++ object lifecycle, concurrency, and memory-safety families
- explicit about `PASS`, `FAIL`, `UNKNOWN`, weak labels, provenance, and split policy

The primary model is a non-generative or minimally generative multi-view ranker. It may use source encoders, fact/path encoders, evidence encoders, cross-view attention or gated fusion, candidate-ranking heads, rule heads, affected-object heads, evidence-selection heads, and uncertainty calibration losses.

The current research direction is not novelty from "source plus graph plus attention" alone. VulnSignal uses tool-grounded evidence as the primary semantic anchor for candidate ranking. Optional vulnerability-concept descriptions, inspired by CLeVeR-style representation refinement, may be used as weak auxiliary contrastive views for low-sample or exploratory ranking.

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

## Dataset Direction

Each candidate can expose separate but linkable input views:

- source window sequence
- protocol/API lifecycle events
- AST/expression facts
- object identity facts
- operation-role facts
- CFG/order facts
- alias/dataflow facts
- callback/async facts
- vulnerability rule instances and validation rows
- optional vulnerability-concept or hypothesis views

The dataset aligns views by `task_id`, `candidate_id`, source location, producer tool, extraction rule, and missing-view mask. It does not require manually built fine-grained cross-view relationship edges at inference time. The model should learn soft relationships among views; tool-proven edges may be added later only as auxiliary validation evidence.

## Current Smoke Dataset

The active dataset phase is a 20-task object-lifetime/refcount smoke dataset under:

```text
reports/e022_object_lifetime_smoke/
```

Current generated state:

```text
20 task instances
51 patch-anchored candidates
100 weak hard-negative candidates
151 total candidate locations
151 source windows
6 positive codeql_conditional labels
12 scoped codeql_conditional_negative labels
0 dynamic oracle labels
```

Current tool-derived artifacts include:

```text
227 AST/expression facts
227 object identity facts
265 lifecycle/API operation-role facts
151 CFG/order rows
151 alias/dataflow rows
151 callback/async rows
21 vulnerability rule instances
21 vulnerability rule-validation rows
```

Coccinelle currently provides 29 lifecycle matches and 9 wrapper-candidate matches. Wrapper candidates are parser-backed hints only; they do not promote labels without a separate rule policy.

The current blocker is not whether candidates can be created. The blocker is stronger evidence extraction: object identity, alias/dataflow, callback graph/path facts, dynamic oracle support, and broader tool-backed rule coverage.

## Inference Modes

VulnSignal results must be reported by mode:

- `tool_grounded`: supported vulnerability families with source windows and tool-derived evidence views. This is the main VulnSignal claim.
- `compositional_few_or_zero_shot`: a new rule is described using known evidence types such as acquire, release, callback, lock, dereference, or bounds-check events. This is exploratory until validated.
- `description_only_zero_shot`: a human-authored or LLM-assisted vulnerability hypothesis is used when tool-grounded or public evidence is unavailable. This can guide checks, but it is not validation.

## Truth Boundary

Model ranking is not vulnerability truth. Label strength comes from the evidence layer:

- `dynamic`: reproduced pre-patch FAIL / post-patch PASS or equivalent executable oracle evidence
- `codeql_conditional`: recorded checker/rule result under explicit preconditions
- `codeql_conditional_negative`: scoped negative for one rule, not global safe-code truth
- `patch_confirmed_weak`: patch/advisory/source hunk evidence without checker/oracle proof
- `UNKNOWN`: missing, incomplete, conflicting, or out-of-scope evidence

Source-only and description-only outputs are useful for triage and hypothesis generation, but they must not be reported as the primary tool-grounded result.

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
