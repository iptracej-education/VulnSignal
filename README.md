# VulnSignal

[![Project](https://img.shields.io/badge/Project-VulnSignal%20-blue)](https://github.com/iptracej-education/VulnSignal/)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Templates](https://img.shields.io/badge/Templates-Any%20Framework-purple)](#supported-templates)
[![Context](https://img.shields.io/badge/Context-8%20Lines-brightgreen)](#how-it-works)


VulnSignal is a checker-grounded vulnerability candidate-ranking framework for C/C++ systems code. It ranks suspicious source-code locations using source context, CodeQL/checker facts, crash or patch evidence, and explicit uncertainty. It does not claim final vulnerability truth from model output alone.

The initial vulnerability-family focus is object lifecycle, concurrency, and memory-safety bugs. The first pilot emphasizes Linux-style object lifetime and refcount patterns, including use-after-free, publish-after-free, missing acquire/release, cancel/flush-before-destroy, and related concurrency-sensitive lifecycle rules. The broader initial scope may add bounds checks, double-free, null/error-path cleanup, and parser/input-validation memory-safety families only after the evidence pipeline is validated.

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

## What VulnSignal Is Not

VulnSignal is not:

- a generic classifier that only outputs vulnerable / non-vulnerable
- a claim that source text or LLM agreement proves vulnerability truth
- a replacement for CodeQL, dynamic oracles, fuzzers, sanitizers, or human audit
- a project centered on patch differences as the main abstraction
- a promise that object-lifetime/refcount alone can supply hundreds of strong tasks

## Dataset Direction

The dataset is derived from original source artifacts, not invented labels. Accepted source families include:

- OSS-Fuzz or sanitizer/reproducer artifacts when source snapshots and crash evidence are available
- OSV, NVD, CVEfixes, MoreFixes, and similar advisory/patch datasets after source and license admission checks
- Magma-style benchmark tasks for controlled evaluation or training only when licensing and leakage rules allow it
- CodeQL/checker tasks created from selected source snapshots and explicit rule definitions

VulnSignal accepts imbalanced candidate-ranking data. It should not manufacture a globally balanced vulnerable/non-vulnerable dataset. Positive candidates are rare; most useful rows are negative or `UNKNOWN` candidates near plausible evidence.

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
- [Alignment Checklist](docs/project/VULNSIGNAL_ALIGNMENT_CHECKLIST.md)
- [Compact Visual Deck](docs/slides/vulnsignal_compact_visual_deck.html)
- [Detailed Dataset Deck](docs/slides/vulnsignal_dataset_development.html)

## Alignment Gate

Run this before committing future VulnSignal documentation changes:

```bash
python3 scripts/check_vulnsignal_alignment.py
```

The gate blocks vague ML vulnerability-detection framing, stale project naming, ambiguous small-model diagram language, and claims that model output alone establishes vulnerability truth.
