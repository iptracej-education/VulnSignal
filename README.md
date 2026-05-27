# VulnSignal

[![Project](https://img.shields.io/badge/Project-VulnSignal%20-blue)](https://github.com/iptracej-education/VulnSignal/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Scope](https://img.shields.io/badge/Scope-C%2FC%2B%2B%20Systems%20Code-purple)](#scope)
[![Truth](https://img.shields.io/badge/Truth-Tool%20Grounded%20%2B%20UNKNOWN-brightgreen)](docs/project/VULNSIGNAL_CORE_WORKFLOW.md)

VulnSignal is a tool-grounded vulnerability candidate-ranking framework and a deep-learning pipeline for vulnerability research. It does not train a generic vulnerable/non-vulnerable function classifier; it ranks suspicious source-code locations inside a real investigation, predicts likely violated rules, selects supporting evidence, and reports uncertainty. It does not claim final vulnerability truth from model output alone.

## Scope

The first implementation focuses on C/C++ object lifecycle, concurrency, and memory-safety bugs, starting with Linux-style object lifetime and refcount patterns. The dataset foundation is public Linux/CVE task instances with source snapshots, patch or advisory anchors, generated candidate snippets, scalable tool-derived representations, and sparse CodeQL validation records when buildable validation is available.

## Why This Exists

Source-code machine learning has moved from token-only models toward multi-representation learning: tokens, ASTs, CFGs, DFGs, program graphs, code property graphs, code language models, and graph neural networks all expose different signals. VulnSignal uses that direction, but it does not claim novelty from "source plus graph plus attention" alone.

Real vulnerability research is not a balanced function-classification task. A reviewer starts with a project snapshot, patch/advisory/checker question, crash clue, or rule family, then needs to know which file/function/line candidates deserve attention first. VulnSignal treats this as task-local candidate ranking.

Tool-grounding gives the model higher-confidence suspicious-code candidates while keeping the ranking auditable. Each candidate links back to a source version, concrete location, generated representation records, and available validator evidence. CodeQL evidence is expected to be sparse in C/C++ systems code; when CodeQL runs, the validation record says `rule_matched`, `rule_not_matched`, or `rule_unknown` with a substatus.

LLM-assisted workflows can help read code, draft hypotheses, summarize evidence, and rerank candidates, but an LLM-only result is not reproducible validation. VulnSignal assumes LLM output is auxiliary unless it is tied back to source anchors and tool records.

Tool-derived multiple representations strengthen inference by giving the model normalized evidence channels beyond raw source tokens. When source, lifecycle/API, AST/CFG/DFG, callback, object, and validation views agree, the ranker can assign higher confidence to suspicious candidates; when views are missing or conflicting, it should preserve uncertainty.

Rule development is mechanism-first. For each CVE/task, VulnSignal must define the vulnerability mechanism, evidence targets, relevant existing CodeQL/CWE query basis, adapted or custom query, validation result, and evidence strength. Patch-derived draft classes describe rule origin only; they do not decide whether evidence is weak, medium, strong, or `UNKNOWN`.


## Model Inputs

Each model row is one candidate code snippet linked to one task. The model uses three input groups:

Primary dataset unit: `(task_instance, candidate_location)`.

| Input group | What it contains |
| --- | --- |
| Source code | Candidate file/function/line snippet with span markers |
| Tool-grounded linked tables | Task rows, candidate rows, CodeQL validation rows, labels, evidence strength, and `UNKNOWN` reasons |
| Representations | Protocol/API events, AST facts, CFG/order facts, DFG/DDG/dataflow facts, graph/path facts, and optional agent-view text |

All inputs join by `task_id` and `candidate_id`. Missing rows are recorded explicitly; the pipeline does not fabricate evidence.

## Current Dataset Status

Current phase: `real_dataset_30_cve`.

Active dataset development is now the 30-CVE evidence-grounded build. Detailed generated reports and datasets remain local until a dataset release.

| Data | Count | Status |
| --- | ---: | --- |
| CVE task instances | 30 | real dataset scope |
| raw candidate locations | 1,533 | task-grouped real-code candidate rows |
| normalized candidate rows | 1,267 | duplicate source windows collapsed |
| source-visible training rows | 939 | expanded same-protocol real-code pool |
| API/protocol representation rows | 1,009 raw / 747 normalized | generalized lifecycle/API roles and scope constraints |
| candidate density | 42.2 normalized average | 3 tasks still below 30 due to source-ref gaps |
| Joern AST/CFG candidates | 967 each | generalized structural views for canonical pre-expansion rows |
| Joern DDG-supported candidates | 295 | model-visible dataflow support mask |

## Stage 1 Baseline Check

| Mode | MRR | Hit@1 | Hit@5 | Hit@10 | nDCG@10 |
| --- | ---: | ---: | ---: | ---: | ---: |
| source-only | 0.5062 | 0.3333 | 0.6667 | 0.8333 | 0.5054 |
| source + AST/CFG | 0.7628 | 0.6667 | 0.8333 | 0.8333 | 0.6783 |
| source + full static views | 0.7917 | 0.6667 | 1.0000 | 1.0000 | 0.8021 |
| validation-assisted | 0.8750 | 0.8333 | 1.0000 | 1.0000 | 0.8369 |

Details: [Stage 1 baseline](docs/project/VULNSIGNAL_STAGE1_BASELINE_CHECK.md).

Stage 1 passes: full static views beat the source-only floor. 

Baseline results are reviewer-facing candidate-ordering metrics within each CVE task, not binary vulnerability accuracy. The harder expanded check is designed to test generalized lifecycle/API, AST/CFG/DDG, callback/object, and validation representations rather than source-text memorization.

Next dataset work: complete missing dataset checks, rebuild the model-ready files, and rerun the baseline.

## Tooling Policy

- Joern is the primary scalable representation extractor for AST/CFG/DDG/callgraph/callback-style views.
- Coccinelle provides Linux lifecycle/API semantic-pattern evidence.
- SVF/LLVM, Clang tooling, and Tree-sitter may add focused views when useful.
- CodeQL is a high-confidence validation lane for selected vulnerability rules, not the default representation extractor and not a required inference dependency.
- CodeQL validation may run during dataset construction, offline CI validation, or optional top-k validation after ranking.
- When CodeQL is attempted, each `(candidate_id, rule_id)` receives `rule_matched`, `rule_not_matched`, or `rule_unknown`.
- A CodeQL rule must point to a CVE mechanism profile and evidence target. Before custom QL is written, the pipeline searches existing CodeQL C/C++ queries, CWE coverage, CodeQL libraries, and local validators.
- Blocked CodeQL validation is recorded as `rule_unknown` with blocker provenance and substatus such as Kbuild target, Kconfig/symbol, header/dependency, toolchain, or unsupported-source failure.
- `rule_unknown` trains confidence/abstention and repair prioritization; it is not positive or negative evidence.
- Grep-only matching, invented protocol traces, and unanchored LLM summaries are not tool-grounded data.

Canonical CodeQL validators are internal working artifacts until they are promoted into the public repository snapshot.

## Key Documents

- [README.md](README.md)
- [PROPOSAL.md](PROPOSAL.md)
- [Document Index](DOCUMENT_INDEX.md)

## Alignment Gate

The internal alignment gate should block vague ML vulnerability-detection framing, stale project naming, ambiguous diagram language, and claims that model output alone establishes vulnerability truth. The gate script is not part of the current three-file public snapshot.
