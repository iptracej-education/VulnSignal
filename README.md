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

Tool-grounding gives the model higher-confidence suspicious-code candidates while keeping the ranking auditable. Each candidate links back to a source version, concrete location, generated representation records, and available validator evidence. CodeQL evidence is expected to be sparse in C/C++ systems code due to compilation limitations across architectures, versions, drivers, I/O, and macro/header consistency.

The biggest advantage of CodeQL is to generalize CVE/CWE mechanism into checkable rules and pattern protocols. For each CVE/task, VulnSignal will define the vulnerability mechanism, evidence targets, relevant existing CodeQL/CWE query basis, generalized custom query, validation result, and evidence strength.

Tool-derived multiple representations strengthen inference by giving the model normalized evidence channels beyond raw source tokens. When source, lifecycle/API, AST/CFG/DFG, callback, object, and validation views agree, the ranker can assign higher confidence to suspicious candidates; when views are missing or conflicting, it should preserve uncertainty.

LLM-assisted workflow might help read code, draft hypotheses, summarize evidence, and re-rank candidates, but an LLM-only result is not reproducible validation. VulnSignal assumes LLM output is auxiliary unless it is tied back to source anchors and our static/dynamic analysis tool-grounded records.


## Model Inputs

Each dataset row is one candidate code snippet linked to one task. The model uses three input groups:

Primary dataset unit: `(task_instance, candidate_location)`.

| Input group | What it contains |
| --- | --- |
| Source code | Candidate file/function/line snippet with span markers |
| Tool-grounded linked tables | Task rows, candidate rows, CodeQL validation rows, labels, evidence strength, and `UNKNOWN` reasons |
| Representations | Generalized protocol/API events, AST facts, CFG/order facts, DFG/DDG/dataflow facts, graph/path facts, and optional agent-view text |

All inputs join by `task_id` and `candidate_id`. Missing rows are recorded explicitly; the pipeline does not fabricate evidence.

## Current Dataset Status

Current phase: `E100 representation-complete; strict-eval-stable; neural v0 frozen diagnostic baseline accepted`.

Active dataset development is now the selected 100-CVE evidence-grounded build. Detailed generated reports and datasets remain local until a dataset release.

| Data | Count | Status |
| --- | ---: | --- |
| CVE task instances | 100 | E100 representation-complete scope |
| raw candidate locations | 4,422 | task-grouped real-code candidate rows |
| normalized candidate rows | 3,904 | duplicate source windows collapsed |
| raw candidate density | 44.22 avg / 30 min | all tasks meet the raw 30-candidate floor |
| normalized density | 39.04 avg / 30 min | all tasks meet the normalized 30-candidate floor |
| source-window rows | 3,305 | all tasks meet the source-visible 30-candidate floor |
| API/protocol rows | 3,904 | model-ready generalized protocol representation |
| CodeQL validation rows | 503 | model-ready sparse validation view |
| Joern AST/CFG rows | 3,904 each | complete model-ready structural views |
| Joern DDG rows | 1,056 | model-ready dataflow-support view |
| strict ranking pairs | 1,676 | model-ready strong-evidence ranking supervision |
| audit auxiliary pairs | 2,451 | patch-weak context pairs for low-weight auxiliary training |
| strict-positive task split | 16 train / 10 validation / 15 test | deterministic stratified split, no label changes |

## Baseline Status

This table checks how well the linear and neural models rank candidate code locations for CVE review.

| Scope | Count |
| --- | ---: |
| total CVE tasks | 100 |
| total normalized candidates | 3,904 |
| task split | 70% train / 10% validation / 20% test |
| test CVEs not used for training | 20 |
| test CVEs with reviewed strong evidence | 15 |
| test CVEs pending strong-evidence review | 5 |

Full static views means API/protocol plus Joern AST/CFG/DDG/callback/lifecycle views. No Joern means Joern structural rows are intentionally hidden. Validation-assisted rows include CodeQL validation features and are offline diagnostics. Neural rows are three-seed means.

| Model | Mode | Strict-positive test tasks evaluated | MRR | Hit@1 | Hit@5 | Hit@10 | nDCG@10 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| linear | source-only | 15 | 0.3109 | 0.1333 | 0.5333 | 0.5333 | 0.2701 |
| linear | source + Joern AST/CFG | 15 | 0.5020 | 0.4000 | 0.7333 | 0.7333 | 0.4612 |
| linear | source + full static views | 15 | 0.6848 | 0.6000 | 0.7333 | 0.8000 | 0.6196 |
| linear | validation-assisted, no Joern | 15 | 0.9556 | 0.9333 | 1.0000 | 1.0000 | 0.9667 |
| linear | validation-assisted + full static views | 15 | 0.9556 | 0.9333 | 1.0000 | 1.0000 | 0.9613 |
| neural v0 | full gated | 15 | 0.9315 | 0.9111 | 0.9778 | 0.9778 | 0.9396 |
| neural v0 | full gated, no-shortcut | 15 | 0.8691 | 0.8222 | 0.9556 | 0.9778 | 0.8949 |

The linear rows are representation diagnostics; the neural rows are the frozen v0 diagnostic baseline. `full gated` uses all declared source, validation/protocol, lifecycle, static, and missing-view feature blocks with gated fusion. `full gated, no-shortcut` repeats the same model while masking patch/proximity/origin shortcut-style feature values.

Details: [baseline evaluation](docs/project/VULNSIGNAL_BASELINE_EVALUATION.md).

Next dataset work: start E300 admission-pool screening. 

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
- [Core workflow](docs/project/VULNSIGNAL_CORE_WORKFLOW.md)
- [Evidence policy](docs/project/VULNSIGNAL_EVIDENCE_POLICY.md)
- [Baseline evaluation](docs/project/VULNSIGNAL_BASELINE_EVALUATION.md)

## Alignment Gate

The internal alignment gate should block vague ML vulnerability-detection framing, stale project naming, ambiguous diagram language, and claims that model output alone establishes vulnerability truth. The gate script is not part of the current three-file public snapshot.
