# VulnSignal

[![Project](https://img.shields.io/badge/Project-VulnSignal%20-blue)](https://github.com/iptracej-education/VulnSignal/)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Scope](https://img.shields.io/badge/Scope-C%2FC%2B%2B%20Systems%20Code-purple)](#vulnerability-family-scope)
[![Truth](https://img.shields.io/badge/Truth-Tool%2FOracle%20Grounded-brightgreen)](#truth-boundary)
[![Scope](https://img.shields.io/badge/Scope-C%2FC%2B%2B%20Systems%20Code-purple)](#scope)
[![Truth](https://img.shields.io/badge/Truth-CodeQL%2FTool%20Grounded-brightgreen)](#core-workflow)

VulnSignal is a research project for building tool-grounded machine learning systems that support vulnerability investigation from real code evidence, not from CVE text or label shortcuts.

The core task is simple: given a CVE and a source-code location, decide whether that code location expresses the same vulnerability mechanism. The model may classify the location, rank it against other locations, or abstain when the evidence is not strong enough.

The current achievement is a 300-CVE dataset for learning that task with strict evidence rules. A candidate is a source-code context being checked against one CVE mechanism.

For each CVE, the dataset has one real candidate and 90 data-synthesized candidates split evenly across single-function/single-file, multi-function/single-file, and multi-function/multi-file code contexts. **Each candidate has vulnerable, fixed, and diff artifacts**, but only vulnerable and fixed artifacts receive labels and full representation families. Diff remains construction and audit evidence only.

For each CVE, we build a tool-grounded representation of the vulnerability as layered evidence:

```text
raw tool facts
    -> L0 normalized execution/path events
    -> L1 concrete CVE step chain for audit
    -> L2 transferable vulnerability mechanism
```

## What Are L0, L1, and L2 Representations?

- **L0** is the evidence layer. It records normalized facts extracted from code, such as object use, object release, object free, reachable cleanup paths, and whether a safety guard actually covers the path.
- **L1** is the audit layer. It links those facts back to the concrete CVE: the source files, functions, paths, and evidence IDs that explain why the vulnerable code satisfies the mechanism.
- **L2** is the learning layer. It removes CVE-specific names and expresses the reusable mechanism, such as refcount lifetime, async work lifetime, RCU lifetime, or missing guard composition.

We use all three because no single layer is enough. L0 is grounded but low level, L1 is reviewable but CVE-specific, and L2 is transferable but must remain traceable back to L0 and L1 evidence.

Together, these layers define the CVE composition rule: the code events and relations that must appear together for the vulnerability mechanism to be present. A candidate receives a label only after its own extracted evidence is compared with that rule:

```text
1 = candidate satisfies the accepted, tool-grounded vulnerable composition
0 = candidate fails the accepted composition
```

## Why Tool-Grounded?

Security datasets are easy to contaminate with shortcuts: patch proximity, file names, generated labels, synthetic markers, or answer-like tokens. VulnSignal treats those as failures.

Every admitted dataset row should link back to real or bounded source code and explicit evidence:

- source file/function/line references;
- candidate role and mechanism rationale;
- CodeQL result when CodeQL is claimed;
- Joern/semantic-navigation representation;
- compile/Kbuild result when source grounding requires it;

The model is not the source of truth. The model is a tool for prioritizing and explaining evidence.

Internally, VulnSignal uses a shared layered standard for this work. The current standard defines L0, L1, and L2 representations from source evidence, mechanism evidence, candidate contrast, CodeQL, Joern, metadata, leakage checks, split checks, and reporting checks required to call a dataset tool-grounded.

The same standard applies at candidate level: every candidate must report its complexity, source/workspace structure, and attempted tooling layers.


## Current Status

The first implementation focuses on C/C++ object lifecycle, concurrency, and memory-safety bugs, starting with Linux-style object lifetime and refcount patterns. Here is the current snapshot data: 

- CVEs analyzed: 300
- Aggregate real-holdout transfer accuracy: 0.905
- Shuffled-label p95: 0.543333
- Real-over-shuffled margin: 0.361667

- All code variance artifacts: 81,900 [1]
- Match/label dataset records: 54,600 [2]
- Full representation records: 382,200 [3]

[1] 300 CVEs x 91 candidates x 3 artifacts: vulnerable_code, fixed_code, diff_code. <br>
[2] 300 CVEs x 91 candidates x 2 representation-bearing artifacts: vulnerable_code and fixed_code. <br>
[3] 54,600 representation-bearing artifacts x 7 families: AST, CFG, DFG, DDG, CPG, callgraph, CodeQL_path. <br>

## Project Structure

| Project | Purpose | Primary Output |
| --- | --- | --- |
| Classification Dataset Engineering - Completed | Build validator-passed candidate composition packages for classification learning. | Validated composition packages or rejection reports. |
| Standard Classification Learning - Target Date: 7/31/2026 | Test whether validator-passed vulnerable/fixed candidate representations produce mechanism-separable labels without shortcut leakage. | Classification diagnostics and representation defect requests. |
| Deep Learning System - Target Date: 8/31/2026 | Build the final transformer-based VulnSignal model. Own architecture, training recipes, optimization, validation for release, inference packaging, and new-code inference readiness. | Trained transformer checkpoints, inference pipeline, release reports, and deployment-ready artifacts. |


## Documentation

Detailed documentation is being reorganized for release.
