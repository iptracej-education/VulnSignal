# VulnSignal Foundational Architecture

## Core principle

```text
The model proposes.
CodeQL/checkers/oracles validate evidence level.
The dataset stores the full evidence chain.
```

## System diagram

```mermaid
flowchart TD
    A[Real Source Repository] --> B[Task Instance Builder]
    A --> C[Joern/Coccinelle Static Extractors]
    A --> D[CodeQL Validator Attempt]

    B --> E[Task Instance]
    C --> E
    D --> E

    E --> F[Candidate Generator]
    F --> F1[Crash Stack Neighborhood]
    F --> F2[Joern Graph/Call Neighbors]
    F --> F3[Call Graph Neighborhood]
    F --> F4[Dataflow Neighborhood]
    F --> F5[Historical Fix Retrieval]

    F1 --> G[Candidate Location Dataset]
    F2 --> G
    F3 --> G
    F4 --> G
    F5 --> G

    G --> H[Multi-View Neural Ranker]
    H --> H1[Location Ranking Head]
    H --> H2[Protocol Rule Head]
    H --> H3[Affected Object Head]
    H --> H4[Evidence Fact Head]
    H --> H5[Test or Mutation Guidance Head]
    H --> H6[UNKNOWN / Confidence Head]

    H1 --> I[Validation Layer]
    H2 --> I
    H3 --> I
    H4 --> I
    H5 --> I

    I --> I1[CodeQL Primary Validation]
    I --> I2[Lifecycle Protocol Checker]
    I --> I3[Dynamic Oracle: ASan/UBSan/Fuzzer/Syzkaller/KUnit]
    I --> I4[Human Audit Evidence for Hard Cases, Not Oracle]

    I1 --> J[Final Evidence Object]
    I2 --> J
    I3 --> J
    I4 --> J

    J --> K[Training and Evaluation Feedback]
```

## Component responsibilities

### 1. Task Instance Builder

Creates a real vulnerability-research task from a real project snapshot.

Fields include project, repository snapshot, vulnerable/pre-patch commit, fixed/post-patch commit when available, build/test metadata, crash report or sanitizer stack when available, source sections, and optional patch metadata for training only.

### 2. Representation Extraction Backbone

Extracts model-facing representations from real code without requiring full compilation by default. Joern provides AST, CFG, DDG/dataflow-like, callgraph, callback, and graph-neighborhood views. Coccinelle provides Linux lifecycle/API semantic-pattern evidence. CodeQL is not the default representation backbone.

### 3. Candidate Generator

Builds many candidate locations per task from sanitizer stack frames, functions near crash or patch, Joern callgraph/graph neighborhoods, Coccinelle lifecycle/API evidence, suspicious API usage, and historical similar fixes.

### 4. Multi-View Neural Ranker

Primary model, not an LLM-first design.

Inputs: source-code slice, Joern structural facts, Coccinelle lifecycle/API events, graph/fact paths, CodeQL validation-attempt records, optional error/sanitizer context, retrieved historical fixes, lifecycle/protocol rule candidates.

Outputs: suspiciousness score, predicted protocol rule, affected object, relevant evidence facts, mutation/test guidance, UNKNOWN/confidence.

### 5. Validation Layer

The model output is checked. CodeQL is the primary validation tool for candidate evidence level and emits `rule_matched`, `rule_not_matched`, or `rule_unknown`. A blocked CodeQL run is stored as `rule_unknown` with blocker provenance. Dynamic oracle results may still use pre-patch FAIL / post-patch PASS. UNKNOWN is first-class, not a failure.

Human audit may add review evidence for hard cases, but human or LLM review is not an oracle by itself. Final truth still requires a dynamic oracle, CodeQL/checker validation result, patch-confirmed before/after behavior tied to evidence, or explicit UNKNOWN.

### 6. Dataset Feedback

Stores every result as evidence: model proposal, Joern/Coccinelle representation facts, CodeQL validation result, checker result, dynamic oracle result, final label source, explanation, and limitations.

## Architecture boundary

VulnSignal does not require full autonomous agents.

VulnSignal trains one useful operation inside an agentic security pipeline:

```text
candidate ranking + protocol hypothesis + test guidance
```
