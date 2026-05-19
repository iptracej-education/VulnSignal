# VulnSignal Vision - Tool-Grounded Vulnerability Research Learning

## One-line vision

VulnSignal builds a tool-grounded dataset and model pipeline that learns to rank suspicious code locations and protocol/lifecycle hypotheses from real source code, semantic facts, and executable-oracle evidence.

## Why VulnSignal is needed

Most ML vulnerability-detection projects train on function-level C/C++ datasets with vulnerable/non-vulnerable labels. These datasets are useful for benchmarking representation learning, but they usually do not reproduce the real workflow of vulnerability researchers:

- locating relevant code inside a large project
- reasoning across call paths and object lifetimes
- forming a concrete vulnerability hypothesis
- producing or improving a test that triggers the bug
- validating the claim through a dynamic oracle or trusted static checker

Earlier object-lifetime experiments confirmed that weak labels and shallow representations are insufficient. Trace text and rule baselines remained competitive, while custom object-flow features failed to add independent signal.

## What VulnSignal copies from successful systems

Modern successful systems such as MDASH and CyberGym are not simple classifiers. They use task environments, semantic grounding, validation, proof, and feedback.

VulnSignal copies the architectural principle:

```text
Prepare -> Rank/Scan -> Hypothesize -> Validate -> Prove or UNKNOWN
```

VulnSignal deliberately does not copy the full multi-agent infrastructure. Instead, it compresses one valuable operation into a trainable model:

```text
source + facts + context -> suspicious location + protocol hypothesis + test guidance
```

## What VulnSignal contributes

VulnSignal is not a smaller MDASH. The intended contribution is a dataset and model target that sits between static analysis and agentic vulnerability discovery:

1. Checker-grounded task instances
2. CodeQL-backed semantic fact extraction
3. Candidate-location ranking data
4. Protocol/lifecycle hypothesis labels
5. Dynamic or conditional oracles
6. Deep-learning-ready multi-view representation

## Model objective

The model should not answer:

```text
Is this function vulnerable?
```

The model should answer:

```text
Which code locations are suspicious?
What object or protocol is implicated?
Which lifecycle/security rule may be violated?
What evidence supports the hypothesis?
What test/mutation direction should be tried?
What remains UNKNOWN?
```

## Truth standard

VulnSignal treats the model as a proposer, not a judge.

The final label is produced by executable proof oracle, CodeQL fact extraction plus rule checker, or explicitly marked UNKNOWN.

## Long-term goal

The ultimate goal remains finding new vulnerabilities in real projects, especially Linux kernel lifetime and concurrency bugs.

The current project does not need to directly discover a zero-day. It must build the correct dataset and pipeline so that future work can realistically move toward that outcome.
