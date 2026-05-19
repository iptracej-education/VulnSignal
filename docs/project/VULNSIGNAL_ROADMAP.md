# VulnSignal Roadmap

## Prior Work Boundary

Earlier experiments E006-E021 are historical research evidence from the source repository.

They remain in the repository as historical work that motivated the VulnSignal direction. They are useful for understanding weak preference ranking, LLM-assisted triage, MLM/trace-text feature limits, object-flow extraction limits, evidence packet design, and leakage-control discipline.

They are not the foundation for VulnSignal ground truth and should not be cited as vulnerability discovery without checker, oracle, or evidence-backed validation.

## VulnSignal Roadmap

### E022 - Tool-Grounded Vulnerability Task Dataset Builder

Goal: Build the first real task-instance dataset with source snapshots, candidate locations, CodeQL facts, and checker/dynamic oracle labels.

Expected outputs:

- `reports/e022_checker_grounded_dataset/task_instances.jsonl`
- `reports/e022_checker_grounded_dataset/candidate_locations.jsonl`
- `reports/e022_checker_grounded_dataset/labels.jsonl`
- `reports/e022_checker_grounded_dataset/dataset_card.md`

### E023 - CodeQL Lifecycle Fact Backbone

Goal: Create initial CodeQL queries and normalized fact schema.

Initial fact families:

- allocation/free/destroy calls
- reference acquire/release calls
- lock/unlock and concurrency events
- source/sink and dataflow paths
- alias and object-identity candidates
- async publish/cancel/lifetime events
- suspicious bounds/copy API contexts

### E024 - Executable Lifecycle Rule Checker

Goal: Run protocol rules over CodeQL/lifecycle facts and produce `PASS` / `FAIL` / `UNKNOWN`.

### E025 - Candidate Ranking Dataset

Goal: Generate candidate locations and labels for root-cause ranking.

### E026 - Non-Generative Candidate Ranker Prototype

Goal: Train/evaluate suspicious location + rule/hypothesis ranking, not vulnerable/non-vulnerable classification.

### E027 - CyberGym-Style Inference Evaluation

Goal: Evaluate on held-out CyberGym-style task instances without benchmark contamination.

Evaluation should report ranking and evidence quality, not generic vulnerable/non-vulnerable accuracy.

## Stop Conditions

Do not proceed to larger model work if candidate labels are not checker-backed, CodeQL facts cannot be extracted reliably, dynamic or conditional oracle evidence is missing, train/eval contamination cannot be ruled out, or the model only beats weak text baselines rather than meaningful semantic baselines.
