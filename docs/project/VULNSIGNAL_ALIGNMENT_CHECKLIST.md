# VulnSignal Alignment Checklist

Every future experiment must include an alignment section answering the required questions below.

## Required Experiment Alignment Section

- [ ] Does this use real source-code task instances?
- [ ] What is the trust layer?
- [ ] Is the label dynamic oracle, CodeQL conditional truth, patch-confirmed weak label, or LLM-only?
- [ ] Is CyberGym used for evaluation, not contaminated training?
- [ ] Is the model predicting one useful vulnerability-research operation?
- [ ] Does this avoid generic vulnerable/non-vulnerable classification?
- [ ] Does this avoid claiming vulnerability discovery without proof?

## Dataset Alignment

- [ ] Is the dataset unit `(task_instance, candidate_location)`?
- [ ] Does every label include provenance?
- [ ] Are strong, conditional, weak, and `UNKNOWN` labels separated?
- [ ] Are source snapshots and candidate locations preserved?
- [ ] Is train/eval split policy explicit?

## Truth Alignment

- [ ] Is final truth backed by dynamic oracle, CodeQL conditional rule check, patch-confirmed evidence, or explicit `UNKNOWN`?
- [ ] Is LLM consensus excluded as ground truth?
- [ ] Is regex/custom parser matching excluded as ground truth?
- [ ] Is historical patch labeling excluded as sole final truth?
- [ ] Is `UNKNOWN` allowed rather than forcing binary labels?

## Model Alignment

- [ ] Does the model rank suspicious file/function/line candidates or rule hypotheses?
- [ ] Does the model propose an affected object, likely violated rule, evidence chain, test/fuzz/mutation guidance, or confidence/`UNKNOWN`?
- [ ] Is the model not making final vulnerability truth claims?
- [ ] Are source-text-only and semantic baselines included when modeling begins?
- [ ] Is reward modeling avoided as the primary next step?

## Claim Alignment

- [ ] Does the report state that checker/oracle evidence validates candidates?
- [ ] Does the report avoid saying LLM consensus validates vulnerabilities?
- [ ] Does the report avoid saying CodeQL proves full safety?
- [ ] Does the report avoid saying the repository currently discovers vulnerabilities?
- [ ] Does the report state limitations and residual uncertainty?
