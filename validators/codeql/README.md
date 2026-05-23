# VulnSignal CodeQL Validators

This directory stores canonical CodeQL validators for VulnSignal rules.

CodeQL is the primary validation tool for candidate evidence level, not the
default representation extractor. Joern, Coccinelle, and parser-backed static
tools create the scalable candidate representations. For each applicable
candidate/rule pair, the pipeline must attempt CodeQL validation first. If
CodeQL cannot run because the source view is not buildable as a CodeQL database,
the result is `rule_unknown` with a blocker reason.

Allowed validation results:

- `rule_matched`: the validator observed the expected rule evidence inside the
  candidate window.
- `rule_not_matched`: the validator ran for the candidate view, but no matching
  rule evidence was observed inside the candidate window.
- `rule_unknown`: CodeQL could not validate the candidate, usually because the
  source view was not buildable, the database was unavailable, build/config
  prerequisites were missing, or required facts were incomplete.

The validator query emits source-anchored evidence. The VulnSignal validation
runner maps those rows to candidate windows and writes
`codeql_validation_results.jsonl`. A missing or blocked CodeQL run is still a
validation result: `rule_unknown`, not a skipped optional step.

Canonical layout:

```text
rules/lifecycle/*.json
  human-readable object-lifecycle protocol rule specs

validators/codeql/lifecycle/*.ql
  CodeQL implementations that emit evidence for those rule specs
```

Smoke and exploratory queries may remain under `reports/`, but they are not the
canonical validator store.
