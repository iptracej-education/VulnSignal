# VulnSignal CodeQL Validation Schema

## Purpose

CodeQL validation records are the primary static validation mechanism for VulnSignal evidence level.

They do not replace Joern/Coccinelle representation extraction. They record whether a CodeQL lifecycle/security-rule validator matched, did not match, or could not evaluate a candidate/rule pair.

## Validation record schema

```json
{
  "validation_id": "string",
  "task_id": "string",
  "candidate_id": "string",
  "rule_id": "string",
  "validator": "codeql",
  "query_path": "validators/codeql/lifecycle/VS-LIFE-REF-LIVE-001.ql",
  "validation_result": "rule_matched|rule_not_matched|rule_unknown",
  "label_strength_effect": "codeql_conditional|scoped_conditional_negative|unknown",
  "file": "string",
  "function": "string",
  "line_start": 1,
  "line_end": 1,
  "evidence_refs": ["string"],
  "blocker_reason": "string_or_null",
  "limitations": ["string"]
}
```

## Initial validation families

### Memory lifetime

- free/destroy rule evidence
- use-after-free lifecycle protocol evidence
- double-free protocol evidence

### Reference counting

- unchecked acquire vs live acquire
- release under required lock/protection
- refcount decrement-to-zero protocol evidence

### Shared publication

- insertion into shared containers
- removal from shared containers
- global/store publication
- file descriptor / handle table publication

### Async lifecycle

- queue work
- schedule work
- timer setup/mod
- callback binding
- cancel/flush/shutdown

### Protection context

- lock/unlock
- RCU read lock/unlock
- guard checks
- bounds checks
- null checks

### Dataflow

- local dataflow
- global dataflow where feasible
- taint paths
- source/sink paths

## Rule

For every applicable candidate/rule pair, attempt CodeQL validation first.

If CodeQL matches the rule evidence, record `rule_matched`.

If CodeQL runs and does not match the rule evidence, record `rule_not_matched`.

If CodeQL cannot run or cannot evaluate the candidate, record `rule_unknown` with a blocker reason. Do not silently replace unknown with false and do not treat blocked validation as optional.
