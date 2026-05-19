# VulnSignal CodeQL Fact Schema

## Purpose

CodeQL facts are the semantic backbone of VulnSignal.

They replace custom regex object-flow features as the trusted static-analysis layer.

## Fact record schema

```json
{
  "fact_id": "string",
  "task_id": "string",
  "query_name": "string",
  "fact_kind": "FREE_CALL|ALLOC_CALL|DATAFLOW_PATH|LOCK_EVENT|REF_EVENT|ASYNC_EVENT|ALIAS_CANDIDATE",
  "file": "string",
  "function": "string",
  "line_start": 1,
  "line_end": 1,
  "code": "string",
  "primary_expr": "string",
  "secondary_expr": "string_or_null",
  "source_node": "string_or_null",
  "sink_node": "string_or_null",
  "path": ["string"],
  "confidence": "HIGH|MEDIUM|LOW",
  "limitations": ["string"]
}
```

## Initial fact families

### Memory lifetime

- allocation calls
- free/destroy calls
- use-after-free candidate paths
- double-free candidate paths

### Reference counting

- acquire-ref calls
- release-ref calls
- refcount decrement-to-zero patterns

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

If CodeQL cannot establish a fact, record UNKNOWN or missing. Do not silently replace unknown with false.
