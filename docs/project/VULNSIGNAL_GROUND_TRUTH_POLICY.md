# VulnSignal Ground Truth Policy

## Core policy

VulnSignal does not treat model output as truth.

Truth must come from an oracle or checker.

## Truth levels

### Level 1 - Dynamic executable ground truth

Strongest.

Examples:

- ASan crash reproduced on pre-patch and not post-patch
- UBSan report reproduced
- fuzz input triggers target bug
- syzkaller reproducer triggers kernel bug
- KUnit/PoC triggers failure condition

### Level 2 - CodeQL-backed conditional truth

Strong, but conditional.

Example:

```text
Given CodeQL facts F and lifecycle rule R,
candidate C violates rule R.
```

Output:

- PASS
- FAIL
- UNKNOWN

### Level 3 - Patch-confirmed behavior

Useful but insufficient alone.

### Level 4 - LLM or human triage

Useful for prioritization, not ground truth.

## Rejected truth sources

The following cannot be final ground truth:

- LLM consensus alone
- regex match alone
- vulnerable/non-vulnerable label without provenance
- CVE label without source/fix/oracle evidence
- historical patch label without source anchoring

## UNKNOWN policy

UNKNOWN is a valid result.

A case should be UNKNOWN when CodeQL cannot resolve object identity, source is unavailable, dynamic reproducer is missing, rule does not apply, proof path is incomplete, or sanitizer result is non-deterministic.

UNKNOWN prevents false precision.

## Label provenance fields

Every label must carry:

```json
{
  "label_value": "PASS|FAIL|UNKNOWN|root_cause|non_root_cause",
  "label_strength": "dynamic|codeql_conditional|patch_confirmed|weak",
  "label_source": "string",
  "evidence_files": ["string"],
  "limitations": ["string"]
}
```
