# Lifecycle CodeQL Validators

Each query in this directory corresponds to a stable lifecycle rule ID in
`rules/lifecycle/`.

The query output is not a vulnerability verdict by itself. It is rule evidence
that the VulnSignal validation runner joins to candidate locations.

Output columns:

```text
source node
rule_id
family
expected_view
validation_evidence_kind
normalized_operation_role
callee
enclosing_function
source_file
start_line
end_line
arg0
arg1
arg2
source_expression
```

Candidate-level validation mapping:

```text
matching validator row inside candidate window -> rule_matched
validator ran with no matching row in window -> rule_not_matched
validator unavailable or incomplete -> rule_unknown
```

`expected_view` is usually `vulnerable` or `fixed`. Some rules only have a
fixed-view requirement because the vulnerable evidence is absence of the fixed
operation.
