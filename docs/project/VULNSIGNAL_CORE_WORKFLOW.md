# VulnSignal Core Workflow

```text
input artifacts:
  source snapshot + generated evidence + candidate source locations

model outputs:
  ranked file/function/line windows
  likely rule, affected object, supporting evidence, and validation guidance

validation records:
  optional CodeQL/checker rule_matched, rule_not_matched, or rule_unknown
```

The model is a proposer, not a judge. Final vulnerability truth still requires checker/oracle evidence or explicit `UNKNOWN`.

The primary dataset unit is `(task_instance, candidate_location)`.
