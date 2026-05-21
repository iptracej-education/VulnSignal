# Lifecycle Rule Specs

These JSON files are executable rule specifications for VulnSignal label promotion.

A rule may promote a candidate only when the rule runner can match the required tool facts and source-window constraints. Patch text is allowed only as a candidate selector; it is not sufficient evidence by itself.

Key fields:

- `rule_id`: stable rule identifier.
- `family`: vulnerability-family or protocol-family bucket.
- `candidate_selectors`: patch/source-window tokens that decide whether the rule should be attempted for a candidate.
- `vulnerable_required`: required vulnerable-view CodeQL fact, or `null` when the rule is fixed-introduction based.
- `fixed_required`: required fixed-view CodeQL fact.
- `source_window_required`: source-window tokens required by the rule.
- `matching`: candidate-local matching policy.
- `negative_policy`: scoped negative-label policy for hard negatives.
- `label_strength`: label strength produced when the rule passes.

Rules must stay narrow. If a rule cannot state its required vulnerable facts, fixed facts, and matching policy, it should not promote labels.
