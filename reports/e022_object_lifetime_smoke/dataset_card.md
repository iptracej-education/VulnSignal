# E022 Object-Lifetime Smoke Dataset Card

Status: 20-task smoke dataset materialized; full-source tool grounding is partial and explicitly tracked.

Created: 2026-05-19

## Purpose

This directory starts Phase 1A by proving that public object-lifetime/refcount records can be normalized into VulnSignal dataset artifacts without overstating label strength.

The current smoke set contains:

- 5 original raw NVD/Linux CVE source records
- 20 task instances after expansion
- 15 additional admitted-for-extraction task candidates beyond the original seed
- 20/20 candidates materialized to patch metadata and affected C-file lists
- 20 source snapshot records using fixed commit and parent commit refs
- 51 patch-anchored candidate locations
- 51 patch hunk records
- 51 candidate rows with vulnerable/fixed source windows fetched from public commit refs
- 100 weak hard-negative candidate rows derived from nearby source windows
- 151 total candidate rows when hard negatives are included
- 10 candidate-level protocol/API sequence rows from a CodeQL source-window fixture probe
- 20 structured lifecycle-call fact rows from a CodeQL source-window fixture probe
- 3 candidate-relevant lifecycle-call fact rows from a real Kbuild-backed CodeQL extraction for `vs-smoke-T0005`
- 98 fixed-view full-source Kbuild-backed lifecycle-call facts across 11 task candidates
- 66 vulnerable-view full-source Kbuild-backed lifecycle-call facts across 10 task candidates
- 20 vulnerable/fixed comparison records
- 4 recorded conditional promotion rules
- 6 positive `codeql_conditional` labels from executable fact-delta rules
- 12 scoped `codeql_conditional_negative` labels
- Coccinelle semantic-pattern evidence for 19 vulnerable/fixed source-window view runs
- Joern CFG/DDG/CPG14 graph exports for the 6 promoted candidates
- multi-view normalized model-input artifacts for AST/expression, object identity, lifecycle/API events, CFG/order, alias/dataflow, callback/async, and rule-validation views
- automated failure analysis for all 51 patch candidates
- mixed-strength labels

## Current Counts

| Artifact | Count |
| --- | ---: |
| original raw candidate sources | 5 |
| task instances after expansion | 20 |
| expansion candidates admitted for extraction | 15 |
| total task candidates including expansion | 20 |
| task candidates with patch metadata resolved | 20 |
| changed C files identified across 20 candidates | 26 |
| patch-anchored candidate locations | 51 |
| weak hard-negative candidate locations | 100 |
| combined candidate locations | 151 |
| source snapshot records | 20 |
| patch hunks extracted | 51 |
| vulnerable/fixed source windows extracted | 51 patch-anchored, 151 including hard negatives |
| protocol/API sequences extracted by tools | 10 source-window fixture probe rows |
| structured fact/path rows extracted by tools | 20 source-window fixture probe rows |
| fixed-view full-source Kbuild-backed CodeQL fact rows | 98 combined batch rows plus 3 earlier focused IGMP rows |
| vulnerable-view full-source Kbuild-backed CodeQL fact rows | 66 batch rows |
| vulnerable/fixed tool-fact comparison rows | 20 |
| recorded conditional promotion rules | 4 |
| conditional rule run rows | 21 |
| evidence packets for promoted labels | 6 |
| Coccinelle source-window view runs | 102 |
| Coccinelle matched view runs | 19 |
| Coccinelle lifecycle matches | 29 |
| Joern promoted-candidate source-window files | 12 |
| AST/expression facts | 227 |
| object identity facts | 227 rows; 23 tool-rendered identities and 204 unresolved |
| lifecycle/API operation role facts | 256 |
| CFG/order view rows | 151 |
| alias/dataflow view rows | 151 |
| callback/async view rows | 151 |
| vulnerability rule instance rows | 21 |
| vulnerability rule validation rows | 21 |
| promotion failure-analysis rows | 51 |
| CodeQL tool runs recorded | 5 |
| dynamic labels | 0 |
| codeql_conditional labels | 6 |
| codeql_conditional_negative labels | 12 scoped negatives |
| patch_confirmed_weak labels | 45 patch-anchored candidates |
| weak labels | 88 hard-negative ranking-contrast candidates |
| UNKNOWN labels | 0 current materialized labels |

## Source Scope

The first five materialized seed records are Linux kernel object-lifetime/refcount cases discovered from NVD CVE records:

- `CVE-2021-46968`: zcrypt kref get/put mismatch
- `CVE-2021-47078`: RDMA/rxe refcount underflow and use-after-free
- `CVE-2023-52503`: amdtee session kref race
- `CVE-2021-46929`: SCTP endpoint RCU-delayed free
- `CVE-2023-6932`: IGMP timer/RCU object lifetime race

The expansion set adds 15 more Linux kernel CVE records with reachable `git.kernel.org` patch anchors. These have now been materialized into patch hunks, candidate locations, vulnerable/fixed source windows, and weak labels. They are still not final vulnerability truth.

## Patch-Hunk Evidence

Patch hunks have been extracted for all 20 smoke tasks. These hunks improve candidate locations from vague CVE text into concrete fixed-source anchors. Examples from the original five seed tasks:

- `CVE-2021-46968`: `zcrypt_card_unregister()` and `zcrypt_queue_unregister()` add missing put operations.
- `CVE-2021-47078`: `rxe_qp.c` failed-init cleanup clears queue and QP reference fields.
- `CVE-2023-52503`: `amdtee_close_session()` and `amdtee_open_session()` move ref release under `kref_put_mutex()`.
- `CVE-2021-46929`: SCTP endpoint free is deferred with `call_rcu()`, and endpoint holds use `refcount_inc_not_zero()`.
- `CVE-2023-6932`: `igmp_start_timer()` changes the timer/refcount protocol to use `refcount_inc_not_zero()`.

Patch hunks are still weak source evidence. They are useful for candidate generation and source-window bootstrapping, but they are not dynamic proof and not CodeQL/checker conditional truth.

## CodeQL Source-Window Probe

The first tool-backed probe has been run over a self-contained C fixture built from the 10 source-window snippets:

- fixture: `codeql_probe/src/lifecycle_probe.c`
- query: `codeql_probe/queries/ExtractLifecycleSmokeFacts.ql`
- tool: CodeQL 2.22.3
- extracted rows: 20 lifecycle-call facts

This is parser-backed CodeQL extraction, not grep. It proves that the smoke dataset can carry protocol/API sequence rows and structured fact rows derived from a real static-analysis tool.

It is still a fixture probe. It does not replace a full Linux source checkout, full build metadata, or production CodeQL databases. Therefore, no label is promoted to `codeql_conditional` from this probe alone.

## Full-Source Kbuild-Backed Probe

The header/build-metadata issue has been solved for one case, `vs-smoke-T0005` (`CVE-2023-6932`, `net/ipv4/igmp.c`):

- exact commit fetched: `e2b706c691905fe78468c361aaabc719d0a496f1`
- local ignored Linux checkout: `.tools/kernel-work/linux-torvalds`
- generated headers prepared with `make defconfig` and `make prepare scripts`
- target compiled with Kbuild: `make net/ipv4/igmp.o`
- CodeQL database created from the real Kbuild compile
- candidate-relevant rows recorded: 3

This proves the production extraction path: full-source CodeQL facts require a real source checkout and Kbuild-generated metadata. Individual fetched `.c` files are not enough.

Extracted facts alone do not promote labels to `codeql_conditional`; promotion requires a recorded checker rule over those facts. The first promotion pass added narrow fact-delta rules after vulnerable/fixed extraction was available.

The all-20 batch is summarized in `kbuild_codeql_summary.md`:

- 11/20 task candidates produced Kbuild-backed CodeQL lifecycle facts.
- 10/20 task candidates produced both vulnerable-view and fixed-view Kbuild-backed CodeQL lifecycle facts.
- 12/26 changed C files produced Kbuild-backed CodeQL lifecycle facts.
- 9/20 task candidates remain blocked by kernel build context, architecture, or old host-tool issues.
- 1/20 task candidates (`vs-smoke-T0020`) produced fixed-view facts but the vulnerable parent failed to compile.

This is not a source-file availability problem. It is a Kbuild profile problem: each hard candidate may require the correct `ARCH`, generated headers, and subsystem `CONFIG_` options before CodeQL can see the translation unit.

## Conditional Label Promotion

The first strong-label pass is recorded in:

- `rules/lifecycle/*.json`
- `codeql_conditional_rule_catalog.jsonl`
- `codeql_conditional_rule_runs_20.jsonl`
- `evidence_packets_20_codeql_conditional.jsonl`
- `labels_20_strengthened.jsonl`
- `strong_label_promotion_20_summary.json`

Promoted positive labels:

- `VS-LIFE-KREF-LOCK-001`: 3 candidates where vulnerable `kref_put` became fixed `kref_put_mutex`.
- `VS-LIFE-REF-LIVE-001`: 1 candidate where vulnerable `refcount_inc` became fixed `refcount_inc_not_zero`.
- `VS-LIFE-RCU-DEFER-001`: 1 candidate where immediate RCU-list release became fixed `call_rcu` deferred release.
- `VS-LIFE-REF-INSERT-001`: 1 candidate where fixed code inserted `refcount_inc_not_zero` and vulnerable code lacked that live acquire.

These labels are stronger than patch-only labels because each one has recorded tool facts, source-window evidence, rule preconditions, and a rule-run row. They are still not dynamic proof.

## Automated Secondary Evidence

The smoke set now has an automated evidence runner:

- `run_evidence_automation_20.py`

It executes capability checks, rule promotion, Coccinelle matching, failure analysis, and Joern graph export. The CodeQL v2 query runner is available for fresh view-specific databases:

- `run_codeql_v2_probe.py`
- `full_source_probe/queries/ExtractLifecycleSourceFactsV2.ql`

Current secondary-tool results:

- Coccinelle: 29 lifecycle matches across 19 source-window view runs.
- Joern: CFG/DDG/CPG14 exports completed for 12 source-window files covering the 6 promoted candidates.
- CodeQL v2: query compiles and a T0005 smoke run produced 63 v2 lifecycle rows, but existing DB paths may have been reused across views, so v2 rows are not used for label promotion until fresh view-specific DBs are generated.
- SVF: binaries are available, but SVF requires LLVM bitcode from buildable translation units.
- Dynamic oracle: syzkaller/QEMU are not available on the current PATH.

## Multi-View Model Input Bridge

The smoke set now generates normalized candidate-level model views:

- `ast_expression_facts.jsonl`
- `object_identity_facts.jsonl`
- `operation_role_facts.jsonl`
- `control_flow_order_facts.jsonl`
- `alias_dataflow_facts.jsonl`
- `callback_graph_facts.jsonl`
- `vulnerability_rule_instances.jsonl`
- `vulnerability_rule_validation.jsonl`
- `multiview_artifact_summary_20.json`

The bridge normalizes tool evidence into generalized fields such as `normalized_operation_role`, `api_family`, `operation_class`, `security_axis`, `lifecycle_stage`, `identity_status`, and `rule_family`. It does not generate default object-operation relationship edges. Views are aligned by task, candidate, source location, tool provenance, and missing-view masks so the model can learn cross-view relationships instead of relying on hand-built links.

## Label Policy

This proof dataset intentionally does **not** mark any row as `dynamic`. Rows marked `codeql_conditional` are strong only under the recorded rule preconditions.

Reasons:

- no local reproducer or pre-patch FAIL / post-patch PASS oracle has been executed
- 9 tasks still lack full-source tool facts under the current build profiles
- remaining patch-anchored candidates do not yet satisfy a recorded checker rule

The strongest current rows are `codeql_conditional`, based on executable fact-delta rules over CodeQL facts and materialized source windows. The remaining `patch_confirmed_weak` rows are based on NVD descriptions and public kernel patch references. These weak rows are useful for candidate generation and pipeline testing, but not final vulnerability-truth claims.

Hard negatives are either weak ranking-contrast candidates or scoped `codeql_conditional_negative` candidates. The scoped negatives are not proven non-vulnerable; they only failed the specific rule that promoted their positive anchor.

## Next Steps

1. Solve older-stable and architecture-specific Kbuild profiles for the 9 tasks without full-source extraction.
2. Decide whether `vs-smoke-T0020` should remain fixed-only/UNKNOWN or be replaced, because its vulnerable parent fails to compile under the current Kbuild profile.
3. Add more recorded checker rules for the remaining compared tasks and for wrapper-aware lifecycle APIs.
4. Decide and encode whether Coccinelle-window-only evidence can produce a separate conditional label strength, or only supporting evidence.
5. Add same-file, same-function, CodeQL-path, and callgraph/dataflow hard negatives beyond the current nearby-window negatives.
6. Deduplicate or group candidates that point to the same file/function/hunk after source extraction.

## Gate Status

This smoke set partially passes the 20-task smoke gate. It passes materialization and source-window generation, but it does not pass the stronger label gate.

Current gate progress:

- 20/20 task candidates have NVD records, reachable primary patch URLs, and changed C-file metadata.
- 20/20 admitted tasks have source snapshot records in metadata form.
- 20/20 admitted tasks have generated candidate-location rows.
- 20/20 admitted tasks have patch hunks resolved.
- 51 patch-anchored candidate rows have vulnerable/fixed source windows fetched from public commit refs.
- 100 weak hard-negative candidate rows have derived nearby source windows.
- 10/10 candidate rows have preliminary CodeQL source-window fixture protocol/API rows.
- 20 structured lifecycle-call fact rows have been extracted by the fixture probe.
- 11/20 task candidates have fixed-view Kbuild-backed full-source CodeQL/lifecycle facts.
- 10/20 task candidates have vulnerable-view Kbuild-backed full-source CodeQL/lifecycle facts.
- 10/20 task candidates have vulnerable/fixed lifecycle fact comparisons.
- 4/20 target tasks have at least one `codeql_conditional` label.
- 6 candidate rows have `codeql_conditional` positive labels.
- 12 candidate rows have scoped `codeql_conditional_negative` labels.
- 0/20 target tasks have `dynamic` labels.
- 45 patch-anchored candidates have automated failure reasons.
- 0 tasks rely only on vague text claims; every admitted task has at least a CVE description plus patch reference.
