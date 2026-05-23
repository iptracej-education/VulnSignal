# VulnSignal Dataset Strategy

## Primary dataset object

The dataset unit is:

```text
(task_instance, candidate_location)
```

not:

```text
function_text, vulnerable_label
```

## Why candidate ranking

Real vulnerability research asks where to look first, what object/rule is suspicious, and what test to mutate. Candidate ranking directly supports that workflow.

## Original input datasets

VulnSignal is not one downloaded vulnerable/non-vulnerable dataset. It is a derived dataset built from original source artifacts with explicit provenance.

| Source family | Original datasets/artifacts | VulnSignal use | Admission rule |
| --- | --- | --- | --- |
| Executable-oracle bugs | OSS-Fuzz/ClusterFuzz public disclosed crash and fix records; Magma-style benchmark tasks after license/provenance review | Primary train/evaluation seeds | Admit as strong only when source snapshot, reproducer or fuzz input, build/test command, and pre-patch FAIL / post-patch PASS evidence are available. |
| CodeQL/checker tasks | Selected source snapshots plus VulnSignal CodeQL/lifecycle/security rule suite | Primary validation/evidence-level labels | Admit as conditional when CodeQL database metadata, query/rule ID, source anchors, and `rule_matched` / `rule_not_matched` / `rule_unknown` result are present. A blocked CodeQL validation attempt must be stored as `rule_unknown` with blocker provenance. |
| Patch/advisory sources | CVEfixes, OSV, MoreFixes, GHSA/project security patches | Candidate expansion and weak provenance | Admit as weak or UNKNOWN unless upgraded by checker/oracle/before-after evidence. Patch hunk alone is never strong truth. |
| SARD-style synthetic/testcase data | SARD and datasets built from SARD, including CLeVeR-style data | Not planned for the current VulnSignal dataset | SARD is mostly function-level C/C++ examples, while VulnSignal is task/candidate based. Using it would require a separate conversion layer, likely double dataset effort, and risk training the wrong structure. Consider only as a later transfer-risk study after the Linux baseline is stable. |
| Held-out evaluation tasks | CyberGym-style task packets or separately packaged benchmark tasks | Evaluation only by default | Keep held out unless a separate uncontaminated training split is explicitly declared and reported. |

## Internet-verified source decision

The current source decision is conservative:

| Source | Current decision | Reason |
| --- | --- | --- |
| OSS-Fuzz / ClusterFuzz public issues | Use as primary executable-oracle seed when public and locally reproducible. | OSS-Fuzz is public, Apache-2.0 for integration code, publishes issues after fix or disclosure window, and ClusterFuzz reports include stack trace, testcase link, and regression range for reproducible crashes. |
| OSV.dev | Use as advisory/commit metadata and source-discovery index, not truth by itself. | OSV provides an API/downloadable database and precise commit/package mapping, but records aggregate multiple upstream databases; each row still needs source and evidence validation. |
| GitHub Advisory Database | Use as advisory metadata with attribution. | GitHub states the advisory database is available through APIs and licensed CC-BY-4.0. Advisory text is not a root-cause label by itself. |
| CVEfixes | Use as weak candidate-expansion source. | The dataset is public and versioned, but it is fix-commit mining from NVD/CVE records; patch labels are not strong root-cause truth without checker/oracle evidence. |
| MoreFixes | Use only as weak candidate-expansion source after storage/license review. | The Zenodo page exposes a large downloadable dataset and explicitly warns that mined repositories have different licenses and users are responsible for license handling. |
| Magma | Use as a pilot executable-oracle benchmark only after repository/license review. | Magma provides Docker-based ground-truth fuzzing infrastructure and stable releases, but it is a benchmark with forward-ported/instrumented bugs; do not generalize from it alone. |
| CyberGym | Hold out for evaluation/schema inspiration by default. | CyberGym is an agent evaluation benchmark with task packets and large data requirements; using it for training would contaminate reported held-out evaluation unless split governance is explicit. |

Blocked from primary training truth:

- advisory-only rows
- patch-hunk-only rows
- unlicensed or license-unclear source snapshots intended for redistribution
- private/non-public OSS-Fuzz issues
- CyberGym evaluation rows

## Vulnerability-family scope

The first VulnSignal implementation should start with Linux/object-lifetime and refcount-style rules because this repository already has domain vocabulary, scripts, and historical evidence there.

That is a first rule family, not the whole project. The schema must support broader C/C++ vulnerability-research families from the beginning:

- object lifetime, refcount, use-after-free, publish-after-free
- bounds and length checks
- null-dereference and error-path cleanup
- double-free or missing release/cancel/flush
- parser/input-validation rule failures

Do not mix families into one generic label. Each task carries `rule_family`, `rule_id`, and evidence references.

## Imbalance and negatives

VulnSignal should accept imbalanced data. It should not manufacture a globally balanced vulnerable/non-vulnerable dataset.

Required negative/counterexample sources:

- same-task candidates with dynamic-oracle non-root-cause status
- CodeQL/checker `rule_not_matched` candidates under the same rule
- same-file and same-function hard negatives near the crash frame or patch hunk
- callgraph/dataflow neighbors that share context but lack evidence
- explicit `UNKNOWN` rows when proof is incomplete

Training handles imbalance with pairwise/listwise ranking groups, hard-negative sampling, per-task weighting, and calibration reporting. Evaluation reports top-k localization, evidence-chain overlap, and UNKNOWN calibration, not binary accuracy on a balanced class table.

The main target is candidate-level relevance, not many vulnerability classes:

- positive or relevant candidate
- negative or non-root-cause candidate
- `UNKNOWN` when evidence is insufficient

Negative subtype metadata is required for sampling, weighting, evaluation, and audit. It must not be treated as separate vulnerability classes.

| Subtype | Meaning | Training use |
| --- | --- | --- |
| `easy_negative` | Wide or low-evidence contrast candidate | Low weight, small margin |
| `weak_nearby_hard_negative` | Near patch/crash/source evidence but not validated | Hard-negative sampling, not global safe-code truth |
| `same_api_hard_negative` | Near the same API/sink/tool fact family | Same-rule/API contrast |
| `checker_not_matched_hard_negative` | Rule-scoped CodeQL/checker `rule_not_matched` candidate | Higher weight, rule-scoped negative only |
| `fixed_version_analog` | Fixed-side analog or patched-away candidate context | Avoid leakage; useful for controlled contrast |
| `unknown_or_unproven` | Insufficient evidence | Train abstention/calibration, not negative classification |

Initial ranking batches should be task grouped. A practical starting group is one positive candidate, one easy/wide negative, two hard negatives, and two verified or conditional hard negatives when available. Negatives should rotate across same task, same rule family, same API/sink, same file/function, same subsystem, fixed-version analogs, and CodeQL/checker `rule_not_matched` candidates. Do not generate all possible positive-negative pairs; cap positive reuse per epoch.

## Initial scale feasibility

The 300-task / 20,000-candidate target is not credible if interpreted as 300 strong Linux object-lifetime/refcount vulnerability tasks from one source.

Internet sanity check as of 2026-05-16:

| Query/source | Public count observed | Interpretation |
| --- | ---: | --- |
| NVD exact phrase `use after free` | 2,781 CVE descriptions | Large global pool, but not all C/C++, not all reproducible, not all source-linked. |
| NVD exact phrase `use-after-free` | 3,826 CVE descriptions | Large global pool, useful for source discovery only. |
| NVD keyword `refcount` | 630 CVE descriptions | Closer to lifetime/refcount language, still not directly usable tasks. |
| NVD exact phrase `reference count` | 330 CVE descriptions | Potentially relevant, requires manual/source validation. |
| NVD exact phrase `double free` | 659 CVE descriptions | Related memory-lifetime family, not necessarily refcount. |
| NVD exact phrase `buffer overflow` | 18,706 CVE descriptions | Shows broader C/C++ memory-safety families have enough scale. |
| OSV Linux ecosystem | about 15k records on OSV page | Advisory metadata only; not root-cause labels. |
| OSV OSS-Fuzz ecosystem | about 3.8k records on OSV page | Stronger source-discovery pool, still requires public testcase/source validation. |
| CyberGym | 1,507 tasks across 188 projects | Holdout/evaluation by default, not training pool. |

Practical conclusion:

- **Object-lifetime/refcount pilot:** target 50-100 tasks and 5,000-10,000 candidate locations first.
- **1,600-candidate checkpoint:** use this as a minimum candidate-row sanity check before serious baseline training. It is not directly comparable to CLeVeR-style function/sample counts, and it is not a claim of 1,600 vulnerabilities.
- **300-task first multi-family training target:** achievable only if it includes multiple C/C++ memory-safety families and CodeQL/checker-generated conditional tasks across major applications/OS projects.
- **20,000 candidates:** achievable because each task yields many candidate locations, but this must not be described as 20,000 vulnerabilities.
- **Strong/oracle positives:** expect far fewer than task count; target 100+ strong/conditional positive candidates for a serious first multi-family dataset, not 300 confirmed bugs.

Therefore the first milestone should be:

```text
scale_checkpoint_1600_candidates:
  50-75 task_instances
  1,600+ candidate_locations
  task-grouped candidate rows
  label strength + missing-view masks on all model rows
  no global vulnerable/non-vulnerable function classifier claim

object_lifetime_pilot:
  50-100 task_instances
  5,000-10,000 candidate_locations
  one rule family
  schema + checker validation only

first_multi_family_dataset:
  300 task_instances
  20,000 candidate_locations
  object lifetime + bounds + double-free/null/error-path families
  CodeQL/checker conditional labels plus reproduced dynamic-oracle evidence
```

20-task expansion baseline:

```text
20 task_instances
692 candidate_locations
34.6 candidates per task
6 positive codeql_conditional labels
12 scoped codeql_conditional_negative labels
215 UNKNOWN expansion labels
0 dynamic oracle labels
```

Current 60-task materialization status:

```text
411 reusable NVD/kernel.org discovery-pool candidates
90 top automated discovery candidates selected for validation
29 automated discovery candidates patch-validated for materialization
11 earlier next-batch candidates patch-validated for materialization
40 new validated admission-backlog tasks materialized
60 materialized task_instances
269 patch-anchored candidate_locations
534 weak nearby hard-negative candidate_locations
803 candidate_locations with hard negatives
2,321 expanded candidate_locations
2,321 expanded source_windows
589 CodeQL/Coccinelle operation-role facts
1,362 CodeQL representation facts from 10 existing DB snapshots
421 AST/expression facts across 4 tasks
421 object-identity facts across 4 tasks, with 349 tool-expression identities and 72 unresolved identities
732 CodeQL guard/CFG-order rows
30 CodeQL callback/async API rows
0 CodeQL local-dataflow rows in the first representation pass
15 60-task rule-validation rows
2 codeql_conditional positive labels
4 scoped codeql_conditional_negative labels
100 Coccinelle lifecycle matches
68 Coccinelle wrapper-candidate matches
166 candidates with at least one non-source tool-grounded view
65 candidates blocked before materialization because current lifecycle signals were missing
```

This is still a smoke proof, not a training-scale dataset. The first expansion pass added historical CodeQL lifecycle-fact anchors, CodeQL-nearby weak contrast candidates, and patch-context candidates, increasing the 20-task set from 151 to 692 rows without promoting label truth. The 60-task expansion now passes the 1,600-row candidate-count checkpoint by adding patch-context rows, parser-backed Coccinelle lifecycle/wrapper candidates, and Kbuild-backed CodeQL validation candidates. Earlier CodeQL representation experiments showed that compile-backed DBs can emit AST/expression, object-identity, guard/CFG-order, and callback/async API views, but the forward dataset path should not depend on CodeQL for representation coverage. The immediate scale problem is evidence quality: Joern-first structural extraction, Coccinelle lifecycle/API coverage, mandatory CodeQL validation-attempt records for applicable candidate/rule pairs, callback-aware rules, and stronger tool-backed label coverage are still missing for most 60-task candidates.

## Preprocessing pipeline

Every original input record is normalized through the same derived files:

```text
original dataset record
  -> source_acquisition_manifest.jsonl
  -> task_instances.jsonl
  -> candidate_locations.jsonl
  -> joern_structural_facts.jsonl / lifecycle_api_events.jsonl
  -> codeql_validation_results.jsonl / oracle_runs.jsonl
  -> labels.jsonl
```

Required preprocessing outputs:

- `source_acquisition_manifest.jsonl`: original dataset name, original record ID, source URL/path, revision IDs, license/usage note, artifact hashes, and split eligibility.
- `task_instances.jsonl`: one vulnerability-research task with source snapshot, source family, build/test metadata, oracle/checker availability, and split policy.
- `candidate_locations.jsonl`: many file/function/line candidates per task, generated from crash frames, patch hunks, Joern callgraph/graph neighbors, same-file hard negatives, Coccinelle lifecycle/API evidence, or API/rule seeds.
- `joern_structural_facts.jsonl`: AST/CFG/DDG/callgraph/callback structural records keyed by fact ID and source anchor.
- `lifecycle_api_events.jsonl`: Coccinelle/Joern lifecycle and API event records keyed by candidate/source anchor.
- `codeql_validation_results.jsonl`: CodeQL validation-attempt records for applicable candidate/rule pairs, with `rule_matched`, `rule_not_matched`, or `rule_unknown` and blocker provenance.
- `oracle_runs.jsonl`: executable evidence rows such as pre-patch result, post-patch result, command, exit code, sanitizer/crash output, and reproducibility status.
- `labels.jsonl`: candidate-level label value, label strength, label source, evidence references, limitations, and explicit `UNKNOWN` when proof is incomplete.

The first model consumes derived records, not the raw original datasets directly. Source windows become bounded token sequences. Joern/Coccinelle output becomes typed representation records. CodeQL/checker output becomes validation/evidence-level records. Candidates are grouped by `task_id` for pairwise or listwise ranking.

Candidate locations are pointers to existing source regions. They are not mutated code variants, generated patches, or alternate programs. A candidate row says, in plain English: "for this task, inspect this file/function/line window." Mutation guidance may be a later model output, but mutation is not how candidate rows are created.

Candidate buckets are evidence-dependent, not mandatory. A dynamic-oracle task may provide crash-frame candidates and reproducer evidence. A patch/advisory task may provide patch-hunk candidates but no executable oracle. Joern/Coccinelle may provide graph-neighbor, lifecycle/API, callback, and same-function candidates. CodeQL/checker validation provides evidence-level flags for applicable candidate/rule pairs. Missing evidence should result in no bucket rows or explicit `UNKNOWN`, not fabricated candidates.

Typical candidate sources per task:

| Candidate bucket | Typical count | Required upstream evidence |
| --- | ---: | --- |
| Crash stack frame lines | 0-3 | Public crash trace or sanitizer stack |
| Patch hunk windows | 0-5 | Fix commit or patch hunk |
| Same-function nearby windows | 5-10 | Source snapshot and candidate anchor |
| Same-file related functions | 10-20 | Source snapshot and parser/index |
| Joern path/graph/call neighbors | 0-15 | Joern CPG/CFG/DDG/callgraph facts |
| Coccinelle lifecycle/API hits | 0-10 | Coccinelle semantic pattern output with source anchors |
| CodeQL validation hits | 0-10 | CodeQL database, validator query, and candidate-level validation result |
| Callgraph/dataflow neighbors | 10-15 | Joern/static analysis facts or source index |
| Hard negatives near evidence | 10+ | At least one positive/anchor location |

These counts are planning ranges, not guarantees. The first multi-family target assumes a mix of source families so that average candidate count can reach roughly 40-100 per task.

## Test-time input contract

For a new case after training, distinguish inference inputs from evaluation-only truth.

Required inference inputs:

- source snapshot for the target project/version
- task brief, rule family, crash/advisory text, or checker question when available
- generated candidate-location rows with source windows
- Joern/Coccinelle representation rows if the evaluated model was trained to use structural/event views
- CodeQL validation-attempt rows for applicable rules, with `rule_unknown` and blocker reason when CodeQL cannot run

Candidate-location rows should be created by the VulnSignal preprocessing/ranking pipeline before final ranking. Each row points to an existing file/function/line range, records why that range was included, and links to a bounded source snippet. Humans may audit generated candidates, but the project must not rely on humans to hand-create the review queue.

This is not a no-human end-to-end truth pipeline. Candidate proposal can be automated; source onboarding, license/provenance review, checker rule design, leakage checks, broken-build handling, and ambiguous evidence resolution still require engineering review. The model proposes and ranks candidates. Checker/oracle evidence determines label strength.

## Human review budget

Humans cannot validate 20,000+ candidate locations exhaustively, and the project should not be designed around that assumption.

Blocked workflow:

- manual labeling of every candidate location
- deep manual review of every task
- human opinion as final truth
- reviewer agreement as a substitute for checker/oracle evidence

Allowed scalable review:

- review source admission, provenance, and license decisions
- audit CodeQL/checker rule definitions and limitations
- inspect top-k evidence packets per task
- sample negatives, low-ranked rows, and `UNKNOWN` rows for quality and leakage
- escalate ambiguous or high-impact rows

Practical first multi-family human-review budget:

```text
per_task:
  top_ranked_packets: 3-5
  sampled_negative_or_unknown_packets: 1-2

first_multi_family_dataset:
  expected_review_packets: about 1,500-2,100
  exhaustive_candidate_rows: explicitly out of scope
```

Bulk label strength must come from reproduced dynamic oracles, CodeQL/checker validation results, and explicit `UNKNOWN`, not from manual row-by-row labeling.

Source windows are the actual code snippets around each candidate row. They are the source-text input to the model and must not include fixed-source text, patch labels, or hidden truth.

Joern/Coccinelle facts are structured representation rows such as AST nodes, call edges, CFG/DDG edges, lifecycle events, object identity hints, callback candidates, and path nodes. They are attached to candidate rows by fact IDs and source anchors.

CodeQL/checker rows are validation-attempt records. They are attached to candidate/rule pairs as `rule_matched`, `rule_not_matched`, or `rule_unknown`. If CodeQL cannot run, record `rule_unknown` with blocker provenance. Do not silently treat blocked validation as absent or optional.

AST, CFG, and DFG/DDG should be represented as separate candidate-linked views. They should not be collapsed into one generic graph record before training. A tool such as Joern can generate a combined CPG internally, but the dataset should expose separate AST/expression facts, CFG/order facts, DFG/DDG/dataflow facts, callback/async facts, and rule-evidence rows where possible. This gives the model distinct encoders for each representation and gives evaluation clear ablations for source-only, source+AST, source+CFG, source+DFG, source+tool-evidence, and fully fused modes.

Tool priority:

- Joern is primary for scalable AST/CFG/DDG/callgraph/callback representation extraction.
- Coccinelle is primary for Linux lifecycle/API semantic-pattern extraction.
- CodeQL is primary for evidence-level validation, not representation extraction. Attempt it first for applicable candidate/rule pairs.
- A blocked CodeQL run is a `rule_unknown` validation result with a blocker reason, not skipped validation.
- Joern output should not be treated as validation truth because it is a graph. It becomes stronger only when consumed by a rule policy or cross-checked by CodeQL/checker/oracle evidence.

Optional/source-only baseline:

- source snapshot plus learned or rule-guided candidate proposal only
- no Joern/Coccinelle representation view
- no CodeQL validation result
- no crash oracle
- no patch or fixed-source evidence

Evaluation-only fields hidden from the model:

- ground-truth labels and root-cause location
- patch diff and fixed source
- oracle result, post-patch behavior, and reproduced/fixed status
- label source or evidence fields that directly reveal the answer

If the main model uses Joern/Coccinelle representation features during training, held-out test tasks must provide the same feature view. CodeQL validation-attempt rows are required for applicable rules to determine evidence level; blocked validation becomes `rule_unknown`. A run without representation views is a `source_only` ablation, not the primary tool-grounded evaluation.

## Dataset Status Reporting Standard

Every dataset extraction/development status report should start with the same two sections so downstream architecture, model design, training, testing, and evaluation decisions are tied to the actual extraction state.

First, report the base dataset status:

| Data | Required status meaning |
| --- | --- |
| task instances | number of admitted task groups |
| patch/source acquisition | fetch failures and source-window availability |
| patch-anchored candidates | original patch/source anchors |
| weak hard negatives | nearby or same-task contrast rows that are not strong safe labels |
| expanded candidate locations | candidate rows available for task-grouped ranking |
| source windows | source-text rows available to the source encoder |
| labels | label count and label-strength distribution |
| candidate representation index | one scaffold row per `(task_instance, candidate_location)` |
| candidates with non-source tool views | rows that have at least one AST/event/object/path/rule view beyond source text |

Second, report the updated candidate-level input categories:

| Candidate input category | Downstream connection |
| --- | --- |
| source window sequence | source encoder, source-only baseline, candidate-span markers |
| lifecycle / API event facts | protocol/API event encoder and lifecycle sequence ablation |
| AST / expression facts | AST/expression encoder and source-token grounding checks |
| object identity facts | object encoder, affected-object head, object-aware rule validation |
| CFG / order facts | CFG/order encoder or path-feature ablation |
| DFG / DDG / dataflow facts | dataflow/path encoder and alias/object continuity validation |
| callback / async graph facts | callback/async encoder and RCU/workqueue/timer validation |
| rule evidence / validation | rule/evidence encoder, label promotion, verifier-guided post-training later |
| task context text | context encoder, task-grouped ranking, split/audit metadata |
| oracle / patch / optional agent-view evidence | hidden supervision, evaluation evidence, and future agent-view ablation |

Do not report candidate count alone as dataset progress. Each report must make clear which model views are present, which are masked as missing, and which missing views block training, testing, or evaluation claims.

## Inference pipeline requirement

At inference time, VulnSignal still requires an evidence-generation pipeline. It is not raw source-code-in, answer-out.

Runtime pipeline:

```text
new source snapshot
  -> candidate generator
  -> source window extractor
  -> tool fact builders, when using the tool-grounded model
  -> view normalizer and missing-view masker
  -> optional agent-view generator
  -> candidate ranker
  -> top-k review packet
```

The runtime pipeline should normalize each available view, not manually connect all views. The model input record should say that source window, AST/expression facts, lifecycle/API events, object identity facts, CFG/order facts, DFG/DDG/dataflow facts, alias facts, callback/async facts, and rule evidence belong to the same candidate. Fine-grained relationships among those views are learned by the model unless a tool explicitly emits a relationship for validation.

Inference-time outputs:

- ranked candidate source locations
- source windows
- attached CodeQL/checker validation-attempt records for applicable rules
- optional agent summaries/hypotheses
- predicted rule/object/evidence/uncertainty
- checker `PASS` / `FAIL` / `UNKNOWN` only if a checker is actually run

Inference-time non-inputs:

- ground-truth labels
- fixed source
- patch truth
- known root cause
- oracle result unless the runtime pipeline executes the oracle

Therefore, the project must build both:

- a dataset-construction pipeline for training/evaluation records
- an inference evidence pipeline for new source snapshots

## Source-only language-model-assisted track

A source-only model with language-model assistance is a useful track, but it makes a weaker claim than tool-grounded VulnSignal.

Allowed source-only track:

- input: source snapshot, task brief, generated source windows
- model: neural source encoder, language-model-assisted ranker, or retrieval-augmented source ranker
- output: ranked source locations, evidence summary draft, and uncertainty
- use: triage, reviewer productivity, baseline comparison, and early model experimentation

Blocked source-only claim:

- source text alone proves vulnerability truth
- language-model agreement is ground truth
- source-only ranking is equivalent to tool-grounded validation
- source-only result can replace dynamic oracle or checker evidence

The project can use deep learning for source-based candidate ranking. The grounding requirement is about evidence and label trust, not about avoiding learned models.

## Hypothesis and concept views

When no tool-grounded evidence or public evidence is available, the dataset may include human-authored or LLM-assisted vulnerability hypotheses as weak concept views. These views can help the model compare a candidate location against a proposed rule, failure mode, or security concern, and they can guide follow-up checker, fuzzing, or review work.

Allowed `vulnerability_concept_views.jsonl` sources:

- rule or family descriptions written before seeing held-out labels
- public advisory or benchmark descriptions allowed by split policy
- human-authored hypotheses based only on inference-available source and task context
- LLM-assisted hypotheses reviewed or accepted as hypothesis inputs, not evidence

Required metadata:

- `task_id`
- optional `candidate_id`
- `concept_source`: `rule_template`, `public_advisory`, `human_hypothesis`, `llm_assisted_hypothesis`, or `benchmark_description`
- `concept_text`
- `vulnerability_family`
- `available_at_inference`
- `evidence_strength`: `tool_grounded`, `public_context`, or `hypothesis_only`
- source inputs used to create the concept
- split and leakage policy

Blocked interpretation:

- a hypothesis description is not a label
- a hypothesis description is not checker/oracle evidence
- LLM agreement is not vulnerability truth
- `hypothesis_only` concept views cannot promote weak labels to conditional or strong labels

Hypothesis and concept views are useful for description-only exploratory ranking and for deciding which checks to build next. The main VulnSignal result remains tool-grounded when the claim requires validation.

## Multi-agent auxiliary-data harness

Multiple language-model agents may generate additional inference data from source code. This is allowed as an auxiliary pipeline, not as label creation.

Allowed `agent_views.jsonl` style outputs:

- candidate function summaries
- suspicious-code rationales
- likely rule-family hypotheses
- affected-object guesses
- call-chain notes and API-use summaries
- review questions
- proposed tests, fuzz targets, or mutation directions

Required metadata:

- `task_id`
- `candidate_id` when candidate-specific
- source inputs used
- prompt/template version
- model identifier
- generation timestamp
- whether the output is available at inference

Blocked interpretation:

- no CodeQL/fact-path grounding unless a checker pipeline creates it
- no checker-backed `PASS` / `FAIL` / `UNKNOWN` unless a checker is run separately
- no final vulnerability truth from source text or language-model agreement
- no replacement for oracle/checker validation

Agent-generated data may feed reranking, explanation, or reviewer triage. It must stay separate from `labels.jsonl`, `oracle_runs.jsonl`, and checker evidence.

## Task instance schema

```json
{
  "task_id": "string",
  "project": "string",
  "language": "c_or_cpp",
  "repo_url": "string",
  "vulnerable_commit": "string",
  "fixed_commit": "string_or_null",
  "split": "train|validation|test|heldout_cybergym",
  "split_policy": "project_disjoint|time_disjoint|vulnerability_family_disjoint|heldout_cybergym|other",
  "build_command": "string_or_null",
  "test_command": "string_or_null",
  "oracle": {
    "type": "asan|ubsan|syzkaller|codeql_rule|patch_confirmed",
    "pre_patch_result": "FAIL|PASS|UNKNOWN",
    "post_patch_result": "PASS|FAIL|UNKNOWN"
  },
  "available_inputs_at_inference": {
    "source_snapshot": true,
    "description": "optional",
    "crash_report": "optional",
    "sanitizer_stack": "optional",
    "codeql_facts": true
  },
  "training_only_fields": {
    "patch_diff": "optional",
    "fixed_source": "optional",
    "known_poc": "optional"
  }
}
```

## Candidate location schema

```json
{
  "candidate_id": "string",
  "task_id": "string",
  "file": "string",
  "function": "string",
  "line_start": 1,
  "line_end": 1,
  "source_slice": "string",
  "codeql_fact_ids": ["fact_1"],
  "candidate_origin": [
    "crash_stack",
    "codeql_path",
    "callgraph_neighbor",
    "api_pattern",
    "same_file_hard_negative"
  ],
  "label": {
    "location_relevance": 0,
    "is_root_cause": false,
    "protocol_rule": "UNKNOWN",
    "label_strength": "strong|conditional|weak",
    "label_source": "dynamic_oracle|codeql_rule|patch_hunk|manual_review|llm_triage",
    "split": "train|validation|test|heldout_cybergym",
    "split_policy": "inherited_from_task|project_disjoint|time_disjoint|vulnerability_family_disjoint|heldout_cybergym|other"
  }
}
```

## Strong label sources

Use executable-oracle and checker-backed data first:

- Magma-style instrumented executable bugs
- OSS-Fuzz/ClusterFuzz bugs with crash reports and fix verification
- syzbot/syzkaller bugs with reproducers
- CodeQL conditional rule checks

## Weak label sources

Use only for auxiliary training:

- CVEfixes
- OSV
- MoreFixes
- GitHub advisory metadata
- historical fix hunks without reproduction

## Evaluation splits

Required:

- explicit `split` and `split_policy` fields in task and candidate/label records
- project-disjoint split
- time-disjoint split
- CyberGym held-out split
- no exact task overlap
- no fixed-code leakage into inference inputs

## Contamination policy

CyberGym should primarily be an inference/evaluation benchmark.

Do not fine-tune on CyberGym and then report CyberGym performance unless the train/eval split is explicit, separated, and reported transparently.
