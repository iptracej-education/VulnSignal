# E022 Expansion Toward 20 Tasks

Status: candidate admission expansion, not full dataset materialization.

Date: 2026-05-19

## Result

The smoke set now has:

- 5 partially materialized task instances: `vs-smoke-T0001` through `vs-smoke-T0005`
- 15 additional admitted-for-extraction candidates: `vs-smoke-T0006` through `vs-smoke-T0020`
- 20 total task candidates with public NVD records and kernel patch anchors

The new 15 records are stored in `task_expansion_candidates.jsonl`.

All 15 primary patch URLs were validated with HTTP 200 responses on 2026-05-19. Results are recorded in `expansion_patch_url_validation.tsv`.

## Admission Rule Used

Each added task must have:

- an NVD CVE record
- Linux kernel scope
- object-lifetime, refcount, RCU, timer/work, or closely related use-after-free language
- at least one public `git.kernel.org` patch or commit URL

These records are admitted for patch-hunk extraction only. They do not yet have candidate locations, source windows, protocol/API sequences, structured facts, or labels beyond `patch_confirmed_weak`.

## Why This Matters

This answers the immediate scale question: reaching 20 object-lifetime/refcount-oriented Linux tasks is feasible as a mixed-strength pilot. It does not prove that all 20 can become strong labels. The next gate is whether the added 15 can be converted into source windows and tool facts without losing provenance.

## Required Next Step

For each of `vs-smoke-T0006` through `vs-smoke-T0020`:

1. fetch the primary patch
2. extract changed files and hunks
3. create candidate locations
4. fetch vulnerable/fixed source windows
5. attempt source-window CodeQL fixture extraction
6. defer full-source CodeQL labels until real kernel build metadata exists
