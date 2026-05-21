# Kbuild-Backed CodeQL Summary for 20 Smoke Candidates

Status: 20 candidates materialized to patch metadata; fixed-view and vulnerable-view Kbuild-backed CodeQL partially successful.

Date: 2026-05-19

## What Is Complete

- 20/20 task candidates have reachable patch metadata.
- 20/20 task candidates have fixed commit, repository URL, vulnerable parent ref, and affected C-file list.
- 26 changed C files were identified across the 20 task candidates.
- 11/20 task candidates produced Kbuild-backed CodeQL lifecycle facts.
- 12/26 changed C files produced Kbuild-backed CodeQL lifecycle facts.
- 98 fixed-view lifecycle-call facts were extracted from successful Kbuild-backed CodeQL runs.
- 66 vulnerable-view lifecycle-call facts were extracted from successful Kbuild-backed CodeQL runs.
- 10 task candidates have both vulnerable-view and fixed-view lifecycle fact extraction.
- 1 task candidate has fixed-view facts but a vulnerable-parent build failure.

## Successful Kbuild-Backed CodeQL Extractions

| Task | File | Candidate-relevant facts |
| --- | --- | ---: |
| `vs-smoke-T0003` | `drivers/tee/amdtee/core.c` | 10 |
| `vs-smoke-T0005` | `net/ipv4/igmp.c` | 18 |
| `vs-smoke-T0007` | `drivers/media/dvb-core/dmxdev.c` | 2 |
| `vs-smoke-T0008` | `net/wireless/scan.c` | 12 |
| `vs-smoke-T0013` | `net/ipv4/tcp_minisocks.c` | 4 |
| `vs-smoke-T0014` | `fs/nfs/direct.c` | 1 |
| `vs-smoke-T0014` | `fs/nfs/write.c` | 2 |
| `vs-smoke-T0015` | `net/mac802154/llsec.c` | 3 |
| `vs-smoke-T0016` | `drivers/peci/cpu.c` | 4 |
| `vs-smoke-T0017` | `net/bluetooth/sco.c` | 5 |
| `vs-smoke-T0018` | `net/ipv4/tcp_ipv4.c` | 8 |
| `vs-smoke-T0020` | `drivers/misc/fastrpc.c` | 29 |

## Vulnerable-View Extraction Results

The vulnerable-parent run retried the 11 tasks that already had fixed-view facts.

| Status | Task count | Notes |
| --- | ---: | --- |
| vulnerable and fixed facts available | 10 | `vs-smoke-T0003`, `vs-smoke-T0005`, `vs-smoke-T0007`, `vs-smoke-T0008`, `vs-smoke-T0013`, `vs-smoke-T0014`, `vs-smoke-T0015`, `vs-smoke-T0016`, `vs-smoke-T0017`, `vs-smoke-T0018` |
| fixed facts available, vulnerable build failed | 1 | `vs-smoke-T0020`; vulnerable parent fails compiling `drivers/misc/fastrpc.c` because `fastrpc_map_get(map)` returns void in that parent context |
| no full-source comparison available | 9 | Same older-stable, architecture, or host-tool blockers listed below |

The comparison artifact is `codeql_vulnerable_fixed_comparison_20.jsonl`. It compares lifecycle-call fact keys across vulnerable and fixed views, but it is not a vulnerability oracle and does not promote labels to `codeql_conditional`.

## Blocked Or Failed Kbuild-Backed CodeQL Extractions

| Task | Failure class | Notes |
| --- | --- | --- |
| `vs-smoke-T0001` | prepare failed | Older stable commit fails building `tools/objtool` during extraction preparation. Affected files are `drivers/s390/crypto/zcrypt_card.c` and `drivers/s390/crypto/zcrypt_queue.c`; likely also needs `ARCH=s390` handling. |
| `vs-smoke-T0002` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `drivers/infiniband/sw/rxe/rxe_qp.c`. |
| `vs-smoke-T0004` | prepare failed | Older stable commit fails building `tools/objtool`; affected files are SCTP files under `net/sctp/`. |
| `vs-smoke-T0006` | prepare failed | Older Torvalds commit fails building `tools/objtool`; affected files are CIPSO/CALIPSO paths. |
| `vs-smoke-T0009` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `drivers/usb/gadget/function/f_fs.c`. |
| `vs-smoke-T0010` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `drivers/spi/spi.c`. |
| `vs-smoke-T0011` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `net/nfc/llcp_sock.c`. |
| `vs-smoke-T0012` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `init/main.c`. |
| `vs-smoke-T0019` | prepare failed | Older stable commit fails building `tools/objtool`; affected file is `net/can/j1939/main.c`. |

## Profile Improvements

The first default pass produced facts for 7 tasks. Adding explicit subsystem `CONFIG_` profiles converted four more tasks:

| Task | Added profile symbols | Result |
| --- | --- | --- |
| `vs-smoke-T0003` | `CONFIG_TEE`, `CONFIG_AMDTEE`, `CONFIG_CRYPTO_DEV_CCP_DD`, `CONFIG_CRYPTO_DEV_SP_PSP` | success |
| `vs-smoke-T0015` | `CONFIG_IEEE802154`, `CONFIG_MAC802154`, `CONFIG_MAC802154_LLSEC` | success |
| `vs-smoke-T0016` | `CONFIG_PECI`, `CONFIG_PECI_CPU` | success |
| `vs-smoke-T0017` | `CONFIG_BT`, `CONFIG_BT_BREDR`, `CONFIG_BT_SCO` | success |

## Interpretation

The files exist and the patch metadata is available. The remaining blockers are build-context problems:

- old kernel commits can fail host-tool preparation with current host compilers
- architecture-specific files may require `ARCH=` and possibly cross-compilers
- subsystem files may require enabling specific `CONFIG_` options before building the target object
- some fixed commits need a per-task extraction profile, not one default `x86_64_defconfig`

This means the 20-task pilot is feasible as a mixed-strength dataset, but not all 20 can be promoted to full-source CodeQL facts with a single generic build recipe. The current evidence supports materialized task/candidate/source-window rows for all 20 tasks, full-source fixed-view facts for 11 tasks, and vulnerable/fixed fact comparison for 10 tasks.

## Next Engineering Step

Create per-task build profiles:

- `ARCH=s390` profile for zcrypt
- subsystem config profile for TEE/AMDTEE
- older-stable profile that disables or bypasses problematic `objtool` host builds

The successful 11 fixed-view tasks can carry Kbuild-backed CodeQL facts. Ten of those also have vulnerable-view facts. `vs-smoke-T0020` remains fixed-only/UNKNOWN for vulnerable comparison until the parent build failure is solved or the task is replaced. The remaining 9 tasks remain patch-materialized candidates with explicit build blockers until the older-stable and architecture-specific profiles are solved.
