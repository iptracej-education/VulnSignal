# Full Source Probe for Existing 5 Smoke Cases

Status: one Kbuild-backed extraction path solved for `vs-smoke-T0005`; initial standalone-file attempt remains blocked.

Date: 2026-05-19

## What Was Tested

The probe fetched the actual public Linux source files for the five existing smoke tasks at both fixed and parent refs where available.

Input manifest:

- `fetch_manifest.tsv`

Fetched scope:

- 5 task instances
- 16 source files
- vulnerable and fixed views

The files are stored locally under `sources/`, which is intentionally ignored because they are fetched GPL-2.0 Linux source snapshots.

## CodeQL Attempts

Attempt 1: `codeql database create ... --command=true`

Result: failed. CodeQL detected C/C++ files but could not process any source because no compiler observed the files.

Attempt 2: `codeql database index-files`

Result: failed. The C/C++ extractor does not provide standalone file-indexing capability.

Attempt 3: compiler-traced extraction with `build_attempt.sh`

Result: database creation completed, but all 16 compilation attempts failed on missing Linux headers or subsystem-local headers. The lifecycle query returned zero rows.

Representative errors:

```text
fatal error: linux/init.h: No such file or directory
fatal error: linux/skbuff.h: No such file or directory
fatal error: linux/io.h: No such file or directory
fatal error: net/sctp/sctp.h: No such file or directory
fatal error: linux/slab.h: No such file or directory
```

## Initial Validation Result

This is a useful negative result. Full-source CodeQL extraction for Linux kernel cases requires real kernel source checkout and build metadata, not only individual affected files.

Required next step for production extraction:

1. create or reuse a Linux source checkout outside the committed dataset
2. resolve the fixed and vulnerable refs
3. build the relevant object files or subsystem with captured compiler commands
4. create CodeQL databases from compiler-observed translation units
5. run lifecycle extraction queries against those databases

Until that exists, the existing CodeQL source-window fixture rows remain probe evidence only and must not upgrade labels to `codeql_conditional`.

## Solved Path for One Case

The header/build issue was solved for `vs-smoke-T0005` (`CVE-2023-6932`, `net/ipv4/igmp.c`) by using a real kernel checkout and Kbuild, not copied headers.

Local ignored workspace:

- `.tools/kernel-work/linux-torvalds`
- `.tools/kernel-work/codeql-db-igmp`

Key commands used:

```text
git init .tools/kernel-work/linux-torvalds
git fetch --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git e2b706c691905fe78468c361aaabc719d0a496f1
git checkout --detach FETCH_HEAD
mamba install -y -p .tools/vulnsignal-analysis flex bison elfutils
PATH=.tools/vulnsignal-analysis/bin:$PATH make defconfig
PATH=.tools/vulnsignal-analysis/bin:$PATH C_INCLUDE_PATH=.tools/vulnsignal-analysis/include LIBRARY_PATH=.tools/vulnsignal-analysis/lib make prepare scripts
PATH=.tools/vulnsignal-analysis/bin:$PATH C_INCLUDE_PATH=.tools/vulnsignal-analysis/include LIBRARY_PATH=.tools/vulnsignal-analysis/lib make net/ipv4/igmp.o V=1
codeql database create .tools/kernel-work/codeql-db-igmp --language=cpp --source-root .tools/kernel-work/linux-torvalds --command="bash reports/e022_object_lifetime_smoke/full_source_probe/build_igmp_for_codeql.sh"
codeql query run reports/e022_object_lifetime_smoke/full_source_probe/queries/ExtractLifecycleSourceFacts.ql --database=.tools/kernel-work/codeql-db-igmp
```

Candidate-relevant CodeQL facts extracted from the real fixed Linux translation unit:

```text
net/ipv4/igmp.c:219 refcount_inc_not_zero role=acquire_ref_if_live function=igmp_start_timer
net/ipv4/igmp.c:220 mod_timer role=timer_register function=igmp_start_timer
net/ipv4/igmp.c:221 ip_ma_put role=release_ref function=igmp_start_timer
```

These rows are recorded in `../full_source_codeql_facts.jsonl`.

This confirms that the correct solution is feasible: fetch/checkout the source tree, prepare generated headers, compile the target with Kbuild under CodeQL tracing, then run the lifecycle query. It should replace the standalone-file path for production extraction.
