# Hard-Case Tool Feasibility Experiment

This document records the feasibility test used to decide whether VulnSignal can capture meaningful tool-derived facts for protocol/API sequences and structured fact/path records in targeted C/C++ vulnerability families.

The goal is not to prove broad vulnerability detection. The goal is narrower: determine whether public or locally installable tools can emit precise enough source-anchored facts for object lifecycle, callback, workqueue, RCU, macro, wrapper, and function-pointer cases. Records that cannot be resolved by tools must be marked partial or `UNKNOWN`.

## Repository Artifacts

- Fixture source: `fixtures/hardcases.c`
- Fixture build file: `fixtures/Makefile`
- CodeQL query pack: `queries/qlpack.yml`
- CodeQL query: `queries/ExtractHardcaseFacts.ql`
- CodeQL structured call-edge query: `queries/ExtractStructuredFacts.ql`
- CodeQL expression-call query: `queries/ExtractExprCalls.ql`
- CodeQL unresolved-call query: `queries/ExtractUnresolvedCalls.ql`
- Coccinelle semantic patch: `queries/hardcases.cocci`
- DOT-to-graph JSONL feasibility helper: `tools/dot_to_graph_jsonl.py`

The same fixture was also copied to `/tmp/vs-hardcase` during the initial run so generated databases and output files did not pollute the repository.

## Installed Tooling

The following tools were validated locally:

```text
CodeQL CLI 2.22.3
Coccinelle spatch
Joern / joern-parse / joern-export
Clang 22.1.5
Bear 4.1.3
SVF 3.4 built locally with wpa, mta, saber, llvm2svf
```

Local tool locations used in the experiment:

```text
.tools/vulnsignal-analysis/bin/clang
.tools/vulnsignal-analysis/bin/bear
.tools/vulnsignal-analysis/bin/cmake
.tools/SVF/Release-build/bin/wpa
.tools/SVF/Release-build/bin/mta
.tools/SVF/Release-build/bin/saber
.tools/SVF/Release-build/bin/llvm2svf
```

## Fixture Coverage

The fixture intentionally contains these hard cases:

| Case | Fixture location | Purpose |
| --- | --- | --- |
| Macro wrappers | `WRAP_GET`, `WRAP_PUT` | Check macro-expanded lifecycle calls. |
| Custom wrapper APIs | `my_get`, `my_put` | Check wrapper-to-lifecycle mapping. |
| Function-pointer callback | `o->cb(o)` | Check indirect call target resolution. |
| Callback registration | `o->cb = cb_a/cb_b` | Check assignment-to-callback evidence. |
| Workqueue-like lifecycle | `init_work`, `queue_work`, `cancel_work_sync`, `flush_work` | Check async-work event extraction. |
| RCU-like callback | `call_rcu(head, rcu_free)` | Check registration-to-callback facts. |
| Free in callback | `rcu_free -> kfree` | Check callback/free source anchor. |
| Concrete caller path | `main -> set_callback -> invoke_callback` | Give SVF enough context to resolve function-pointer targets. |

## Commands and Observed Outputs

Run commands from the repository root unless a command sets a different working directory.

### 1. Build Metadata With Bear

Command:

```bash
mkdir -p /tmp/vs-hardcase/src
cp docs/feasibility/hardcase_tool_feasibility/fixtures/hardcases.c /tmp/vs-hardcase/src/
cp docs/feasibility/hardcase_tool_feasibility/fixtures/Makefile /tmp/vs-hardcase/src/
cd /tmp/vs-hardcase/src
/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/bear -- /usr/bin/make CC=/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang
```

Observed output:

```text
/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang -g -O0 -Wall -Wextra -c hardcases.c -o hardcases.o
```

Observed `compile_commands.json` excerpt:

```json
[
  {
    "file": "hardcases.c",
    "arguments": [
      "/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang",
      "-g",
      "-O0",
      "-Wall",
      "-Wextra",
      "-c",
      "hardcases.c",
      "-o",
      "hardcases.o"
    ],
    "directory": "/tmp/vs-hardcase/src",
    "output": "hardcases.o"
  }
]
```

Validation:

```text
PASS: Bear can produce build metadata for tool-backed source extraction.
NOTE: Bear needed to run outside the sandbox because its collector requires interception privileges.
```

### 2. CodeQL Source-Anchored Fact Extraction

Commands:

```bash
mkdir -p /tmp/vs-hardcase/query /tmp/vs-hardcase/out
cp docs/feasibility/hardcase_tool_feasibility/queries/qlpack.yml /tmp/vs-hardcase/query/
cp docs/feasibility/hardcase_tool_feasibility/queries/ExtractHardcaseFacts.ql /tmp/vs-hardcase/query/

HOME=/tmp codeql database create /tmp/vs-hardcase/codeql-db \
  --language=cpp \
  --source-root /tmp/vs-hardcase/src \
  --command "/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang -g -O0 -c hardcases.c -o hardcases.o" \
  --overwrite

cd /tmp/vs-hardcase/query
HOME=/tmp codeql pack install
HOME=/tmp codeql query run /tmp/vs-hardcase/query/ExtractHardcaseFacts.ql \
  --database /tmp/vs-hardcase/codeql-db \
  --output /tmp/vs-hardcase/out/hardcase_facts.bqrs

HOME=/tmp codeql bqrs decode /tmp/vs-hardcase/out/hardcase_facts.bqrs --format=csv
```

Observed decoded output:

```csv
"c","factKind","role","targetName","col4","col5","col6","col7"
"call to my_get","resolved_call","wrapper_get","my_get","macro_lifetime","hardcases.c",72,"call to my_get"
"call to my_put","resolved_call","wrapper_put","my_put","macro_lifetime","hardcases.c",73,"call to my_put"
"call to call_rcu","resolved_call","rcu_register","call_rcu","release_rcu","hardcases.c",68,"call to call_rcu"
"call to kfree","resolved_call","free","kfree","rcu_free","hardcases.c",64,"call to kfree"
"call to init_work","resolved_call","work_init_wrapper","init_work","schedule_lifecycle","hardcases.c",55,"call to init_work"
"call to my_get","resolved_call","wrapper_get","my_get","schedule_lifecycle","hardcases.c",56,"call to my_get"
"call to queue_work","resolved_call","queue_work","queue_work","schedule_lifecycle","hardcases.c",57,"call to queue_work"
"call to cancel_work_sync","resolved_call","cancel_work","cancel_work_sync","schedule_lifecycle","hardcases.c",58,"call to cancel_work_sync"
"call to flush_work","resolved_call","flush_work","flush_work","schedule_lifecycle","hardcases.c",59,"call to flush_work"
"call to my_put","resolved_call","wrapper_put","my_put","schedule_lifecycle","hardcases.c",60,"call to my_put"
"call to kref_put","resolved_call","release_ref","kref_put","my_put","hardcases.c",29,"call to kref_put"
"call to kref_get","resolved_call","acquire_ref","kref_get","my_get","hardcases.c",28,"call to kref_get"
```

Validation:

```text
PASS: CodeQL can emit source-anchored resolved calls for wrappers, lifecycle calls, RCU registration, workqueue events, and macro-expanded wrapper calls.
LIMIT: This query does not resolve indirect function-pointer targets. SVF is needed for that hard case.
```

### 3. Clang Macro and AST Evidence

Commands:

```bash
cd /tmp/vs-hardcase/src
/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang -E hardcases.c
/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis/bin/clang -Xclang -ast-dump -fsyntax-only hardcases.c
```

Observed preprocessor excerpt:

```c
void schedule_lifecycle(struct work_struct *work, struct obj *o) {
  init_work(work);
  my_get(o);
  queue_work(((void*)0), work);
  cancel_work_sync(work);
  flush_work(work);
  my_put(o);
}

int macro_lifetime(struct obj *o) {
  my_get(o);
  my_put(o);
  return o->value;
}
```

Observed AST facts included:

```text
CallExpr ... Function ... 'my_get'
CallExpr ... Function ... 'my_put'
BinaryOperator ... 'o->cb = cb_a'
BinaryOperator ... 'o->cb = cb_b'
CallExpr ... 'call_rcu(head, rcu_free)'
```

Validation:

```text
PASS: Clang provides macro-aware source and AST evidence.
USE: Use Clang/CodeQL for macro-heavy source provenance. Do not rely on text parsing.
```

### 4. SVF Function-Pointer Target Resolution

Commands:

```bash
cd /tmp/vs-hardcase/src
/home/iptracej/Dev/VulnSignal/.tools/SVF/llvm-21.1.0.obj/bin/clang \
  -g -O0 -emit-llvm -c hardcases.c \
  -o /tmp/vs-hardcase/out/hardcases.bc

LD_LIBRARY_PATH=/home/iptracej/Dev/VulnSignal/.tools/SVF/Release-build/lib:/home/iptracej/Dev/VulnSignal/.tools/SVF/llvm-21.1.0.obj/lib:/home/iptracej/Dev/VulnSignal/.tools/SVF/z3.obj/bin:$LD_LIBRARY_PATH \
  /home/iptracej/Dev/VulnSignal/.tools/SVF/Release-build/bin/wpa \
  -ander -print-fp /tmp/vs-hardcase/out/hardcases.bc
```

Observed output excerpt:

```text
==================Function Pointer Targets==================

NodeID: 73
CallSite: CallICFGNode63 {fun: invoke_callback{ "ln": 35, "cl": 3, "fl": "hardcases.c" }}
   call void %5(ptr noundef %6), !dbg !26
   Location: CallICFGNode: { "ln": 35, "cl": 3, "fl": "hardcases.c" } with Targets:
        cb_b
        cb_a
```

Validation:

```text
PASS: SVF can identify an indirect call site and resolve possible function-pointer targets when enough flow context exists.
LIMIT: Before adding the concrete caller path in main(), SVF found the indirect call site but reported no targets. Therefore unresolved target sets must be represented as partial or UNKNOWN.
```

### 5. Coccinelle Semantic Pattern Capture

Commands:

```bash
cp docs/feasibility/hardcase_tool_feasibility/queries/hardcases.cocci /tmp/vs-hardcase/query/
spatch --sp-file /tmp/vs-hardcase/query/hardcases.cocci /tmp/vs-hardcase/src/hardcases.c
```

Observed output:

```text
COCCI_FACT,wrapper_get_or_acquire,/tmp/vs-hardcase/src/hardcases.c,28
COCCI_FACT,wrapper_get_or_acquire,/tmp/vs-hardcase/src/hardcases.c,3
COCCI_FACT,wrapper_put_or_release,/tmp/vs-hardcase/src/hardcases.c,29
COCCI_FACT,wrapper_put_or_release,/tmp/vs-hardcase/src/hardcases.c,4
COCCI_FACT,queue_work,/tmp/vs-hardcase/src/hardcases.c,57
COCCI_FACT,call_rcu,rcu_free,/tmp/vs-hardcase/src/hardcases.c,68
```

Validation:

```text
PASS: Coccinelle can capture Linux-style semantic patterns for wrappers, queue_work, and call_rcu.
LIMIT: Macro wrapper calls may be reported at macro definition lines. Coccinelle is useful as supplemental evidence, not the only source of macro-heavy source locations.
```

### 6. Joern CPG/CFG Extraction

Commands:

```bash
joern-parse /tmp/vs-hardcase/src/hardcases.c \
  --language c \
  -o /tmp/vs-hardcase/out/hardcases.cpg.bin

joern-export /tmp/vs-hardcase/out/hardcases.cpg.bin \
  --repr cfg \
  --format dot \
  -o /tmp/vs-hardcase/out/joern_cfg

rg -n "queue_work|call_rcu|invoke_callback|cb_a|cb_b|my_get|my_put|worker" /tmp/vs-hardcase/out/joern_cfg
```

Observed output excerpt:

```text
work->func = worker
METHOD_REF, worker
call_rcu(head, rcu_free)
METHOD_REF, rcu_free
invoke_callback(&o)
queue_work(NULL, work)
my_get(o)
my_put(o)
o->cb = cb_a
METHOD_REF, cb_a
o->cb = cb_b
METHOD_REF, cb_b
```

Validation:

```text
PASS: Joern can build a CPG/CFG representation and expose graph facts for assignments, method references, callback setup, queue calls, and RCU calls.
USE: Joern is a useful supplemental graph source for structured_facts_paths.jsonl.
```

### 7. Structured Fact / Path Record Extraction

This test checks whether the same toolchain can produce lower-level structured facts and graph/path records, separate from normalized protocol/API event sequences.

Expected structured record types:

```text
call_edge
expr_call / pointer_call
callback_assignment
method_ref
cfg_node
ddg_edge
pdg_edge
icfg_node
possible_indirect_target
```

#### 7.1 CodeQL Call Edges and Expression Calls

Commands:

```bash
cp docs/feasibility/hardcase_tool_feasibility/queries/ExtractStructuredFacts.ql /tmp/vs-hardcase/query/
cp docs/feasibility/hardcase_tool_feasibility/queries/ExtractExprCalls.ql /tmp/vs-hardcase/query/
cp docs/feasibility/hardcase_tool_feasibility/queries/ExtractUnresolvedCalls.ql /tmp/vs-hardcase/query/

HOME=/tmp codeql query run /tmp/vs-hardcase/query/ExtractStructuredFacts.ql \
  --database /tmp/vs-hardcase/codeql-db \
  --output /tmp/vs-hardcase/out/structured_call_edges.bqrs

HOME=/tmp codeql bqrs decode /tmp/vs-hardcase/out/structured_call_edges.bqrs --format=csv

HOME=/tmp codeql query run /tmp/vs-hardcase/query/ExtractExprCalls.ql \
  --database /tmp/vs-hardcase/codeql-db \
  --output /tmp/vs-hardcase/out/expr_calls.bqrs

HOME=/tmp codeql bqrs decode /tmp/vs-hardcase/out/expr_calls.bqrs --format=csv
```

Observed `call_edge` output excerpt:

```csv
"call to call_rcu","call_edge","release_rcu","call_rcu","hardcases.c",68,"call to call_rcu"
"call to kfree","call_edge","rcu_free","kfree","hardcases.c",64,"call to kfree"
"call to init_work","call_edge","schedule_lifecycle","init_work","hardcases.c",55,"call to init_work"
"call to my_get","call_edge","schedule_lifecycle","my_get","hardcases.c",56,"call to my_get"
"call to queue_work","call_edge","schedule_lifecycle","queue_work","hardcases.c",57,"call to queue_work"
"call to cancel_work_sync","call_edge","schedule_lifecycle","cancel_work_sync","hardcases.c",58,"call to cancel_work_sync"
"call to flush_work","call_edge","schedule_lifecycle","flush_work","hardcases.c",59,"call to flush_work"
"call to my_put","call_edge","schedule_lifecycle","my_put","hardcases.c",60,"call to my_put"
"call to kref_put","call_edge","my_put","kref_put","hardcases.c",29,"call to kref_put"
"call to kref_get","call_edge","my_get","kref_get","hardcases.c",28,"call to kref_get"
```

Observed expression-call output:

```csv
"c","col1","col2","col3","col4","col5"
"call to expression","expr_call","invoke_callback","hardcases.c",35,"call to expression"
```

Validation:

```text
PASS: CodeQL can produce structured call-edge records with caller, callee, source file, line, and source expression.
PASS: CodeQL can identify the function-pointer expression call site as an expression call.
LIMIT: The simple CodeQL query identifies the indirect call site but does not resolve possible targets. SVF is needed for possible target sets.
```

#### 7.2 Joern DDG/PDG Graph Records

Commands:

```bash
joern-export /tmp/vs-hardcase/out/hardcases.cpg.bin \
  --repr ddg \
  --format dot \
  -o /tmp/vs-hardcase/out/joern_ddg

joern-export /tmp/vs-hardcase/out/hardcases.cpg.bin \
  --repr pdg \
  --format dot \
  -o /tmp/vs-hardcase/out/joern_pdg

rg -n "queue_work|call_rcu|invoke_callback|cb_a|cb_b|o-&gt;cb|work-&gt;func|my_get|my_put|kref" \
  /tmp/vs-hardcase/out/joern_ddg \
  /tmp/vs-hardcase/out/joern_pdg
```

Observed output excerpt:

```text
o->cb = cb_a
METHOD_REF, cb_a
o->cb = cb_b
METHOD_REF, cb_b
<operator>.pointerCall, 35, o->cb(o)
work->func = worker
queue_work(NULL, work)
call_rcu(head, rcu_free)
kref_get(&o->ref)
kref_put(&o->ref)
DDG: o->cb = cb_a
DDG: work->func = worker
DDG: queue_work(NULL, work)
DDG: call_rcu(head, rcu_free)
```

Validation:

```text
PASS: Joern can produce graph records for callback assignments, method references, pointer calls, work-handler assignment, queue calls, RCU calls, and lifecycle calls.
USE: Joern is suitable for supplemental `structured_facts_paths.jsonl` graph records.
LIMIT: The DOT export is graph evidence, not final semantic truth. VulnSignal still needs a normalizer that converts graph nodes/edges into stable JSONL records.
```

#### 7.3 SVF ICFG, Callgraph, and Indirect Target Records

Commands:

```bash
mkdir -p /tmp/vs-hardcase/out/svf_graphs

LD_LIBRARY_PATH=/home/iptracej/Dev/VulnSignal/.tools/SVF/Release-build/lib:/home/iptracej/Dev/VulnSignal/.tools/SVF/llvm-21.1.0.obj/lib:/home/iptracej/Dev/VulnSignal/.tools/SVF/z3.obj/bin:$LD_LIBRARY_PATH \
  /home/iptracej/Dev/VulnSignal/.tools/SVF/Release-build/bin/wpa \
  -ander -print-fp -dump-callgraph -dump-icfg -dump-vfg \
  /tmp/vs-hardcase/out/hardcases.bc

rg -n "invoke_callback|cb_a|cb_b|schedule_lifecycle|queue_work|call_rcu|my_get|my_put|kref" \
  /tmp/vs-hardcase/out/svf_graphs/*.dot
```

Observed output excerpt:

```text
==================Function Pointer Targets==================

CallSite: CallICFGNode63 {fun: invoke_callback{ "ln": 35, "cl": 3, "fl": "hardcases.c" }}
Location: CallICFGNode: { "ln": 35, "cl": 3, "fl": "hardcases.c" } with Targets:
        cb_b
        cb_a
```

Observed DOT graph files:

```text
icfg_initial.dot
callgraph_initial.dot
callgraph_final.dot
```

Observed `callgraph_final.dot` excerpt:

```text
CallGraphNode ID: 4 {fun: invoke_callback}|{<s0>15|<s1>16}
CallGraphNode ID: 2 {fun: cb_a}
CallGraphNode ID: 3 {fun: cb_b}
```

Observed `icfg_initial.dot` excerpt:

```text
CallICFGNode63 {fun: invoke_callback{ "ln": 35, "cl": 3, "fl": "hardcases.c" }}
call void %5(ptr noundef %6)

StoreStmt ... store ptr @cb_a ... { "ln": 40, "cl": 11, "fl": "hardcases.c" }
StoreStmt ... store ptr @cb_b ... { "ln": 42, "cl": 11, "fl": "hardcases.c" }

CallICFGNode103 {fun: schedule_lifecycle{ "ln": 57, "cl": 3, "fl": "hardcases.c" }}
call void @queue_work(...)

CallICFGNode124 {fun: release_rcu{ "ln": 68, "cl": 3, "fl": "hardcases.c" }}
call void @call_rcu(...)
```

Validation:

```text
PASS: SVF can produce ICFG and callgraph records with source locations.
PASS: SVF can resolve possible indirect-call targets when flow context is present.
PASS: SVF final callgraph includes the resolved indirect edges from invoke_callback to cb_a/cb_b.
LIMIT: SVF target sets are possible targets, not proof of runtime execution. Missing flow context may produce an unresolved target set.
```

## Structured Fact / Path Record Decision

The feasibility test supports creating `structured_facts_paths.jsonl` from tool outputs.

Recommended record families:

```text
codeql_call_edge
codeql_expr_call
joern_cfg_node
joern_ddg_edge
joern_pdg_edge
joern_method_ref
joern_assignment
svf_icfg_node
svf_callgraph_edge
svf_possible_indirect_target
svf_store/load/gep_fact
```

Required fields:

```text
fact_id
candidate_id
tool
tool_version
fact_kind
source_file
source_line
source_column_when_available
enclosing_function
source_expression_or_ir
source_node_id_when_available
target_node_id_when_available
target_function_when_available
edge_type_when_available
resolution_status
limitations
```

Validation policy:

```text
Tool graph/path facts can support model input and evidence rationale.
They are not final vulnerability truth.
Possible target sets remain possible, not confirmed runtime paths.
Missing graph/path resolution becomes partial or UNKNOWN.
```

## Optional Graph Structure Feasibility

Optional graph structure is the graph-shaped model input derived from structured facts and tool graph exports. It is separate from source-window sequences and protocol/API sequences.

Expected graph input shape:

```json
{
  "graph_id": "joern:pdg:9-pdg.dot",
  "tool": "joern",
  "graph_kind": "pdg",
  "node_count": 12,
  "edge_count": 31,
  "nodes": [
    {"node_id": "30064771094", "label": "queue_work, 57 | queue_work(NULL, work)"}
  ],
  "edges": [
    {"src": "30064771094", "dst": "30064771095", "edge_label": "DDG: work"}
  ]
}
```

### 8. Graph JSONL Conversion

The feasibility helper `tools/dot_to_graph_jsonl.py` converts Graphviz DOT files into one graph JSON object per line. It uses Graphviz itself through `dot -Tjson`, avoiding a custom DOT parser.

Commands:

```bash
python3 docs/feasibility/hardcase_tool_feasibility/tools/dot_to_graph_jsonl.py \
  --tool joern \
  --graph-kind pdg \
  --output /tmp/vs-hardcase/out/optional_graph_joern_pdg.jsonl \
  /tmp/vs-hardcase/out/joern_pdg/5-pdg.dot \
  /tmp/vs-hardcase/out/joern_pdg/6-pdg.dot \
  /tmp/vs-hardcase/out/joern_pdg/8-pdg.dot \
  /tmp/vs-hardcase/out/joern_pdg/9-pdg.dot \
  /tmp/vs-hardcase/out/joern_pdg/11-pdg.dot

python3 docs/feasibility/hardcase_tool_feasibility/tools/dot_to_graph_jsonl.py \
  --tool joern \
  --graph-kind ddg \
  --output /tmp/vs-hardcase/out/optional_graph_joern_ddg.jsonl \
  /tmp/vs-hardcase/out/joern_ddg/5-ddg.dot \
  /tmp/vs-hardcase/out/joern_ddg/6-ddg.dot \
  /tmp/vs-hardcase/out/joern_ddg/8-ddg.dot \
  /tmp/vs-hardcase/out/joern_ddg/9-ddg.dot \
  /tmp/vs-hardcase/out/joern_ddg/11-ddg.dot

python3 docs/feasibility/hardcase_tool_feasibility/tools/dot_to_graph_jsonl.py \
  --tool svf \
  --graph-kind callgraph \
  --output /tmp/vs-hardcase/out/optional_graph_svf_callgraph.jsonl \
  /tmp/vs-hardcase/out/svf_graphs/callgraph_final.dot

python3 docs/feasibility/hardcase_tool_feasibility/tools/dot_to_graph_jsonl.py \
  --tool svf \
  --graph-kind icfg \
  --output /tmp/vs-hardcase/out/optional_graph_svf_icfg.jsonl \
  /tmp/vs-hardcase/out/svf_graphs/icfg_initial.dot
```

Observed line counts:

```text
    5 /tmp/vs-hardcase/out/optional_graph_joern_ddg.jsonl
    5 /tmp/vs-hardcase/out/optional_graph_joern_pdg.jsonl
    1 /tmp/vs-hardcase/out/optional_graph_svf_callgraph.jsonl
    1 /tmp/vs-hardcase/out/optional_graph_svf_icfg.jsonl
   12 total
```

Observed Joern graph JSONL excerpts:

```json
{
  "graph_id": "joern:pdg:5-pdg.dot",
  "graph_name": "invoke_callback",
  "graph_kind": "pdg",
  "node_count": 4,
  "edge_count": 5,
  "nodes": [
    {"node_id": "30064771082", "label": "<operator>.pointerCall, 35 | o->cb(o)"}
  ],
  "edges": [
    {"src": "30064771082", "dst": "128849018884", "edge_label": "DDG: o->cb(o)"}
  ]
}
```

```json
{
  "graph_id": "joern:pdg:6-pdg.dot",
  "graph_name": "set_callback",
  "nodes": [
    {"node_id": "30064771084", "label": "<operator>.assignment, 40 | o->cb = cb_a"},
    {"node_id": "124554051584", "label": "METHOD_REF, 40 | cb_a | o->cb = cb_a"},
    {"node_id": "30064771086", "label": "<operator>.assignment, 42 | o->cb = cb_b"},
    {"node_id": "124554051585", "label": "METHOD_REF, 42 | cb_b | o->cb = cb_b"}
  ]
}
```

```json
{
  "graph_id": "joern:pdg:9-pdg.dot",
  "graph_name": "schedule_lifecycle",
  "nodes": [
    {"node_id": "30064771091", "label": "init_work, 55 | init_work(work)"},
    {"node_id": "30064771094", "label": "queue_work, 57 | queue_work(NULL, work)"},
    {"node_id": "30064771095", "label": "cancel_work_sync, 58 | cancel_work_sync(work)"},
    {"node_id": "30064771096", "label": "flush_work, 59 | flush_work(work)"}
  ]
}
```

Observed SVF graph JSONL excerpts:

```json
{
  "graph_id": "svf:callgraph:callgraph_final.dot",
  "graph_kind": "callgraph",
  "node_count": 20,
  "nodes": [
    {"label": "{CallGraphNode ID: 4 {fun: invoke_callback}|{<s0>15|<s1>16}}"},
    {"label": "{CallGraphNode ID: 2 {fun: cb_a}}"},
    {"label": "{CallGraphNode ID: 3 {fun: cb_b}}"}
  ]
}
```

```json
{
  "graph_id": "svf:icfg:icfg_initial.dot",
  "graph_kind": "icfg",
  "node_count": 147,
  "edge_count": 142
}
```

Validation:

```text
PASS: Optional graph records can be created from Joern PDG/DDG outputs.
PASS: Optional graph records can be created from SVF callgraph and ICFG outputs.
PASS: Hard-case nodes appear in graph form: pointer call, callback assignment, work-handler assignment, workqueue events, RCU call, lifecycle calls, and possible indirect targets.
LIMIT: The current graph JSONL is a feasibility format. Production graph input must add candidate_id, source anchors, stable node types, stable edge types, provenance, and resolution_status.
LIMIT: SVF graph labels are rich but tool-specific. They require a normalizer before model training.
```

Recommended optional graph record families:

```text
joern_pdg_graph
joern_ddg_graph
joern_cfg_graph
svf_callgraph
svf_icfg
svf_value_flow_graph_when_available
```

Required production fields:

```text
graph_id
candidate_id
tool
tool_version
graph_kind
node_id
node_type
node_label
source_file_when_available
source_line_when_available
edge_src
edge_dst
edge_type
edge_label
resolution_status
limitations
```

Graph input decision:

```text
Optional graph structure is feasible for targeted families.
It should be derived from CodeQL/Joern/SVF structured facts and graph exports.
It should not replace protocol/API sequences or source windows.
It should be used as an optional model view with missing-view masks.
Unresolved graph relationships remain partial or UNKNOWN.
```

## Hard-Case Classification

| Hard case | Result | Evidence |
| --- | --- | --- |
| Missing build metadata | Supported | Bear produced `compile_commands.json`. |
| Macro-heavy code | Supported with caveat | Clang/CodeQL preserve macro-aware call facts; Coccinelle can report macro definition lines. |
| Custom wrappers | Supported for known wrappers | CodeQL extracted `my_get -> kref_get` and `my_put -> kref_put`; Coccinelle also matched wrappers. |
| Function pointers | Supported when flow context exists | SVF resolved `o->cb(o)` to `cb_a` and `cb_b`. |
| Callback registration | Partial/supported | Clang AST, Joern DDG/PDG graph JSONL, and SVF ICFG expose `o->cb = cb_a/cb_b`; SVF resolves targets with concrete flow. |
| RCU callbacks | Supported for registration and callback source facts | CodeQL/Coccinelle/Joern captured `call_rcu(head, rcu_free)` and `rcu_free -> kfree`. |
| Workqueue execution | Supported for event and graph facts; partial for async execution | CodeQL/Coccinelle/Joern graph JSONL captured init/queue/cancel/flush facts; runtime execution ordering is not proven. |
| Thread interleavings | Not statically proven | SVF has MTA support, but strong runtime evidence still requires KCSAN/reproducer/syzkaller/ftrace-style evidence. |
| Virtual dispatch | Not covered by this C fixture | Needs a separate C++ fixture with CodeQL C++ class facts, SVF CHA, and Joern. |

## Validation Decision

The feasibility test supports starting VulnSignal under a scoped claim:

```text
VulnSignal can capture meaningful tool-derived facts and create protocol/API sequences for targeted C/C++ vulnerability families when the target family has a defined rule pack, extraction queries, source anchors, and explicit partial/UNKNOWN handling.
```

It does not support broader claims:

```text
Not supported: all vulnerability families.
Not supported: arbitrary API semantic normalization.
Not supported: static proof of thread interleavings.
Not supported: strong labels when tool facts are unresolved.
```

The implementation rule should be:

```text
Only tool-emitted facts are normalized.
Raw source text is preserved for audit and source-window input.
No source-text grep or manually invented protocol traces are admitted.
Unresolved hard cases become partial or UNKNOWN.
```

## Required Follow-Up Tests

1. C++ virtual-dispatch fixture using CodeQL C++ class/call facts, SVF CHA, and Joern.
2. Real Linux workqueue fixture using `INIT_WORK`, `container_of`, `queue_work`, `cancel_work_sync`, and object free.
3. Real Linux RCU fixture using `call_rcu`, `kfree_rcu`, `container_of`, callback free, and post-release use.
4. One real vulnerable/fixed patch pair to test bad/good protocol sequence extraction.
5. One KCSAN/syzkaller/reproducer-backed case for runtime concurrency evidence.
