/**
 * @name Extract unresolved call sites
 * @description Feasibility query for indirect or unresolved call sites used by structured_facts_paths.jsonl.
 * @kind table
 * @id vulnsignal/extract-unresolved-calls
 */

import cpp

from FunctionCall c
where not exists(Function target | c.getTarget() = target)
select c, "unresolved_or_indirect_call", c.getEnclosingFunction().getName(),
  c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine(), c.toString()

