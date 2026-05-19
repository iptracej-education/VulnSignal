/**
 * @name Extract structured hard-case facts
 * @description Feasibility query for lower-level call, argument, and unresolved-call records used by structured_facts_paths.jsonl.
 * @kind table
 * @id vulnsignal/extract-structured-hardcase-facts
 */

import cpp

from FunctionCall c, Function target
where c.getTarget() = target
select c, "call_edge", c.getEnclosingFunction().getName(), target.getName(),
  c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine(), c.toString()

