/**
 * @name Extract expression call sites
 * @description Feasibility query for function-pointer style expression calls.
 * @kind table
 * @id vulnsignal/extract-expr-calls
 */

import cpp

from ExprCall c
select c, "expr_call", c.getEnclosingFunction().getName(),
  c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine(), c.toString()

