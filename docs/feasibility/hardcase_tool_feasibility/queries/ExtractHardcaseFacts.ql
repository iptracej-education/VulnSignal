/**
 * @name Extract hard-case facts
 * @description Feasibility query for source-anchored calls, indirect calls, and lifecycle-like APIs.
 * @kind table
 * @id vulnsignal/extract-hardcase-facts
 */

import cpp

predicate lifecycleRole(string callee, string role) {
  callee = "kref_get" and role = "acquire_ref"
  or callee = "kref_put" and role = "release_ref"
  or callee = "kfree" and role = "free"
  or callee = "queue_work" and role = "queue_work"
  or callee = "cancel_work_sync" and role = "cancel_work"
  or callee = "flush_work" and role = "flush_work"
  or callee = "call_rcu" and role = "rcu_register"
  or callee = "my_get" and role = "wrapper_get"
  or callee = "my_put" and role = "wrapper_put"
  or callee = "init_work" and role = "work_init_wrapper"
}

from FunctionCall c, string factKind, string role, string targetName
where
  exists(Function target |
    c.getTarget() = target and
    lifecycleRole(target.getName(), role) and
    targetName = target.getName() and
    factKind = "resolved_call"
  )
  or
  (
    not exists(Function target | c.getTarget() = target) and
    role = "unknown" and
    targetName = "" and
    factKind = "unresolved_or_indirect_call"
  )
select c, factKind, role, targetName, c.getEnclosingFunction().getName(),
  c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine(), c.toString()
