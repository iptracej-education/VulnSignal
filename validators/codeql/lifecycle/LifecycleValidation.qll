import cpp

/**
 * Stable mapping from a VulnSignal lifecycle rule to the API evidence the
 * CodeQL validator should observe in one source view.
 */
predicate expectedRuleCall(
  string ruleId,
  string family,
  string expectedView,
  string callee,
  string role
) {
  ruleId = "VS-LIFE-REF-LIVE-001" and
  family = "refcount_live_acquire" and
  expectedView = "vulnerable" and
  callee = "refcount_inc" and
  role = "acquire_ref_unchecked"
  or
  ruleId = "VS-LIFE-REF-LIVE-001" and
  family = "refcount_live_acquire" and
  expectedView = "fixed" and
  callee = "refcount_inc_not_zero" and
  role = "acquire_ref_if_live"
  or
  ruleId = "VS-LIFE-REF-INSERT-001" and
  family = "refcount_live_acquire_inserted" and
  expectedView = "fixed" and
  callee = "refcount_inc_not_zero" and
  role = "acquire_ref_if_live"
  or
  ruleId = "VS-LIFE-KREF-LOCK-001" and
  family = "kref_release_under_mutex" and
  expectedView = "vulnerable" and
  callee = "kref_put" and
  role = "release_ref"
  or
  ruleId = "VS-LIFE-KREF-LOCK-001" and
  family = "kref_release_under_mutex" and
  expectedView = "fixed" and
  callee = "kref_put_mutex" and
  role = "release_ref_locked"
  or
  ruleId = "VS-LIFE-RCU-DEFER-001" and
  family = "rcu_deferred_release" and
  expectedView = "fixed" and
  callee = "call_rcu" and
  role = "defer_free_rcu"
}

predicate lifecycleContextCall(string callee, string role) {
  callee = "list_del_rcu" and role = "rcu_unlink"
  or callee = "kref_put" and role = "release_ref"
  or callee = "kfree" and role = "free"
  or callee = "kfree_sensitive" and role = "free_sensitive"
}

predicate callTargetName(FunctionCall call, string callee) {
  exists(Function target |
    call.getTarget() = target and
    callee = target.getName()
  )
}

predicate argText(FunctionCall call, int index, string text) {
  index = 0 and exists(Expr arg | arg = call.getArgument(0) and text = arg.toString())
  or
  index = 1 and exists(Expr arg | arg = call.getArgument(1) and text = arg.toString())
  or
  index = 2 and exists(Expr arg | arg = call.getArgument(2) and text = arg.toString())
  or
  index = 0 and not exists(Expr arg | arg = call.getArgument(0)) and text = ""
  or
  index = 1 and not exists(Expr arg | arg = call.getArgument(1)) and text = ""
  or
  index = 2 and not exists(Expr arg | arg = call.getArgument(2)) and text = ""
}

predicate validatorEvidenceForRule(
  FunctionCall call,
  string ruleId,
  string family,
  string expectedView,
  string evidenceKind,
  string role,
  string callee
) {
  expectedRuleCall(ruleId, family, expectedView, callee, role) and
  callTargetName(call, callee) and
  evidenceKind = "required_call"
  or
  ruleId = "VS-LIFE-RCU-DEFER-001" and
  family = "rcu_deferred_release" and
  expectedView = "vulnerable" and
  lifecycleContextCall(callee, role) and
  callTargetName(call, callee) and
  evidenceKind = "context_call"
}

predicate validatorEvidence(
  FunctionCall call,
  string ruleId,
  string family,
  string expectedView,
  string evidenceKind,
  string role,
  string callee,
  Function enclosing,
  string arg0,
  string arg1,
  string arg2
) {
  validatorEvidenceForRule(call, ruleId, family, expectedView, evidenceKind, role, callee) and
  enclosing = call.getEnclosingFunction() and
  argText(call, 0, arg0) and
  argText(call, 1, arg1) and
  argText(call, 2, arg2)
}
