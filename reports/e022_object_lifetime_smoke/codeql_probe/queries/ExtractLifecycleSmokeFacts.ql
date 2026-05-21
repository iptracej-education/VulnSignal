import cpp

predicate lifecycleRole(string callee, string role) {
  callee = "zcrypt_card_put" and role = "release_ref"
  or callee = "zcrypt_queue_put" and role = "release_ref"
  or callee = "zcrypt_card_get" and role = "acquire_ref"
  or callee = "zcrypt_queue_get" and role = "acquire_ref"
  or callee = "kref_put" and role = "release_ref"
  or callee = "kref_put_mutex" and role = "release_ref_locked"
  or callee = "refcount_inc" and role = "acquire_ref_unchecked"
  or callee = "refcount_inc_not_zero" and role = "acquire_ref_if_live"
  or callee = "call_rcu" and role = "defer_free_rcu"
  or callee = "kfree" and role = "free"
  or callee = "sock_put" and role = "release_socket_ref"
  or callee = "mod_timer" and role = "timer_register"
  or callee = "ip_ma_put" and role = "release_ref"
  or callee = "rxe_queue_cleanup" and role = "cleanup_queue"
  or callee = "rxe_drop_ref" and role = "release_ref"
  or callee = "destroy_session" and role = "destroy_callback"
  or callee = "sctp_endpoint_destroy_rcu" and role = "rcu_free_callback"
}

from FunctionCall call, Function target, Function enclosing, string role
where
  call.getTarget() = target and
  lifecycleRole(target.getName(), role) and
  enclosing = call.getEnclosingFunction()
select
  call,
  "lifecycle_call",
  role,
  target.getName(),
  enclosing.getName(),
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.toString()
