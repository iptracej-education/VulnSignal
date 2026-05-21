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
  or callee = "kfree_sensitive" and role = "free_sensitive"
  or callee = "sock_put" and role = "release_socket_ref"
  or callee = "sock_hold" and role = "acquire_socket_ref"
  or callee = "mod_timer" and role = "timer_register"
  or callee = "del_timer_sync" and role = "timer_cancel_sync"
  or callee = "timer_shutdown_sync" and role = "timer_cancel_sync"
  or callee = "queue_work" and role = "workqueue_enqueue"
  or callee = "cancel_work_sync" and role = "workqueue_cancel_sync"
  or callee = "flush_work" and role = "workqueue_flush"
  or callee = "ip_ma_put" and role = "release_ref"
  or callee = "rxe_queue_cleanup" and role = "cleanup_queue"
  or callee = "rxe_drop_ref" and role = "release_ref"
  or callee = "destroy_session" and role = "destroy_callback"
  or callee = "sctp_endpoint_destroy_rcu" and role = "rcu_free_callback"
  or callee = "list_del_rcu" and role = "rcu_unlink"
  or callee = "list_del_init" and role = "list_unlink"
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

predicate argLocation(FunctionCall call, int index, string file, int line) {
  index = 0 and exists(Expr arg |
    arg = call.getArgument(0) and
    file = arg.getLocation().getFile().getRelativePath() and
    line = arg.getLocation().getStartLine()
  )
  or
  index = 0 and not exists(Expr arg | arg = call.getArgument(0)) and file = "" and line = 0
}

from FunctionCall call, Function target, Function enclosing, string role,
  string arg0, string arg1, string arg2,
  string arg0File, int arg0Line
where
  call.getTarget() = target and
  lifecycleRole(target.getName(), role) and
  enclosing = call.getEnclosingFunction() and
  argText(call, 0, arg0) and
  argText(call, 1, arg1) and
  argText(call, 2, arg2) and
  argLocation(call, 0, arg0File, arg0Line)
select
  call,
  "lifecycle_call_v2",
  role,
  target.getName(),
  enclosing.getName(),
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getEndLine(),
  arg0,
  arg1,
  arg2,
  arg0File,
  arg0Line,
  call.toString()
