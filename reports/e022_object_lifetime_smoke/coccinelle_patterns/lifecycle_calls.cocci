@kref_put_call@
expression E, F;
position p;
@@
kref_put@p(E, F)

@script:python depends on kref_put_call@
p << kref_put_call.p;
@@
print("VS_COCCI_MATCH\tkref_put\trelease_ref\t%s\t%s" % (p[0].file, p[0].line))

@kref_put_mutex_call@
expression E, F, M;
position p;
@@
kref_put_mutex@p(E, F, M)

@script:python depends on kref_put_mutex_call@
p << kref_put_mutex_call.p;
@@
print("VS_COCCI_MATCH\tkref_put_mutex\trelease_ref_locked\t%s\t%s" % (p[0].file, p[0].line))

@refcount_inc_call@
expression E;
position p;
@@
refcount_inc@p(E)

@script:python depends on refcount_inc_call@
p << refcount_inc_call.p;
@@
print("VS_COCCI_MATCH\trefcount_inc\tacquire_ref_unchecked\t%s\t%s" % (p[0].file, p[0].line))

@refcount_inc_not_zero_call@
expression E;
position p;
@@
refcount_inc_not_zero@p(E)

@script:python depends on refcount_inc_not_zero_call@
p << refcount_inc_not_zero_call.p;
@@
print("VS_COCCI_MATCH\trefcount_inc_not_zero\tacquire_ref_if_live\t%s\t%s" % (p[0].file, p[0].line))

@call_rcu_call@
expression E, F;
position p;
@@
call_rcu@p(E, F)

@script:python depends on call_rcu_call@
p << call_rcu_call.p;
@@
print("VS_COCCI_MATCH\tcall_rcu\tdefer_free_rcu\t%s\t%s" % (p[0].file, p[0].line))

@list_del_rcu_call@
expression E;
position p;
@@
list_del_rcu@p(E)

@script:python depends on list_del_rcu_call@
p << list_del_rcu_call.p;
@@
print("VS_COCCI_MATCH\tlist_del_rcu\trcu_unlink\t%s\t%s" % (p[0].file, p[0].line))

@kfree_call@
expression E;
position p;
@@
kfree@p(E)

@script:python depends on kfree_call@
p << kfree_call.p;
@@
print("VS_COCCI_MATCH\tkfree\tfree\t%s\t%s" % (p[0].file, p[0].line))

@kfree_sensitive_call@
expression E;
position p;
@@
kfree_sensitive@p(E)

@script:python depends on kfree_sensitive_call@
p << kfree_sensitive_call.p;
@@
print("VS_COCCI_MATCH\tkfree_sensitive\tfree_sensitive\t%s\t%s" % (p[0].file, p[0].line))
