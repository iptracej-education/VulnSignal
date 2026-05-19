@ wrapper_get @
expression E;
position p;
@@
(
my_get(E)@p
|
kref_get(E)@p
)

@ script:python @
p << wrapper_get.p;
@@
print("COCCI_FACT,wrapper_get_or_acquire,%s,%s" % (p[0].file, p[0].line))

@ wrapper_put @
expression E;
position p;
@@
(
my_put(E)@p
|
kref_put(E)@p
)

@ script:python @
p << wrapper_put.p;
@@
print("COCCI_FACT,wrapper_put_or_release,%s,%s" % (p[0].file, p[0].line))

@ async_work @
expression WQ, WORK;
position p;
@@
queue_work(WQ, WORK)@p

@ script:python @
p << async_work.p;
@@
print("COCCI_FACT,queue_work,%s,%s" % (p[0].file, p[0].line))

@ rcu @
expression HEAD;
identifier FUNC;
position p;
@@
call_rcu(HEAD, FUNC)@p

@ script:python @
p << rcu.p;
FUNC << rcu.FUNC;
@@
print("COCCI_FACT,call_rcu,%s,%s,%s" % (FUNC, p[0].file, p[0].line))
