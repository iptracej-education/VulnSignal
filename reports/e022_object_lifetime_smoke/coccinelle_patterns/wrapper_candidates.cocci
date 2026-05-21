@custom_put_wrapper@
identifier f =~ ".*_put";
expression E;
position p;
@@
f@p(E)

@script:python depends on custom_put_wrapper@
f << custom_put_wrapper.f;
p << custom_put_wrapper.p;
@@
print("VS_COCCI_WRAPPER\t%s\tcustom_release_wrapper_candidate\t%s\t%s" % (f, p[0].file, p[0].line))

@custom_release_wrapper@
identifier f =~ ".*_release";
expression E;
position p;
@@
f@p(E)

@script:python depends on custom_release_wrapper@
f << custom_release_wrapper.f;
p << custom_release_wrapper.p;
@@
print("VS_COCCI_WRAPPER\t%s\tcustom_release_wrapper_candidate\t%s\t%s" % (f, p[0].file, p[0].line))

@custom_drop_ref_wrapper@
identifier f =~ ".*_drop_ref";
expression E;
position p;
@@
f@p(E)

@script:python depends on custom_drop_ref_wrapper@
f << custom_drop_ref_wrapper.f;
p << custom_drop_ref_wrapper.p;
@@
print("VS_COCCI_WRAPPER\t%s\tcustom_release_wrapper_candidate\t%s\t%s" % (f, p[0].file, p[0].line))

@custom_get_wrapper@
identifier f =~ ".*_get";
expression E;
position p;
@@
f@p(E)

@script:python depends on custom_get_wrapper@
f << custom_get_wrapper.f;
p << custom_get_wrapper.p;
@@
print("VS_COCCI_WRAPPER\t%s\tcustom_acquire_wrapper_candidate\t%s\t%s" % (f, p[0].file, p[0].line))

@custom_hold_wrapper@
identifier f =~ ".*_hold";
expression E;
position p;
@@
f@p(E)

@script:python depends on custom_hold_wrapper@
f << custom_hold_wrapper.f;
p << custom_hold_wrapper.p;
@@
print("VS_COCCI_WRAPPER\t%s\tcustom_acquire_wrapper_candidate\t%s\t%s" % (f, p[0].file, p[0].line))
