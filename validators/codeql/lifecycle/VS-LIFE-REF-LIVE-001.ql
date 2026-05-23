import cpp
import LifecycleValidation

from FunctionCall call, Function enclosing, string family, string expectedView,
  string evidenceKind, string role, string callee, string arg0, string arg1, string arg2
where
  validatorEvidence(
    call,
    "VS-LIFE-REF-LIVE-001",
    family,
    expectedView,
    evidenceKind,
    role,
    callee,
    enclosing,
    arg0,
    arg1,
    arg2
  )
select
  call,
  "VS-LIFE-REF-LIVE-001",
  family,
  expectedView,
  evidenceKind,
  role,
  callee,
  enclosing.getName(),
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getEndLine(),
  arg0,
  arg1,
  arg2,
  call.toString()
