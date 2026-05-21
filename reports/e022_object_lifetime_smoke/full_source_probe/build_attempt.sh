#!/usr/bin/env bash
set -uo pipefail

log="../compile_attempt.log"
: > "${log}"

status=0
while IFS= read -r source_file; do
  echo "== ${source_file}" >> "${log}"
  gcc -fsyntax-only -w -D__KERNEL__ "${source_file}" >> "${log}" 2>&1
  rc=$?
  echo "exit=${rc}" >> "${log}"
  if [ "${rc}" -ne 0 ]; then
    status=1
  fi
done < <(find . -name '*.c' | sort)

echo "overall_compile_status=${status}" >> "${log}"

# Return success so CodeQL can finalize any translation units it managed to observe.
exit 0
