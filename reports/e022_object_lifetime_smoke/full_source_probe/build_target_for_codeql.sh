#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 path/to/target.o" >&2
  exit 2
fi

target="$1"
analysis_env="/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis"
export PATH="${analysis_env}/bin:/usr/local/bin:/usr/bin:/bin"
export C_INCLUDE_PATH="${analysis_env}/include"
export LIBRARY_PATH="${analysis_env}/lib"

source_file="${target%.o}.c"
dep_file="$(dirname "${target}")/.$(basename "${target}" .o).o.d"
cmd_file="$(dirname "${target}")/.$(basename "${target}" .o).o.cmd"

rm -f "${target}" "${dep_file}" "${cmd_file}"
make "${target}" V=1
