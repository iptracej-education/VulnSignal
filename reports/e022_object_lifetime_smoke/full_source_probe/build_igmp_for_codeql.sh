#!/usr/bin/env bash
set -euo pipefail

analysis_env="/home/iptracej/Dev/VulnSignal/.tools/vulnsignal-analysis"
export PATH="${analysis_env}/bin:/usr/local/bin:/usr/bin:/bin"
export C_INCLUDE_PATH="${analysis_env}/include"
export LIBRARY_PATH="${analysis_env}/lib"

rm -f net/ipv4/igmp.o net/ipv4/.igmp.o.cmd net/ipv4/.igmp.o.d
make net/ipv4/igmp.o V=1
