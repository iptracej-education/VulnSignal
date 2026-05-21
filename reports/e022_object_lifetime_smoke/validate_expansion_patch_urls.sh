#!/usr/bin/env bash
set -euo pipefail

jq -r '.task_id + "\t" + .primary_patch_url' task_expansion_candidates.jsonl |
while IFS=$'\t' read -r task url; do
  status="$(curl -L -s -o /dev/null -w "%{http_code}" "${url}")"
  printf "%s\t%s\t%s\n" "${task}" "${status}" "${url}"
done
