#!/usr/bin/env bash
set -euo pipefail

base_url="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain"
manifest="fetch_manifest.tsv"
out_root="sources"

while IFS=$'\t' read -r task view ref path; do
  out_dir="${out_root}/${task}/${view}/$(dirname "${path}")"
  mkdir -p "${out_dir}"
  curl -fsSL "${base_url}/${path}?id=${ref}" -o "${out_root}/${task}/${view}/${path}"
done < "${manifest}"
