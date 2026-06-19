#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${script_dir}/system_suite.sh"

bash -n "${script}"

"${script}" --version >/dev/null
"${script}" --help >/dev/null
"${script}" --non-interactive unknown >/tmp/system_suite_unknown.out 2>/tmp/system_suite_unknown.err && {
  printf "Expected unknown command to fail\n" >&2
  exit 1
}

SYSTEM_SUITE_DISK_PATH="/" "${script}" --non-interactive info >/tmp/system_suite_info.out
"${script}" --non-interactive cleanup --dry-run >/tmp/system_suite_cleanup.out
"${script}" --non-interactive backup >/tmp/system_suite_backup.out

printf "Smoke tests passed\n"
