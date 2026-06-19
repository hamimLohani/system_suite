#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${script_dir}/system_suite.sh"
smoke_home="$(mktemp -d "${TMPDIR:-/tmp}/system-suite-smoke-home.XXXXXX")"

trap 'rm -rf "${smoke_home}"' EXIT
export HOME="${smoke_home}"
export TERM="${TERM:-dumb}"

run_check() {
  local name=${1}
  local expect=${2}
  shift 2

  local stdout="${TMPDIR:-/tmp}/system_suite_${name}.out"
  local stderr="${TMPDIR:-/tmp}/system_suite_${name}.err"
  local exit_code=0

  "$@" >"${stdout}" 2>"${stderr}" || exit_code=$?

  if [[ ${expect} == "pass" && ${exit_code} -ne 0 ]]; then
    printf "%s failed with exit code %d\n" "${name}" "${exit_code}" >&2
  elif [[ ${expect} == "fail" && ${exit_code} -eq 0 ]]; then
    printf "%s was expected to fail but passed\n" "${name}" >&2
  else
    return 0
  fi

  printf '%s\n' "--- ${name} stdout ---" >&2
  cat "${stdout}" >&2 || true
  printf '%s\n' "--- ${name} stderr ---" >&2
  cat "${stderr}" >&2 || true
  return 1
}

bash -n "${script}"

run_check version pass "${script}" --version
run_check help pass "${script}" --help
run_check unknown fail "${script}" --non-interactive unknown

SYSTEM_SUITE_DISK_PATH="/" run_check info pass "${script}" --non-interactive info
run_check cleanup pass "${script}" --non-interactive cleanup --dry-run
run_check backup pass "${script}" --non-interactive backup

printf "Smoke tests passed\n"
