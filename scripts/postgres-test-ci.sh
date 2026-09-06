#!/usr/bin/env bash
# Hosted Ubuntu admission only. Database discovery always follows the kernel gate.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]] ||
   ! grep -qx 'ID=ubuntu' /etc/os-release; then
  echo 'This AppArmor setup is restricted to ephemeral GitHub-hosted runners.' >&2
  exit 1
fi

task_root=$(mktemp -d /tmp/buzz-pg-ci.XXXXXX)
profile="$task_root/bwrap.apparmor"
profile_loaded=false
cleanup() {
  status=$?
  if "$profile_loaded"; then
    sudo apparmor_parser -R "$profile" || status=1
  fi
  rm -f "$profile" "$task_root/preflight.log"
  rmdir "$task_root" || status=1
  exit "$status"
}
trap cleanup EXIT

uname -sr
/usr/bin/bwrap --version
started_us=$(date +%s%6N)
if ! python3 scripts/test-postgres-test-fence.py >"$task_root/preflight.log" 2>&1; then
  ended_us=$(date +%s%6N)
  cat "$task_root/preflight.log"
  # Ubuntu permits userns creation but can deny its capabilities. Diagnose the
  # actual denial before allowing bwrap to finish constructing its namespaces.
  sudo journalctl -k --since "@${started_us:0:-6}" --no-pager -o json |
    python3 scripts/postgres_test_ci_admission.py "$task_root/preflight.log" "$started_us" "$ended_us"
  # This additive, temporary executable profile follows Ubuntu's documented
  # userns exception. It grants no host capabilities, changes no sysctl, and
  # does not replace an existing profile. bwrap still drops all capabilities
  # and disables nested userns before any fixture command is admitted.
  cat >"$profile" <<'PROFILE'
abi <abi/4.0>,
profile buzz-postgres-ci-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
PROFILE
  sudo apparmor_parser -a -T "$profile"
  profile_loaded=true
  python3 scripts/test-postgres-test-fence.py
else
  cat "$task_root/preflight.log"
fi

scripts/postgres-test-run.sh --task-root "$task_root" --pg-bin-dir "$(pg_config --bindir)"
