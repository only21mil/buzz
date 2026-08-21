#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
manifest=$script_dir/install-manifest.tsv
sudoers=$script_dir/buzz-ci-acceptance-ctl.sudoers
service=$script_dir/buzz-ci-execd.service
socket=$script_dir/buzz-ci-execd.socket
harness=$script_dir/harness.env.plan
principals=$script_dir/principals.tsv
case_plan=$script_dir/qualification-cases.plan

fail() {
  printf 'substrate selftest: %s\n' "$1" >&2
  exit 1
}

bash -n "$script_dir/selftest.sh"

awk -F '\t' '
  /^#/ || NF == 0 { next }
  NF != 6 { bad = 1; next }
  $2 !~ /^\// || $2 ~ /(^|\/)\.\.?($|\/)/ { bad = 1 }
  $3 !~ /^(root|buzzci-ctl)$/ || $4 !~ /^(root|buzzci-ctl)$/ { bad = 1 }
  $5 !~ /^0[0-7]{3}$/ { bad = 1 }
  $6 !~ /^(directory|compiled-binary|file|rendered-file)$/ { bad = 1 }
  seen[$2]++ { bad = 1 }
  END { exit bad }
' "$manifest" || fail 'invalid install manifest'

manifest_row() {
  local destination=$1 expected=$2
  local actual
  actual=$(awk -F '\t' -v destination="$destination" '$2 == destination { print; count++ } END { if (count != 1) exit 1 }' "$manifest") \
    || fail "missing or duplicate manifest path: $destination"
  [[ $actual == "$expected" ]] || fail "wrong manifest contract: $destination"
}

manifest_row /usr/libexec/buzz-ci-execd \
  $'cargo-bin:buzz-ci-execd\t/usr/libexec/buzz-ci-execd\troot\troot\t0755\tcompiled-binary'
manifest_row /usr/libexec/buzz-ci-acceptance-ctl \
  $'cargo-bin:buzz-ci-acceptance-ctl\t/usr/libexec/buzz-ci-acceptance-ctl\troot\tbuzzci-ctl\t0750\tcompiled-binary'
manifest_row /etc/sudoers.d/buzz-ci-acceptance-ctl \
  $'buzz-ci-acceptance-ctl.sudoers\t/etc/sudoers.d/buzz-ci-acceptance-ctl\troot\troot\t0440\tfile'
manifest_row /etc/buzzci/harness.env \
  $'rendered:harness.env.plan\t/etc/buzzci/harness.env\troot\troot\t0400\trendered-file'
manifest_row /etc/buzzci/qualification-cases \
  $'-\t/etc/buzzci/qualification-cases\troot\troot\t0755\tdirectory'
manifest_row /usr/share/buzzci/substrate/qualification-cases.plan \
  $'qualification-cases.plan\t/usr/share/buzzci/substrate/qualification-cases.plan\troot\troot\t0444\tfile'

awk -F '\t' '
  /^#/ || NF == 0 { next }
  NF != 3 || $1 !~ /^TM-(06|07|1[2-7])$/ || $2 !~ /^[a-z0-9][a-z0-9_-]*$/ \
    || $3 !~ /^(none|teardown_failure)$/ { bad = 1 }
  seen[$1 SUBSEP $2]++ { bad = 1 }
  $3 == "teardown_failure" { teardown++ }
  END { if (bad || teardown != 2 || length(seen) != 35) exit 1 }
' "$case_plan" || fail 'invalid qualification case plan'

grep -Fxq 'ListenStream=/run/buzzci/execd.sock' "$socket"
grep -Fxq 'FileDescriptorName=buzz-ci-execd' "$socket"
grep -Fxq 'Accept=no' "$socket"
grep -Fxq 'SocketUser=buzzci-ctl' "$socket"
grep -Fxq 'SocketGroup=buzzci-ctl' "$socket"
grep -Fxq 'SocketMode=0600' "$socket"
grep -Fxq 'DirectoryMode=0711' "$socket"
grep -Fxq 'Service=buzz-ci-execd.service' "$socket"

grep -Fxq 'User=root' "$service"
grep -Fxq 'Group=root' "$service"
grep -Fxq 'ExecStart=/usr/libexec/buzz-ci-execd --socket-activation' "$service"
if rg -n '^Exec(Start|StartPre|StartPost)=.*(^|[[:space:]])(/bin/)?(ba|d?a|z|k)?sh([[:space:]]|$)' "$service"; then
  fail 'service invokes a shell'
fi
if rg -n '^ExecStart=[^/]' "$service"; then
  fail 'service ExecStart is not absolute'
fi

grep -Fxq 'Defaults!/usr/libexec/buzz-ci-acceptance-ctl env_reset,!setenv' "$sudoers"
grep -Fxq 'root ALL=(buzzci-ctl) NOPASSWD: /usr/libexec/buzz-ci-acceptance-ctl ""' "$sudoers"
[[ $(wc -l <"$sudoers") -eq 2 ]] || fail 'sudoers contains an unexpected rule'
if rg -n '[*?\[\]]|/bin/(ba|d?a|z|k)?sh|[[:space:]]-c([[:space:]]|$)' "$sudoers"; then
  fail 'sudoers contains a wildcard or shell'
fi
if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$sudoers" >/dev/null
fi

expected_keys='BUZZ_CI_ACCEPTANCE_CTL
BUZZ_CI_BROKER_UNIT
BUZZ_CI_EXECD_SOCKET
BUZZ_CI_FIXTURE_REPO
BUZZ_CI_GRAPH_FIXTURE_DIR
BUZZ_CI_GRAPH_REDUCER
BUZZ_CI_HARNESS_SIGNER
BUZZ_CI_LEASE_STATE_ROOT
BUZZ_CI_QUALIFICATION_CASE_ROOT
BUZZ_CI_RUNNER_CTL'
actual_keys=$(awk -F= 'NF && $1 !~ /^#/ { print $1 }' "$harness" | sort)
[[ $actual_keys == "$expected_keys" ]] || fail 'harness key set changed'
grep -Fxq 'BUZZ_CI_ACCEPTANCE_CTL=/usr/libexec/buzz-ci-acceptance-ctl' "$harness"
grep -Fxq 'BUZZ_CI_RUNNER_CTL=/usr/libexec/buzz-ci-runner' "$harness"
grep -Fxq 'BUZZ_CI_QUALIFICATION_CASE_ROOT=/etc/buzzci/qualification-cases' "$harness"
[[ $(awk -F= '$1 == "BUZZ_CI_ACCEPTANCE_CTL" { print $2 }' "$harness") \
    != $(awk -F= '$1 == "BUZZ_CI_RUNNER_CTL" { print $2 }' "$harness") ]] \
  || fail 'qualification and production controls are aliased'

grep -Fqx $'controller\tbuzzci-ctl\t961\t961\t/var/lib/buzzci/principals/ctl\t/usr/sbin/nologin' "$principals"
for job_principal in buzzci-mat-01 buzzci-exec-01 buzzci-run-01; do
  job_row=$(awk -F '\t' -v principal="$job_principal" '$2 == principal { print; count++ } END { if (count != 1) exit 1 }' "$principals") \
    || fail "missing or duplicate job principal: $job_principal"
  [[ $(cut -f3 <<<"$job_row") != 961 && $(cut -f4 <<<"$job_row") != 961 ]] \
    || fail "ordinary job principal crosses control identity: $job_principal"
  ! rg -Fq "$job_principal" "$sudoers" \
    || fail "ordinary job principal received acceptance sudo: $job_principal"
done

for repository_asset in README.md buzz-ci-execd.service buzz-ci-execd.socket \
  buzz-ci-acceptance-ctl.sudoers buzzci-control.tmpfiles harness.env.plan \
  install-manifest.tsv principals.tsv qualification-cases.plan; do
  [[ $(stat -c '%a' "$script_dir/$repository_asset") == 644 ]] \
    || fail "unexpected repository mode: $repository_asset"
done
[[ $(stat -c '%a' "$script_dir/selftest.sh") == 755 ]] \
  || fail 'selftest is not executable'

if rg -n '(^|[;&|[:space:]])(sudo|systemctl|systemd-run|useradd|groupadd|usermod|install|cp|mv|mount)([;&|[:space:]]|$)' \
  "$script_dir" --glob '*.sh' --glob '!selftest.sh'; then
  fail 'host mutation command appeared in executable deployment checks'
fi

printf '{"status":"pass","scope":"static_deployment_contract"}\n'
