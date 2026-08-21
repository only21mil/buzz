#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
manifest=$script_dir/install-manifest.tsv
sudoers=$script_dir/buzz-ci-acceptance-ctl.sudoers
service=$script_dir/buzz-ci-execd.service
socket=$script_dir/buzz-ci-execd.socket
dropin=$script_dir/buzz-ci-execd.service.d/10-host-adapters.conf
tmpfiles=$script_dir/buzzci-control.tmpfiles
harness=$script_dir/harness.env.plan
principals=$script_dir/principals.tsv
case_plan=$script_dir/qualification-cases.plan
authority_plan=$script_dir/authority-v1.json.plan
state_plan=$script_dir/activation-state-v1.json.plan
adapter_plan=$script_dir/host-adapters-v1.json.plan
path_plan=$script_dir/host-paths.plan

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
  END { if (bad || length(seen) != 29) exit 1 }
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
manifest_row /etc/buzzci/authority \
  $'-\t/etc/buzzci/authority\troot\troot\t0700\tdirectory'
manifest_row /etc/buzzci/authority/authority-v1.json \
  $'rendered:authority-v1.json.plan\t/etc/buzzci/authority/authority-v1.json\troot\troot\t0400\trendered-file'
manifest_row /etc/buzzci/authority/host-adapters-v1.json \
  $'rendered:host-adapters-v1.json.plan\t/etc/buzzci/authority/host-adapters-v1.json\troot\troot\t0400\trendered-file'
manifest_row /etc/buzzci/harness.env \
  $'rendered:harness.env.plan\t/etc/buzzci/harness.env\troot\troot\t0400\trendered-file'
manifest_row /etc/buzzci/qualification-cases \
  $'-\t/etc/buzzci/qualification-cases\troot\troot\t0755\tdirectory'
manifest_row /etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf \
  $'buzz-ci-execd.service.d/10-host-adapters.conf\t/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf\troot\troot\t0644\tfile'
manifest_row /etc/sudoers.d/buzz-ci-acceptance-ctl \
  $'buzz-ci-acceptance-ctl.sudoers\t/etc/sudoers.d/buzz-ci-acceptance-ctl\troot\troot\t0440\tfile'
manifest_row /var/lib/buzzci/activation \
  $'-\t/var/lib/buzzci/activation\troot\troot\t0700\tdirectory'
manifest_row /var/lib/buzzci/activation/state-v1.json \
  $'rendered:activation-state-v1.json.plan\t/var/lib/buzzci/activation/state-v1.json\troot\troot\t0600\trendered-file'
manifest_row /var/lib/buzzci/activation/receipts \
  $'-\t/var/lib/buzzci/activation/receipts\troot\troot\t0700\tdirectory'
manifest_row /var/lib/buzzci/leases \
  $'-\t/var/lib/buzzci/leases\troot\troot\t0700\tdirectory'
manifest_row /var/lib/buzzci/seccomp/v1/sha256 \
  $'-\t/var/lib/buzzci/seccomp/v1/sha256\troot\troot\t0700\tdirectory'
manifest_row /var/lib/buzzci/seccomp \
  $'-\t/var/lib/buzzci/seccomp\troot\troot\t0700\tdirectory'
manifest_row /var/lib/buzzci/seccomp/v1 \
  $'-\t/var/lib/buzzci/seccomp/v1\troot\troot\t0700\tdirectory'
manifest_row /run/buzzci \
  $'-\t/run/buzzci\troot\troot\t0711\tdirectory'
manifest_row /run/netns \
  $'-\t/run/netns\troot\troot\t0755\tdirectory'
manifest_row /var/lib/buzzci \
  $'-\t/var/lib/buzzci\troot\troot\t0700\tdirectory'

while IFS=$'\t' read -r source _destination _owner _group _mode _kind; do
  [[ -n $source && ${source:0:1} != '#' ]] || continue
  case $source in
    -|cargo-bin:*) continue ;;
    rendered:*) source=${source#rendered:} ;;
  esac
  [[ -f $script_dir/$source && ! -L $script_dir/$source ]] \
    || fail "manifest source is missing, linked, or not regular: $source"
done <"$manifest"

awk -F '\t' '
  /^#/ || NF == 0 { next }
  NF != 7 { bad = 1; next }
  $1 !~ /^(install|runtime|authority|state|receipt|artifact)$/ { bad = 1 }
  $2 !~ /^\// || $2 ~ /(^|\/)\.\.?($|\/)/ { bad = 1 }
  $3 !~ /^(root|buzzci-ctl)$/ || $4 !~ /^(root|buzzci-ctl)$/ { bad = 1 }
  $5 !~ /^0[0-7]{3}$/ { bad = 1 }
  $6 !~ /^(compiled-binary|directory|unix-socket|immutable-file|atomic-file|packaged-file)$/ { bad = 1 }
  $7 !~ /^(installer|installer-atomic|installer-then-execd|systemd-tmpfiles|systemd|execd|operating-system|execd-atomic)$/ { bad = 1 }
  seen[$2]++ { bad = 1 }
  END { if (bad || length(seen) != 21) exit 1 }
' "$path_plan" || fail 'invalid host path contract'

path_row() {
  local path=$1 expected=$2
  local actual
  actual=$(awk -F '\t' -v path="$path" '$2 == path { print; count++ } END { if (count != 1) exit 1 }' "$path_plan") \
    || fail "missing or duplicate host path: $path"
  [[ $actual == "$expected" ]] || fail "wrong host path contract: $path"
}

path_row /run/buzzci/execd.sock \
  $'runtime\t/run/buzzci/execd.sock\tbuzzci-ctl\tbuzzci-ctl\t0600\tunix-socket\tsystemd'
path_row /run/netns \
  $'runtime\t/run/netns\troot\troot\t0755\tdirectory\tsystemd-tmpfiles'
path_row /var/lib/buzzci \
  $'artifact\t/var/lib/buzzci\troot\troot\t0700\tdirectory\tsystemd-tmpfiles'
path_row /var/lib/buzzci/seccomp \
  $'artifact\t/var/lib/buzzci/seccomp\troot\troot\t0700\tdirectory\tsystemd-tmpfiles'
path_row /var/lib/buzzci/seccomp/v1 \
  $'artifact\t/var/lib/buzzci/seccomp/v1\troot\troot\t0700\tdirectory\tsystemd-tmpfiles'
path_row /var/lib/buzzci/activation/state-v1.json \
  $'state\t/var/lib/buzzci/activation/state-v1.json\troot\troot\t0600\tatomic-file\tinstaller-then-execd'
path_row /var/lib/buzzci/activation/receipts/authority.json \
  $'receipt\t/var/lib/buzzci/activation/receipts/authority.json\troot\troot\t0600\tatomic-file\texecd'
path_row /var/lib/buzzci/activation/receipts/seccomp.json \
  $'receipt\t/var/lib/buzzci/activation/receipts/seccomp.json\troot\troot\t0600\tatomic-file\texecd'
path_row /var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json \
  $'artifact\t/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json\troot\troot\t0444\timmutable-file\texecd-atomic'

jq -e '
  keys == ["ordinary","qualification","revision","root_authority","version"] and
  .version == 1 and
  .revision == 1 and
  .root_authority == "@LOWERCASE_64_HEX_PUBLIC_KEY@" and
  .qualification == null and
  .ordinary == null
' "$authority_plan" >/dev/null || fail 'invalid root authority plan'

jq -e '
  keys == ["activation","active_lease","authority_revision","authority_sha256","committed","last_admission_at","next_lease_generation","nonce_ledger","qualification","revision","state","version"] and
  .version == 1 and
  .revision == 1 and
  .authority_revision == 1 and
  .authority_sha256 == "@LOWERCASE_64_HEX_RENDERED_AUTHORITY_SHA256@" and
  .committed == true and
  .state == "unprovisioned" and
  .qualification == null and
  .activation == null and
  .active_lease == false and
  .nonce_ledger == [] and
  .last_admission_at == null and
  .next_lease_generation == 1
' "$state_plan" >/dev/null || fail 'invalid zero-capacity activation state plan'

jq -e '
  keys == ["activation_state_file","adapter_receipt_root","authority_file","composition_order","default_capacity","lease_state_root","network_namespace_root","qualification_case_root","schema","seccomp_profile","seccomp_sha256","seccomp_source","systemd_resolve_runtime"] and
  .schema == "buzz-ci-host-adapters-v1" and
  .default_capacity == 0 and
  .authority_file == "/etc/buzzci/authority/authority-v1.json" and
  .activation_state_file == "/var/lib/buzzci/activation/state-v1.json" and
  .adapter_receipt_root == "/var/lib/buzzci/activation/receipts" and
  .lease_state_root == "/var/lib/buzzci/leases" and
  .qualification_case_root == "/etc/buzzci/qualification-cases" and
  .network_namespace_root == "/run/netns" and
  .systemd_resolve_runtime == "/run/systemd/resolve" and
  .seccomp_source == "/usr/share/containers/seccomp.json" and
  .seccomp_profile == "/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json" and
  .seccomp_sha256 == "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4" and
  .composition_order == ["authority","durable_state","cleanup_reconcile","seccomp_readback","dns_readback","activation_dispatch"]
' "$adapter_plan" >/dev/null || fail 'invalid host adapter plan'

awk '
  NF == 0 || /^#/ { next }
  NF != 6 || $1 != "d" || $2 !~ /^\// || $2 ~ /(^|\/)\.\.?($|\/)$/ \
    || $3 !~ /^0[0-7]{3}$/ || $4 !~ /^(root|buzzci-ctl)$/ \
    || $5 !~ /^(root|buzzci-ctl)$/ || $6 != "-" { bad = 1 }
  seen[$2]++ { bad = 1 }
  END { if (bad || length(seen) != 13) exit 1 }
' "$tmpfiles" || fail 'invalid tmpfiles contract'
for expected in \
  'd /run/buzzci 0711 root root -' \
  'd /run/netns 0755 root root -' \
  'd /var/lib/buzzci 0700 root root -' \
  'd /var/lib/buzzci/activation 0700 root root -' \
  'd /var/lib/buzzci/activation/receipts 0700 root root -' \
  'd /var/lib/buzzci/activation/receipts/cleanup 0700 root root -' \
  'd /var/lib/buzzci/activation/receipts/dns 0700 root root -' \
  'd /var/lib/buzzci/leases 0700 root root -' \
  'd /var/lib/buzzci/seccomp 0700 root root -' \
  'd /var/lib/buzzci/seccomp/v1 0700 root root -' \
  'd /var/lib/buzzci/seccomp/v1/sha256 0700 root root -'; do
  grep -Fxq "$expected" "$tmpfiles" || fail "missing tmpfiles row: $expected"
done

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
if rg -n '^Exec(Start|StartPre|StartPost)=.*(^|[[:space:]])(/bin/)?(ba|d?a|z|k)?sh([[:space:]]|$)' "$service" "$dropin"; then
  fail 'service composition invokes a shell'
fi
if rg -n '^ExecStart=[^/]' "$service" "$dropin"; then
  fail 'service ExecStart is not absolute'
fi
[[ $(rg -c '^ExecStart=' "$service" "$dropin" | awk -F: '{ total += $NF } END { print total + 0 }') -eq 1 ]] \
  || fail 'service composition does not have one ExecStart'
grep -Fxq 'Requires=systemd-tmpfiles-setup.service' "$dropin"
grep -Fxq 'After=local-fs.target systemd-tmpfiles-setup.service' "$dropin"
grep -Fxq 'RequiresMountsFor=/etc/buzzci/authority /etc/buzzci/qualification-cases /run/netns /var/lib/buzzci/activation /var/lib/buzzci/leases /var/lib/buzzci/seccomp/v1/sha256' "$dropin"
grep -Fxq 'ReadOnlyPaths=/etc/buzzci/authority /etc/buzzci/qualification-cases /usr/share/containers/seccomp.json' "$dropin"
grep -Fxq 'ReadWritePaths=' "$dropin"
grep -Fxq 'ReadWritePaths=/run/buzzci /run/netns /var/lib/buzzci/activation /var/lib/buzzci/leases /var/lib/buzzci/seccomp/v1/sha256' "$dropin"
if rg -n '^(Exec|User|Group|SupplementaryGroups|Sockets)=' "$dropin"; then
  fail 'host adapter drop-in adds a process or principal'
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

repo_root=$(git -C "$script_dir" rev-parse --show-toplevel) \
  || fail 'cannot resolve repository root for index-mode checks'
index_mode() {
  local relative=${1#"$repo_root/"}
  git -C "$repo_root" ls-files -s -- "$relative" \
    | awk 'NR == 1 { mode = $1 } END { if (NR != 1) exit 1; print mode }'
}
while IFS= read -r repository_asset; do
  [[ $(index_mode "$repository_asset") == 100644 ]] \
    || fail "unexpected repository index mode: ${repository_asset#"$script_dir/"}"
done < <(find "$script_dir" -type f ! -name selftest.sh -print | sort)
[[ $(index_mode "$script_dir/selftest.sh") == 100755 ]] \
  || fail 'selftest is not executable in the repository index'

if rg -n '(^|[;&|[:space:]])(sudo|systemctl|systemd-run|useradd|groupadd|usermod|install|cp|mv|mount)([;&|[:space:]]|$)' \
  "$script_dir" --glob '*.sh' --glob '!selftest.sh'; then
  fail 'host mutation command appeared in executable deployment assets'
fi

printf '{"status":"pass","scope":"static_host_adapter_contract","capacity":0}\n'
