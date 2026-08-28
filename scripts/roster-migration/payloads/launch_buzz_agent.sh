#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

if (($# != 1)); then
  printf 'usage: %s sats-codex|sats-codex-2|sats-codex-r|sats-claude-code|sats-claude-code-r|sats-glm|sats-dsv4f|sats-glm52|alpheus-claude-code|alpheus-codex\n' "$0" >&2
  exit 2
fi

readonly slug=$1
readonly secret_file=/home/victor/.config/sats/secrets.env
readonly secret_dir=${secret_file%/*}
readonly buzz_acp=/home/victor/work/buzz-agents/bin/buzz-acp
readonly buzz_acp_sha256=1131489bba3ed06f0e92a1ba08d83db4a287f6e2836b603e4bc9445948eb5d7f
readonly expected_owner=victor
readonly owner_pubkey=4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d
readonly sats_codex_wrapper=/home/victor/bin/codex-sats-codex
readonly sats_codex_wrapper_sha256=8741c95e0932a061d6afe711ad43daa716b7b8dcce940d980724e60b89ad6cc5
readonly sats_codex_r_activation_marker_dir=/home/victor/.local/state/sats-codex-r
readonly sats_codex_r_activation_marker=${sats_codex_r_activation_marker_dir}/ACTIVATION_APPROVED
readonly sats_codex_r_home=/home/victor/work/buzz-agents/sats-codex-r/home
readonly sats_codex_r_codex_home=${sats_codex_r_home}/.codex
readonly sats_codex_r_xdg_config_home=${sats_codex_r_home}/.config
readonly sats_codex_r_xdg_cache_home=${sats_codex_r_home}/.cache
readonly sats_codex_r_xdg_local_home=${sats_codex_r_home}/.local
readonly sats_codex_r_xdg_data_home=${sats_codex_r_xdg_local_home}/share
readonly sats_codex_r_xdg_state_home=${sats_codex_r_xdg_local_home}/state
readonly sats_codex_r_wrapper=/home/victor/bin/codex-sats-codex-r
readonly sats_codex_r_wrapper_sha256=b2e0839cbf25ce257ab35a904e744cdfc1bc3a815220832995bf8b943781be39
readonly sats_codex_2_activation_marker_dir=/home/victor/.local/state/sats-codex-2
readonly sats_codex_2_activation_marker=${sats_codex_2_activation_marker_dir}/ACTIVATION_APPROVED
readonly sats_codex_2_home=/home/victor/work/buzz-agents/sats-codex-2/home
readonly sats_codex_2_codex_home=${sats_codex_2_home}/.codex
readonly sats_codex_2_auth=${sats_codex_2_codex_home}/auth.json
readonly sats_codex_2_xdg_config_home=${sats_codex_2_home}/.config
readonly sats_codex_2_xdg_cache_home=${sats_codex_2_home}/.cache
readonly sats_codex_2_xdg_local_home=${sats_codex_2_home}/.local
readonly sats_codex_2_xdg_data_home=${sats_codex_2_xdg_local_home}/share
readonly sats_codex_2_xdg_state_home=${sats_codex_2_xdg_local_home}/state
readonly sats_codex_2_wrapper=/home/victor/bin/codex-sats-codex-2
readonly sats_codex_2_wrapper_sha256=6b82aea37e78341f954db48426238d5934be5004b2c779fc296fe7c06c6f081c
readonly sats_claude_code_r_home=/home/victor/work/buzz-agents/sats-claude-code-r/home
readonly sats_claude_code_r_claude_config=${sats_claude_code_r_home}/.claude
readonly sats_claude_code_r_credentials=${sats_claude_code_r_claude_config}/.credentials.json
readonly sats_glm_home=/home/victor/work/buzz-agents/sats-glm/home
readonly sats_glm_claude_config=${sats_glm_home}/.claude
readonly sats_glm_proxy_config=/home/victor/.config/sats-glm/cliproxyapi.yaml
readonly sats_glm_proxy_unit=/home/victor/.config/systemd/user/sats-glm-proxy.service
readonly sats_dsv4f_home=/home/victor/work/buzz-agents/sats-dsv4f/home
readonly sats_dsv4f_claude_config=${sats_dsv4f_home}/.claude
readonly sats_dsv4f_proxy_config=/home/victor/.config/sats-dsv4f/cliproxyapi.yaml
readonly sats_dsv4f_proxy_unit=/home/victor/.config/systemd/user/sats-dsv4f-proxy.service
readonly sats_glm52_home=/home/victor/work/buzz-agents/sats-glm52/home
readonly sats_glm52_claude_config=${sats_glm52_home}/.claude
readonly sats_glm52_proxy_config=/home/victor/.config/sats-glm52/cliproxyapi.yaml
readonly sats_glm52_proxy_unit=/home/victor/.config/systemd/user/sats-glm52-proxy.service
# Alpheus seats (Mason's agents, Victor-hosted). Workdir and memory scope are
# the fail-closed Alpheus space, never the Sats/Victor canon.
readonly mason_pubkey=1a536702f3eb8db5cd9cbb661cc2bdbf863ff011ddf2fc652309e1c225fd8a19
readonly alpheus_workdir=/home/victor/work/alpheus/Agent-Shared
readonly alpheus_claude_home=/home/victor/work/buzz-agents/alpheus-claude-code/home
readonly alpheus_claude_config=${alpheus_claude_home}/.claude
readonly alpheus_claude_credentials=${alpheus_claude_config}/.credentials.json
readonly alpheus_codex_home=/home/victor/work/buzz-agents/alpheus-codex/home
readonly alpheus_codex_codex_home=${alpheus_codex_home}/.codex
readonly alpheus_codex_auth=${alpheus_codex_codex_home}/auth.json
readonly alpheus_codex_wrapper=/home/victor/bin/codex-alpheus-codex
readonly alpheus_codex_wrapper_sha256=0be9519e0d9ccf50dab98c7f0b05519948e627c991401c26b0f0be9513a9b879

fail() {
  printf 'Buzz agent launch blocked: %s\n' "$1" >&2
  exit 1
}

validate_trusted_directory() {
  local directory=$1
  local canonical

  [[ -d ${directory} && ! -L ${directory} ]] || fail "trusted directory is missing or a symlink: ${directory}"
  canonical=$(/usr/bin/readlink -e -- "${directory}") || fail "cannot resolve trusted directory: ${directory}"
  [[ ${canonical} == "${directory}" && \
    $(/usr/bin/stat -c '%U:%G' -- "${directory}") == victor:victor && \
    $(/usr/bin/stat -c %a -- "${directory}") == 700 && \
    -w ${directory} && -x ${directory} ]] || fail "trusted directory has unsafe identity, ownership, mode, or access: ${directory}"
}

validate_trusted_directory /home/victor/.cache/tmp

if [[ ${slug} == sats-codex-r ]]; then
  validate_trusted_directory "${sats_codex_r_activation_marker_dir}"
  [[ -f ${sats_codex_r_activation_marker} && ! -L ${sats_codex_r_activation_marker} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_r_activation_marker}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_codex_r_activation_marker}") == 600 ]] || \
    fail 'Sats Codex-R activation is not approved'
  /usr/bin/cmp -s -- "${sats_codex_r_activation_marker}" <(printf '%s\n' ACTIVATION_APPROVED) || \
    fail 'Sats Codex-R activation is not approved'
fi

if [[ ${slug} == sats-codex-2 ]]; then
  validate_trusted_directory "${sats_codex_2_activation_marker_dir}"
  [[ -f ${sats_codex_2_activation_marker} && ! -L ${sats_codex_2_activation_marker} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_2_activation_marker}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_codex_2_activation_marker}") == 600 ]] || \
    fail 'Sats Codex-2 activation is not approved'
  /usr/bin/cmp -s -- "${sats_codex_2_activation_marker}" <(printf '%s\n' ACTIVATION_APPROVED) || \
    fail 'Sats Codex-2 activation is not approved'
fi

[[ -d ${secret_dir} && ! -L ${secret_dir} && $(/usr/bin/stat -c %a -- "${secret_dir}") == 700 ]] || \
  fail 'sanctioned secrets directory is missing, a symlink, or not mode 0700'
[[ -f ${secret_file} && ! -L ${secret_file} && -r ${secret_file} && \
  $(/usr/bin/stat -c %U -- "${secret_file}") == "${expected_owner}" && \
  $(/usr/bin/stat -c %a -- "${secret_file}") == 600 ]] || \
  fail 'sanctioned secrets file is missing, a symlink, unreadable, not owned by victor, or not mode 0600'

# shellcheck disable=SC1090
. "${secret_file}"

responder_pubkey=
if [[ ${slug} != sats-codex-r ]]; then
  responder_pubkey=${BUZZ_RACHEL_RESPONDER_PUBKEY:-}
  [[ ${responder_pubkey} =~ ^[0-9a-f]{64}$ ]] || {
    printf 'Rachel responder public key is missing or invalid\n' >&2
    exit 1
  }
fi

runtime_home=/home/victor
workdir=/home/victor/Obsidian/Victor/Agent-Shared
agent_owner=${owner_pubkey}
respond_to=allowlist
# `mentions` wakes a seat only on an explicit p-tag; `all` also delivers ordinary
# thread replies and tag-less DMs, at the cost of waking on every admitted
# author's traffic in every member channel.
subscribe=mentions
# Seat concurrency pool: how many model subprocesses buzz-acp runs at once
# (parallel wakeups). Not related to child-agent fan-out inside a session.
agents=1
# Rachel and Mason may both address the Sats seats (Victor, 2026-08-15). Reachability
# only: the harness forwards their events, and each seat's system prompt still decides
# what their requests authorize. Victor remains the sole approver for gated actions.
respond_to_allowlist=${responder_pubkey},${mason_pubkey}
allowed_respond_to=owner-only,allowlist

case "${slug}" in
  sats-codex)
    private_key=${BUZZ_SATS_CODEX_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_CODEX_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/codex-acp
    mcp_command=/home/victor/work/buzz-agents/bin/buzz-dev-mcp
    runtime_env=(
      "CODEX_PATH=${sats_codex_wrapper}"
      'CODEX_CONFIG={"model":"gpt-5.6-sol","model_reasoning_effort":"high"}'
    )
    model='gpt-5.6-sol[high]'
    session_title='Sats Codex · GPT-5.6 Sol high'
    system_prompt=/home/victor/.config/buzz/agents/sats-codex-system.md
    system_prompt_sha256=0a8ed14ed7fb15d832ca9c20486af8493c516d7ba51559bd27d89bce065bce21
    ;;
  sats-codex-2)
    private_key=${BUZZ_SATS_CODEX2_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_CODEX2_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/codex-acp
    mcp_command=/home/victor/work/buzz-agents/bin/buzz-dev-mcp
    runtime_home=${sats_codex_2_home}
    runtime_env=(
      "CODEX_HOME=${sats_codex_2_codex_home}"
      "XDG_CONFIG_HOME=${sats_codex_2_xdg_config_home}"
      "XDG_CACHE_HOME=${sats_codex_2_xdg_cache_home}"
      "XDG_DATA_HOME=${sats_codex_2_xdg_data_home}"
      "XDG_STATE_HOME=${sats_codex_2_xdg_state_home}"
      "CODEX_PATH=${sats_codex_2_wrapper}"
      'CODEX_CONFIG={"model":"gpt-5.6-sol","model_reasoning_effort":"high"}'
    )
    model='gpt-5.6-sol[high]'
    session_title='UTXO · GPT-5.6 Sol high'
    system_prompt=/home/victor/.config/buzz/agents/sats-codex-2-system.md
    system_prompt_sha256=62cbb90fb39e95eaa8cbc6008e117c9cc76fbed98955c75ef153d12c117fbd28
    ;;
  sats-codex-r)
    private_key=${BUZZ_SATS_CODEX_R_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_CODEX_R_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/codex-acp
    mcp_command=/home/victor/work/buzz-agents/bin/buzz-dev-mcp
    runtime_home=${sats_codex_r_home}
    runtime_env=(
      "CODEX_HOME=${sats_codex_r_codex_home}"
      "XDG_CONFIG_HOME=${sats_codex_r_xdg_config_home}"
      "XDG_CACHE_HOME=${sats_codex_r_xdg_cache_home}"
      "XDG_DATA_HOME=${sats_codex_r_xdg_data_home}"
      "XDG_STATE_HOME=${sats_codex_r_xdg_state_home}"
      "CODEX_PATH=${sats_codex_r_wrapper}"
      'CODEX_CONFIG={"model":"gpt-5.6-sol","model_reasoning_effort":"high"}'
    )
    model='gpt-5.6-sol[high]'
    session_title='Sats Codex-R · GPT-5.6 Sol high'
    system_prompt=/home/victor/.config/buzz/agents/sats-codex-r-system.md
    system_prompt_sha256=0a69ecc6359270f1c95a460c75566a76834a616e4dd65a491c3b259748da04a8
    respond_to=owner-only
    respond_to_allowlist=
    allowed_respond_to=owner-only
    ;;
  sats-claude-code|sats-claude-code-r)
    fail 'Sats Claude Code and Sats Claude Code-R are retired and have no orchestration or review route'
    ;;
  sats-glm)
    private_key=${BUZZ_SATS_GLM_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_GLM_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/claude-agent-acp
    mcp_command=
    runtime_home=${sats_glm_home}
    runtime_env=(
      "CLAUDE_CONFIG_DIR=${sats_glm_claude_config}"
      "XDG_CONFIG_HOME=${sats_glm_home}/.config"
      "XDG_CACHE_HOME=${sats_glm_home}/.cache"
      "XDG_DATA_HOME=${sats_glm_home}/.local/share"
      "XDG_STATE_HOME=${sats_glm_home}/.local/state"
      CLAUDE_CODE_EXECUTABLE=/home/victor/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
      ANTHROPIC_BASE_URL=http://127.0.0.1:8327
      "ANTHROPIC_AUTH_TOKEN=${BUZZ_SATS_GLM_PROXY_TOKEN:-}"
      # This loopback proxy serves GLM 5.3 Flash only and has no Anthropic
      # provider, so a Claude model id fails. Pin every selector this build
      # reads to its alias.
      ANTHROPIC_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_OPUS_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_SONNET_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_HAIKU_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_FABLE_MODEL=glm53-flash-max
      ANTHROPIC_SMALL_FAST_MODEL=glm53-flash-max
      CLAUDE_CODE_SUBAGENT_MODEL=glm53-flash-max
      CLAUDE_CONTEXT_COLLAPSE_MODEL=glm53-flash-max
      CLAUDE_CODE_AUTO_MODE_MODEL=glm53-flash-max
      CLAUDE_CODE_BG_CLASSIFIER_MODEL=glm53-flash-max
      # Receiver-side kind allowlist (RCA 2026-08-21, Sats Codex freeze): under
      # subscribe=all the wildcard accepted kind-20002 typing pings as agent
      # input. Keep messages, reminders, and workflow approvals; drop
      # typing/presence/reactions before queueing.
      "BUZZ_ACP_KINDS=9,40002,40007,46010"
      # Trimmed from the default 12 (Victor, 2026-08-21 cost review): halves
      # the re-read context per wakeup.
      BUZZ_ACP_CONTEXT_MESSAGE_LIMIT=6
      # OpenRouter caps GLM 5.3 Flash at 1048576 tokens on the selected route.
      CLAUDE_CODE_DISABLE_1M_CONTEXT=1
      CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000
      CLAUDE_CODE_MAX_CONTEXT_TOKENS=1048576
      CLAUDE_AUTOCOMPACT_PCT_OVERRIDE=85
    )
    model='glm53-flash-max'
    session_title='Segwit · GLM 5.3 Flash max'
    system_prompt=/home/victor/.config/buzz/agents/sats-glm-system.md
    system_prompt_sha256=c7177f33e2b6f1a05f98478c40cffce9d1b258fd224ac39ee8eb37f8d69f054f
    # 2026-08-21 ~19:33Z (Victor, cost review): all-replies trial ended, back
    # to the fleet-default mentions wake. Known trade on the pinned binary:
    # untagged thread replies and tagless Desktop DMs no longer wake this seat
    # (the DM fix lives only on the buzz-dm-fix branch). Kinds allowlist kept
    # above as defense in depth if anyone flips subscribe back to all.
    # Victor wants 18 parallel wakeups on this seat (2026-08-21, thread
    # 668dc541): 18 children inside a session already worked at agents=1.
    agents=18
    ;;
  sats-dsv4f)
    private_key=${BUZZ_SATS_DSV4F_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_DSV4F_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/claude-agent-acp
    mcp_command=
    runtime_home=${sats_dsv4f_home}
    runtime_env=(
      "CLAUDE_CONFIG_DIR=${sats_dsv4f_claude_config}"
      "XDG_CONFIG_HOME=${sats_dsv4f_home}/.config"
      "XDG_CACHE_HOME=${sats_dsv4f_home}/.cache"
      "XDG_DATA_HOME=${sats_dsv4f_home}/.local/share"
      "XDG_STATE_HOME=${sats_dsv4f_home}/.local/state"
      CLAUDE_CODE_EXECUTABLE=/home/victor/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
      ANTHROPIC_BASE_URL=http://127.0.0.1:8328
      "ANTHROPIC_AUTH_TOKEN=${BUZZ_SATS_DSV4F_PROXY_TOKEN:-}"
      # This loopback proxy serves Qwen 3.8 Flash only and has no Anthropic
      # provider, so a Claude model id fails. Pin every selector this build
      # reads to its alias.
      ANTHROPIC_MODEL=qwen38-flash
      ANTHROPIC_DEFAULT_OPUS_MODEL=qwen38-flash
      ANTHROPIC_DEFAULT_SONNET_MODEL=qwen38-flash
      ANTHROPIC_DEFAULT_HAIKU_MODEL=qwen38-flash
      ANTHROPIC_DEFAULT_FABLE_MODEL=qwen38-flash
      ANTHROPIC_SMALL_FAST_MODEL=qwen38-flash
      CLAUDE_CODE_SUBAGENT_MODEL=qwen38-flash
      CLAUDE_CONTEXT_COLLAPSE_MODEL=qwen38-flash
      CLAUDE_CODE_AUTO_MODE_MODEL=qwen38-flash
      CLAUDE_CODE_BG_CLASSIFIER_MODEL=qwen38-flash
      # Receiver-side kind allowlist (RCA 2026-08-21, Sats Codex freeze): under
      # subscribe=all the wildcard accepted kind-20002 typing pings as agent
      # input. Keep messages, reminders, and workflow approvals; drop
      # typing/presence/reactions before queueing.
      "BUZZ_ACP_KINDS=9,40002,40007,46010"
      # Trimmed from the default 12 (Victor, 2026-08-21 cost review): halves
      # the re-read context per wakeup.
      BUZZ_ACP_CONTEXT_MESSAGE_LIMIT=6
      # Qwen 3.8 Flash has a 1000000-token context window on OpenRouter.
      CLAUDE_CODE_DISABLE_1M_CONTEXT=1
      CLAUDE_CODE_AUTO_COMPACT_WINDOW=950000
      CLAUDE_CODE_MAX_CONTEXT_TOKENS=1000000
      CLAUDE_AUTOCOMPACT_PCT_OVERRIDE=85
    )
    model='qwen38-flash'
    session_title='Knots · Qwen 3.8 Flash'
    system_prompt=/home/victor/.config/buzz/agents/sats-dsv4f-system.md
    system_prompt_sha256=356283c2760baba950654ef92e483cc87c86c97c7c2b42d7deef9a2c1f60c36f
    # Fleet-default mentions wake; same known trade as the sats-glm seat on
    # the pinned binary (untagged thread replies and tagless Desktop DMs do
    # not wake this seat). Victor wants 18 parallel wakeups here (2026-08-21
    # seat build, cloned from the Sats GLM seat pattern).
    agents=18
    ;;
  sats-glm52)
    private_key=${BUZZ_SATS_GLM52_PRIVATE_KEY:-}
    auth_tag=${BUZZ_SATS_GLM52_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/claude-agent-acp
    mcp_command=
    runtime_home=${sats_glm52_home}
    runtime_env=(
      "CLAUDE_CONFIG_DIR=${sats_glm52_claude_config}"
      "XDG_CONFIG_HOME=${sats_glm52_home}/.config"
      "XDG_CACHE_HOME=${sats_glm52_home}/.cache"
      "XDG_DATA_HOME=${sats_glm52_home}/.local/share"
      "XDG_STATE_HOME=${sats_glm52_home}/.local/state"
      CLAUDE_CODE_EXECUTABLE=/home/victor/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
      ANTHROPIC_BASE_URL=http://127.0.0.1:8329
      "ANTHROPIC_AUTH_TOKEN=${BUZZ_SATS_GLM52_PROXY_TOKEN:-}"
      # This loopback proxy serves GLM 5.3 Flash only and has no Anthropic
      # provider, so a Claude model id fails. Pin every selector this build
      # reads to its alias.
      ANTHROPIC_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_OPUS_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_SONNET_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_HAIKU_MODEL=glm53-flash-max
      ANTHROPIC_DEFAULT_FABLE_MODEL=glm53-flash-max
      ANTHROPIC_SMALL_FAST_MODEL=glm53-flash-max
      CLAUDE_CODE_SUBAGENT_MODEL=glm53-flash-max
      CLAUDE_CONTEXT_COLLAPSE_MODEL=glm53-flash-max
      CLAUDE_CODE_AUTO_MODE_MODEL=glm53-flash-max
      CLAUDE_CODE_BG_CLASSIFIER_MODEL=glm53-flash-max
      # Receiver-side kind allowlist (RCA 2026-08-21, Sats Codex freeze): under
      # subscribe=all the wildcard accepted kind-20002 typing pings as agent
      # input. Keep messages, reminders, and workflow approvals; drop
      # typing/presence/reactions before queueing.
      "BUZZ_ACP_KINDS=9,40002,40007,46010"
      # Trimmed from the default 12 (Victor, 2026-08-21 cost review): halves
      # the re-read context per wakeup.
      BUZZ_ACP_CONTEXT_MESSAGE_LIMIT=6
      # OpenRouter caps GLM 5.3 Flash at 1048576 tokens on the selected route.
      CLAUDE_CODE_DISABLE_1M_CONTEXT=1
      CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000
      CLAUDE_CODE_MAX_CONTEXT_TOKENS=1048576
      CLAUDE_AUTOCOMPACT_PCT_OVERRIDE=85
    )
    model='glm53-flash-max'
    session_title='Ledger · GLM 5.3 Flash max'
    system_prompt=/home/victor/.config/buzz/agents/sats-glm52-system.md
    system_prompt_sha256=73a0a6bcc3597f6a3157d9cab9fbcae126fe449bc7c6cf48262d9361cba87959
    # Fleet-default mentions wake; same known trade as the sats-glm seat on
    # the pinned binary (untagged thread replies and tagless Desktop DMs do
    # not wake this seat). Victor wants 18 parallel wakeups here (2026-08-21
    # seat build, cloned from the Sats GLM seat pattern).
    agents=18
    ;;
  alpheus-claude-code)
    private_key=${BUZZ_ALPHEUS_CLAUDE_PRIVATE_KEY:-}
    auth_tag=${BUZZ_ALPHEUS_CLAUDE_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/claude-agent-acp
    mcp_command=
    runtime_home=${alpheus_claude_home}
    workdir=${alpheus_workdir}
    # Mason's Anthropic subscription: credentials live only in this isolated
    # CLAUDE_CONFIG_DIR, never in /home/victor/.claude.
    runtime_env=(
      "CLAUDE_CONFIG_DIR=${alpheus_claude_config}"
      "XDG_CONFIG_HOME=${alpheus_claude_home}/.config"
      "XDG_CACHE_HOME=${alpheus_claude_home}/.cache"
      "XDG_DATA_HOME=${alpheus_claude_home}/.local/share"
      "XDG_STATE_HOME=${alpheus_claude_home}/.local/state"
      'ANTHROPIC_MODEL=claude-fable-5[1m]'
      CLAUDE_CODE_EXECUTABLE=/home/victor/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
    )
    model='claude-fable-5[1m]'
    session_title='Alpheus Claude Code · Fable 5 high'
    system_prompt=/home/victor/.config/buzz/agents/alpheus-claude-code-system.md
    system_prompt_sha256=e7df68e8b0bbfca5a6dc29267c6495ceca4c0b290b1f2269396f3b944a7eae33
    # Mason manages this seat (Victor, 2026-08-15). The relay DB owner link is
    # Mason; the harness owner stays Victor because buzz-acp resolves the owner
    # from the Victor-signed attestation regardless of env. Mason is reachable
    # via this allowlist, Victor via attestation ownership.
    respond_to_allowlist=${mason_pubkey}
    ;;
  alpheus-codex)
    private_key=${BUZZ_ALPHEUS_CODEX_PRIVATE_KEY:-}
    auth_tag=${BUZZ_ALPHEUS_CODEX_AUTH_TAG:-}
    agent_command=/home/victor/.npm-global/bin/codex-acp
    mcp_command=/home/victor/work/buzz-agents/bin/buzz-dev-mcp
    runtime_home=${alpheus_codex_home}
    workdir=${alpheus_workdir}
    runtime_env=(
      "CODEX_HOME=${alpheus_codex_codex_home}"
      "XDG_CONFIG_HOME=${alpheus_codex_home}/.config"
      "XDG_CACHE_HOME=${alpheus_codex_home}/.cache"
      "XDG_DATA_HOME=${alpheus_codex_home}/.local/share"
      "XDG_STATE_HOME=${alpheus_codex_home}/.local/state"
      "CODEX_PATH=${alpheus_codex_wrapper}"
      'CODEX_CONFIG={"model":"gpt-5.6-sol","model_reasoning_effort":"high"}'
    )
    model='gpt-5.6-sol[high]'
    session_title='Alpheus Codex · GPT-5.6 Sol high'
    system_prompt=/home/victor/.config/buzz/agents/alpheus-codex-system.md
    system_prompt_sha256=184427261b7822eab5242b816176eb79ae3bc618b2b2755b88f9b8258aa986c4
    # Mason manages this seat (Victor, 2026-08-15). The relay DB owner link is
    # Mason; the harness owner stays Victor because buzz-acp resolves the owner
    # from the Victor-signed attestation regardless of env. Mason is reachable
    # via this allowlist, Victor via attestation ownership.
    respond_to_allowlist=${mason_pubkey}
    ;;
  *)
    printf 'unknown Buzz agent slug: %s\n' "${slug}" >&2
    exit 2
    ;;
esac

if [[ ${slug} == sats-codex ]]; then
  [[ -f ${sats_codex_wrapper} && ! -L ${sats_codex_wrapper} && \
    -x ${sats_codex_wrapper} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_wrapper}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_codex_wrapper}") == 700 ]] || \
    fail 'Sats Codex wrapper is missing or unsafe'
  actual_sats_codex_wrapper_sha256=
  read -r actual_sats_codex_wrapper_sha256 _ < <(/usr/bin/sha256sum -- "${sats_codex_wrapper}") || \
    fail 'cannot hash pinned Sats Codex wrapper'
  [[ ${actual_sats_codex_wrapper_sha256} == "${sats_codex_wrapper_sha256}" ]] || \
    fail 'pinned Sats Codex wrapper digest mismatch'
  unset actual_sats_codex_wrapper_sha256
fi

if [[ ${slug} == sats-codex-2 ]]; then
  for runtime_dir in \
    "${sats_codex_2_home}" \
    "${sats_codex_2_codex_home}" \
    "${sats_codex_2_xdg_config_home}" \
    "${sats_codex_2_xdg_cache_home}" \
    "${sats_codex_2_xdg_local_home}" \
    "${sats_codex_2_xdg_data_home}" \
    "${sats_codex_2_xdg_state_home}"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats Codex-2 runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${sats_codex_2_wrapper} && ! -L ${sats_codex_2_wrapper} && \
    -x ${sats_codex_2_wrapper} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_2_wrapper}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_codex_2_wrapper}") == 700 ]] || \
    fail 'Sats Codex-2 wrapper is missing or unsafe'
  actual_sats_codex_2_wrapper_sha256=
  read -r actual_sats_codex_2_wrapper_sha256 _ < <(/usr/bin/sha256sum -- "${sats_codex_2_wrapper}") || \
    fail 'cannot hash pinned Sats Codex-2 wrapper'
  [[ ${actual_sats_codex_2_wrapper_sha256} == "${sats_codex_2_wrapper_sha256}" ]] || \
    fail 'pinned Sats Codex-2 wrapper digest mismatch'
  unset actual_sats_codex_2_wrapper_sha256
  [[ -f ${sats_codex_2_auth} && ! -L ${sats_codex_2_auth} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_2_auth}") == "${expected_owner}" ]] || \
    fail 'Sats Codex-2 has no OpenAI login: run HOME=/home/victor/work/buzz-agents/sats-codex-2/home CODEX_HOME=/home/victor/work/buzz-agents/sats-codex-2/home/.codex /home/victor/bin/codex login'
fi

if [[ ${slug} == sats-codex-r ]]; then
  for runtime_dir in \
    "${sats_codex_r_home}" \
    "${sats_codex_r_codex_home}" \
    "${sats_codex_r_xdg_config_home}" \
    "${sats_codex_r_xdg_cache_home}" \
    "${sats_codex_r_xdg_local_home}" \
    "${sats_codex_r_xdg_data_home}" \
    "${sats_codex_r_xdg_state_home}"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats Codex-R runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${sats_codex_r_wrapper} && ! -L ${sats_codex_r_wrapper} && \
    -x ${sats_codex_r_wrapper} && \
    $(/usr/bin/stat -c %U -- "${sats_codex_r_wrapper}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_codex_r_wrapper}") == 700 ]] || \
    fail 'Sats Codex-R wrapper is missing or unsafe'
  actual_sats_codex_r_wrapper_sha256=
  read -r actual_sats_codex_r_wrapper_sha256 _ < <(/usr/bin/sha256sum -- "${sats_codex_r_wrapper}") || \
    fail 'cannot hash pinned Sats Codex-R wrapper'
  [[ ${actual_sats_codex_r_wrapper_sha256} == "${sats_codex_r_wrapper_sha256}" ]] || \
    fail 'pinned Sats Codex-R wrapper digest mismatch'
  unset actual_sats_codex_r_wrapper_sha256
fi

if [[ ${slug} == sats-claude-code-r ]]; then
  for runtime_dir in \
    "${sats_claude_code_r_home}" \
    "${sats_claude_code_r_claude_config}" \
    "${sats_claude_code_r_home}/.config" \
    "${sats_claude_code_r_home}/.cache" \
    "${sats_claude_code_r_home}/.local" \
    "${sats_claude_code_r_home}/.local/share" \
    "${sats_claude_code_r_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats Claude Code-R runtime directory is missing or unsafe: ${runtime_dir}"
  done
  # Fail closed until Victor has logged this seat's isolated CLAUDE_CONFIG_DIR
  # into its own Anthropic subscription.
  [[ -f ${sats_claude_code_r_credentials} && ! -L ${sats_claude_code_r_credentials} && \
    $(/usr/bin/stat -c %U -- "${sats_claude_code_r_credentials}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_claude_code_r_credentials}") == 600 ]] || \
    fail 'Sats Claude Code-R has no Anthropic login: run CLAUDE_CONFIG_DIR=/home/victor/work/buzz-agents/sats-claude-code-r/home/.claude claude and /login'
fi

if [[ ${slug} == sats-glm ]]; then
  for runtime_dir in \
    "${sats_glm_home}" \
    "${sats_glm_claude_config}" \
    "${sats_glm_home}/.config" \
    "${sats_glm_home}/.cache" \
    "${sats_glm_home}/.local" \
    "${sats_glm_home}/.local/share" \
    "${sats_glm_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats GLM runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${sats_glm_proxy_config} && ! -L ${sats_glm_proxy_config} && \
    $(/usr/bin/stat -c %U -- "${sats_glm_proxy_config}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_glm_proxy_config}") == 600 ]] || \
    fail 'Sats GLM proxy config is missing or unsafe'
  [[ -f ${sats_glm_proxy_unit} && ! -L ${sats_glm_proxy_unit} && \
    $(/usr/bin/stat -c %U -- "${sats_glm_proxy_unit}") == "${expected_owner}" ]] || \
    fail 'Sats GLM proxy unit is missing'
  ! /usr/bin/grep -Fq -- PLACEHOLDER "${sats_glm_proxy_config}" || \
    fail 'Sats GLM proxy config still contains placeholder credentials'
  [[ -n ${BUZZ_SATS_GLM_PROXY_TOKEN:-} ]] || \
    fail 'Sats GLM proxy token is missing from the sanctioned secrets store'
fi

if [[ ${slug} == sats-dsv4f ]]; then
  for runtime_dir in \
    "${sats_dsv4f_home}" \
    "${sats_dsv4f_claude_config}" \
    "${sats_dsv4f_home}/.config" \
    "${sats_dsv4f_home}/.cache" \
    "${sats_dsv4f_home}/.local" \
    "${sats_dsv4f_home}/.local/share" \
    "${sats_dsv4f_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats DSV4F runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${sats_dsv4f_proxy_config} && ! -L ${sats_dsv4f_proxy_config} && \
    $(/usr/bin/stat -c %U -- "${sats_dsv4f_proxy_config}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_dsv4f_proxy_config}") == 600 ]] || \
    fail 'Sats DSV4F proxy config is missing or unsafe'
  [[ -f ${sats_dsv4f_proxy_unit} && ! -L ${sats_dsv4f_proxy_unit} && \
    $(/usr/bin/stat -c %U -- "${sats_dsv4f_proxy_unit}") == "${expected_owner}" ]] || \
    fail 'Sats DSV4F proxy unit is missing'
  ! /usr/bin/grep -Fq -- PLACEHOLDER "${sats_dsv4f_proxy_config}" || \
    fail 'Sats DSV4F proxy config still contains placeholder credentials'
  [[ -n ${BUZZ_SATS_DSV4F_PROXY_TOKEN:-} ]] || \
    fail 'Sats DSV4F proxy token is missing from the sanctioned secrets store'
fi

if [[ ${slug} == sats-glm52 ]]; then
  for runtime_dir in \
    "${sats_glm52_home}" \
    "${sats_glm52_claude_config}" \
    "${sats_glm52_home}/.config" \
    "${sats_glm52_home}/.cache" \
    "${sats_glm52_home}/.local" \
    "${sats_glm52_home}/.local/share" \
    "${sats_glm52_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Sats GLM5.2 runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${sats_glm52_proxy_config} && ! -L ${sats_glm52_proxy_config} && \
    $(/usr/bin/stat -c %U -- "${sats_glm52_proxy_config}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${sats_glm52_proxy_config}") == 600 ]] || \
    fail 'Sats GLM5.2 proxy config is missing or unsafe'
  [[ -f ${sats_glm52_proxy_unit} && ! -L ${sats_glm52_proxy_unit} && \
    $(/usr/bin/stat -c %U -- "${sats_glm52_proxy_unit}") == "${expected_owner}" ]] || \
    fail 'Sats GLM5.2 proxy unit is missing'
  ! /usr/bin/grep -Fq -- PLACEHOLDER "${sats_glm52_proxy_config}" || \
    fail 'Sats GLM5.2 proxy config still contains placeholder credentials'
  [[ -n ${BUZZ_SATS_GLM52_PROXY_TOKEN:-} ]] || \
    fail 'Sats GLM5.2 proxy token is missing from the sanctioned secrets store'
fi

if [[ ${slug} == alpheus-claude-code ]]; then
  for runtime_dir in \
    "${alpheus_workdir}" \
    "${alpheus_claude_home}" \
    "${alpheus_claude_config}" \
    "${alpheus_claude_home}/.config" \
    "${alpheus_claude_home}/.cache" \
    "${alpheus_claude_home}/.local" \
    "${alpheus_claude_home}/.local/share" \
    "${alpheus_claude_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Alpheus Claude Code runtime directory is missing or unsafe: ${runtime_dir}"
  done
  # Fail closed until Mason's Anthropic account is logged into this seat's
  # isolated CLAUDE_CONFIG_DIR.
  [[ -f ${alpheus_claude_credentials} && ! -L ${alpheus_claude_credentials} && \
    $(/usr/bin/stat -c %U -- "${alpheus_claude_credentials}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${alpheus_claude_credentials}") == 600 ]] || \
    fail 'Alpheus Claude Code has no Anthropic login: run HOME=/home/victor/work/buzz-agents/alpheus-claude-code/home CLAUDE_CONFIG_DIR=/home/victor/work/buzz-agents/alpheus-claude-code/home/.claude claude auth login'
fi

if [[ ${slug} == alpheus-codex ]]; then
  for runtime_dir in \
    "${alpheus_workdir}" \
    "${alpheus_codex_home}" \
    "${alpheus_codex_codex_home}" \
    "${alpheus_codex_home}/.config" \
    "${alpheus_codex_home}/.cache" \
    "${alpheus_codex_home}/.local" \
    "${alpheus_codex_home}/.local/share" \
    "${alpheus_codex_home}/.local/state"; do
    [[ -d ${runtime_dir} && ! -L ${runtime_dir} && \
      $(/usr/bin/stat -c %U -- "${runtime_dir}") == "${expected_owner}" && \
      $(/usr/bin/stat -c %a -- "${runtime_dir}") == 700 ]] || \
      fail "Alpheus Codex runtime directory is missing or unsafe: ${runtime_dir}"
  done
  [[ -f ${alpheus_codex_wrapper} && ! -L ${alpheus_codex_wrapper} && \
    -x ${alpheus_codex_wrapper} && \
    $(/usr/bin/stat -c %U -- "${alpheus_codex_wrapper}") == "${expected_owner}" && \
    $(/usr/bin/stat -c %a -- "${alpheus_codex_wrapper}") == 700 ]] || \
    fail 'Alpheus Codex wrapper is missing or unsafe'
  actual_alpheus_codex_wrapper_sha256=
  read -r actual_alpheus_codex_wrapper_sha256 _ < <(/usr/bin/sha256sum -- "${alpheus_codex_wrapper}") || \
    fail 'cannot hash pinned Alpheus Codex wrapper'
  [[ ${actual_alpheus_codex_wrapper_sha256} == "${alpheus_codex_wrapper_sha256}" ]] || \
    fail 'pinned Alpheus Codex wrapper digest mismatch'
  unset actual_alpheus_codex_wrapper_sha256
  # Fail closed until Mason's OpenAI account is logged into this seat's
  # isolated CODEX_HOME.
  [[ -f ${alpheus_codex_auth} && ! -L ${alpheus_codex_auth} && \
    $(/usr/bin/stat -c %U -- "${alpheus_codex_auth}") == "${expected_owner}" ]] || \
    fail 'Alpheus Codex has no OpenAI login: run HOME=/home/victor/work/buzz-agents/alpheus-codex/home CODEX_HOME=/home/victor/work/buzz-agents/alpheus-codex/home/.codex codex login'
fi

[[ ${private_key} =~ ^[0-9a-f]{64}$ ]] || {
  printf 'Buzz agent private key is missing or invalid for %s\n' "${slug}" >&2
  exit 1
}
[[ -n ${auth_tag} ]] || fail "Buzz auth tag is missing for ${slug}"

[[ -f ${buzz_acp} && ! -L ${buzz_acp} && -x ${buzz_acp} && \
  $(/usr/bin/stat -c %U -- "${buzz_acp}") == "${expected_owner}" && \
  $(/usr/bin/stat -c %a -- "${buzz_acp}") == 755 ]] || \
  fail 'pinned buzz-acp is missing, a symlink, non-executable, not owned by victor, or not mode 0755'
actual_buzz_acp_sha256=
read -r actual_buzz_acp_sha256 _ < <(/usr/bin/sha256sum -- "${buzz_acp}") || \
  fail 'cannot hash pinned buzz-acp'
[[ ${actual_buzz_acp_sha256} == "${buzz_acp_sha256}" ]] || \
  fail 'pinned buzz-acp digest mismatch'
unset actual_buzz_acp_sha256

clear_exported_environment() {
  local name
  local -a exported_names=()
  local -a function_names=()

  mapfile -t exported_names < <(compgen -e)
  mapfile -t function_names < <(compgen -A function)

  for name in "${function_names[@]}"; do
    export -nf "${name?}"
  done
  for name in "${exported_names[@]}"; do
    if ! unset -v "${name}" 2>/dev/null; then
      export -n "${name?}"
    fi
  done
  [[ -z $(compgen -e) ]] || fail 'inherited exported environment was not fully cleared'
}

assert_exact_exported_environment() {
  local exported_name
  local runtime_assignment
  local -A expected_exports=(
    [HOME]=1
    [USER]=1
    [LOGNAME]=1
    [PATH]=1
    [LANG]=1
    [LC_ALL]=1
    [TMPDIR]=1
    [RUST_LOG]=1
    [BUZZ_PRIVATE_KEY]=1
    [BUZZ_RELAY_URL]=1
    [BUZZ_ACP_AGENT_OWNER]=1
    [BUZZ_ACP_AGENT_COMMAND]=1
    [BUZZ_ACP_AGENT_ARGS]=1
    [BUZZ_ACP_MCP_COMMAND]=1
    [BUZZ_ACP_SYSTEM_PROMPT_FILE]=1
    [BUZZ_ACP_SESSION_TITLE]=1
    [BUZZ_ACP_RESPOND_TO]=1
    [BUZZ_ACP_RESPOND_TO_ALLOWLIST]=1
    [BUZZ_ACP_ALLOWED_RESPOND_TO]=1
    [BUZZ_ACP_PERMISSION_MODE]=1
    [BUZZ_ACP_SUBSCRIBE]=1
    [BUZZ_ACP_AGENTS]=1
    [BUZZ_ACP_HEARTBEAT_INTERVAL]=1
    [BUZZ_ACP_IDLE_TIMEOUT]=1
    [BUZZ_ACP_MAX_TURN_DURATION]=1
  )

  for runtime_assignment in "${runtime_env[@]}"; do
    expected_exports["${runtime_assignment%%=*}"]=1
  done
  [[ -z ${model} ]] || expected_exports[BUZZ_ACP_MODEL]=1
  expected_exports[BUZZ_AUTH_TAG]=1

  while IFS= read -r exported_name; do
    [[ ${expected_exports["${exported_name}"]+present} == present ]] || \
      fail "unexpected exported environment name: ${exported_name}"
    unset "expected_exports[${exported_name}]"
  done < <(compgen -e)
  ((${#expected_exports[@]} == 0)) || fail 'minimal exported environment is incomplete'
}

read_codex_feature_booleans() {
  /usr/bin/awk '
    /^\[features\]$/ { section = ""; in_features = 1; next }
    /^\[features\.[[:alnum:]_.-]+\]$/ {
      section = $0
      sub(/^\[features\./, "", section)
      sub(/\]$/, ".", section)
      in_features = 1
      next
    }
    /^\[/ { in_features = 0; next }
    in_features && /^[[:space:]]*[[:alnum:]_.-]+[[:space:]]*=[[:space:]]*(true|false)([[:space:]]*(#.*)?)?$/ {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/[[:space:]]/, "", line)
      print section line
    }
  ' "$1" | /usr/bin/sort | /usr/bin/paste -sd, -
}

clear_exported_environment
export TMPDIR=/home/victor/.cache/tmp

[[ -f ${system_prompt} && ! -L ${system_prompt} && -r ${system_prompt} ]] || \
  fail "reviewed system prompt is missing, unreadable, or a symlink for ${slug}"
actual_system_prompt_sha256=
read -r actual_system_prompt_sha256 _ < <(/usr/bin/sha256sum -- "${system_prompt}") || \
  fail "cannot hash the reviewed system prompt for ${slug}"
[[ ${actual_system_prompt_sha256} == "${system_prompt_sha256}" ]] || \
  fail "reviewed system prompt digest mismatch for ${slug}"
unset actual_system_prompt_sha256 system_prompt_sha256

export HOME="${runtime_home}"
export USER=victor
export LOGNAME=victor
export PATH=/home/victor/.npm-global/bin:/home/victor/.local/share/mise/installs/node/24.18.1/bin:/home/victor/bin:/home/victor/.local/bin:/home/victor/work/buzz-agents/bin:/usr/bin:/bin
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export RUST_LOG=info
export BUZZ_PRIVATE_KEY="${private_key}"
export BUZZ_RELAY_URL=wss://framework-desktop.tail69757d.ts.net:38443
export BUZZ_ACP_AGENT_OWNER="${agent_owner}"
export BUZZ_ACP_AGENT_COMMAND="${agent_command}"
export BUZZ_ACP_AGENT_ARGS=
export BUZZ_ACP_MCP_COMMAND="${mcp_command}"
export BUZZ_ACP_SYSTEM_PROMPT_FILE="${system_prompt}"
export BUZZ_ACP_SESSION_TITLE="${session_title}"
export BUZZ_ACP_RESPOND_TO="${respond_to}"
export BUZZ_ACP_RESPOND_TO_ALLOWLIST="${respond_to_allowlist}"
export BUZZ_ACP_ALLOWED_RESPOND_TO="${allowed_respond_to}"
export BUZZ_ACP_PERMISSION_MODE=bypass-permissions
export BUZZ_ACP_SUBSCRIBE="${subscribe}"
export BUZZ_ACP_AGENTS="${agents}"
export BUZZ_ACP_HEARTBEAT_INTERVAL=0
export BUZZ_ACP_IDLE_TIMEOUT=620
export BUZZ_ACP_MAX_TURN_DURATION=7200
export "${runtime_env[@]}"

if [[ -n ${model} ]]; then
  export BUZZ_ACP_MODEL="${model}"
fi
export BUZZ_AUTH_TAG="${auth_tag}"

launcher_path=$(/usr/bin/readlink -e -- "$0") || fail 'cannot resolve launcher path'
cd "${workdir}"
export -n PWD OLDPWD
assert_exact_exported_environment

prompt_path=$(/usr/bin/readlink -e -- "${system_prompt}") || fail "cannot resolve the reviewed system prompt for ${slug}"
read -r launcher_sha256 _ < <(/usr/bin/sha256sum -- "${launcher_path}") || fail 'cannot hash launcher'
read -r prompt_sha256 _ < <(/usr/bin/sha256sum -- "${prompt_path}") || fail "cannot hash the resolved system prompt for ${slug}"

codex_wrapper=
codex_home=
for runtime_assignment in "${runtime_env[@]}"; do
  case ${runtime_assignment} in
    CODEX_PATH=*) codex_wrapper=${runtime_assignment#CODEX_PATH=} ;;
    CODEX_HOME=*) codex_home=${runtime_assignment#CODEX_HOME=} ;;
  esac
done

if [[ -n ${codex_wrapper} ]]; then
  [[ -n ${codex_home} ]] || codex_home=/home/victor/.codex
  codex_wrapper=$(/usr/bin/readlink -e -- "${codex_wrapper}") || fail "cannot resolve Codex wrapper for ${slug}"
  config_toml=$(/usr/bin/readlink -e -- "${codex_home}/config.toml") || fail "cannot resolve config.toml for ${slug}"
  read -r codex_wrapper_sha256 _ < <(/usr/bin/sha256sum -- "${codex_wrapper}") || fail "cannot hash the resolved Codex wrapper for ${slug}"
  features=$(read_codex_feature_booleans "${config_toml}") || fail "cannot read boolean features from config.toml for ${slug}"
  [[ ${features} == *code_mode_host=* ]] || fail "code_mode_host is unreadable in config.toml for ${slug}"
else
  codex_wrapper_sha256=none
  config_toml=none
  features=none
fi

printf 'slug=%s launcher_sha256=%s prompt_sha256=%s codex_wrapper_sha256=%s config_toml=%s features=%s\n' \
  "${slug}" "${launcher_sha256}" "${prompt_sha256}" "${codex_wrapper_sha256}" "${config_toml}" "${features}"
exec "${buzz_acp}"
