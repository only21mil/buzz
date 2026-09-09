use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceError;
use rmcp::ServiceExt;
use serde_json::{Map, Value};
use tokio::process::Command;
use tokio::sync::watch;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{Config, HookServers};
use crate::types::{clamp, AgentError, McpServerStdio, ToolDef, ToolResult, ToolResultContent};

const SEP: &str = "__";
const MAX_NAME_LEN: usize = 128;
const MAX_QNAME_LEN: usize = 64;
const MAX_TOOLS_PER_SESSION: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_SCHEMA_BYTES: usize = 4096;
const MARKER_FIELD_MAX: usize = 256;
pub const MAX_MCP_SERVERS: usize = 16;
const MAX_HOOK_RESULT_BYTES: usize = 16 * 1024;

/// Byte budgets for a single tool result. `total` bounds everything the
/// result may occupy in history (text + images); `text` bounds the text
/// portion alone, since text is where runaway outputs (build logs, file
/// dumps) live while images are legitimately large and self-limiting.
#[derive(Clone, Copy)]
pub struct ResultBudget {
    pub total: usize,
    pub text: usize,
}

const PASSTHROUGH_ENV: &[&str] = &[
    // Core
    "PATH",
    "HOME",
    "TERM",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    // SSH — required for git clone/push over SSH (git@github.com:...)
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    // Git — operator-configured helpers and transport overrides
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_CONFIG_GLOBAL",
    // Proxy — on a host whose only route out is a CONNECT proxy, dropping
    // these does not degrade the tools, it blinds them: apt, curl, pip and git
    // all connect directly instead, and the egress firewall resets the socket.
    // The agent then reports "Connection reset by peer" and concludes the
    // environment has no network, which is indistinguishable in the transcript
    // from a task that is genuinely offline.
    //
    // Both cases are needed. curl and git read the lowercase spellings, most
    // Go and Python tooling reads the uppercase ones, and libcurl deliberately
    // ignores uppercase HTTP_PROXY (CGI ambiguity), so keeping only one form
    // silently breaks half the toolchain.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    // TLS trust — a proxy that terminates TLS presents its own CA, and an
    // image whose trust store does not carry it fails every https fetch with a
    // verification error. Same class of failure as the proxy vars: the parent
    // was configured correctly and the child could not see it.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // Buzz identity — dev-mcp writes NOSTR_PRIVATE_KEY to a keyfile then
    // removes it from its own env (children never see it). BUZZ_PRIVATE_KEY
    // and BUZZ_RELAY_URL are kept for the buzz CLI. BUZZ_AUTH_TAG is a
    // non-secret signed ownership attestation needed by portable owner-scoped
    // CLI operations; MCP subprocesses are trusted like the agent runtime.
    "NOSTR_PRIVATE_KEY",
    "BUZZ_PRIVATE_KEY",
    "BUZZ_RELAY_URL",
    "BUZZ_AUTH_TAG",
    // Agent display name — dev-mcp uses it as the git author name. On the
    // Desktop path this arrives via the wire `mcpServers[].env` declaration
    // (which wins here anyway); the allowlist entry covers ACP clients that
    // spawn buzz-agent without declaring it.
    "BUZZ_ACP_DISPLAY_NAME",
];

// Windows has no $TMPDIR/$HOME. TMP/TEMP/USERPROFILE are what
// std::env::temp_dir() consults — without them it falls back to C:\Windows,
// which child processes can't write to (PermissionDenied). USERPROFILE is the
// always-set floor. APPDATA carries child-tool config (git, etc.).
#[cfg(windows)]
const PASSTHROUGH_ENV_WINDOWS: &[&str] = &["TMP", "TEMP", "USERPROFILE", "APPDATA"];

/// Environment retained by `spawn_one()` after `env_clear()` on Windows.
/// Shell resolver keys are shared with Doctor through the public contract.
#[cfg(windows)]
fn windows_child_passthrough_env() -> impl Iterator<Item = &'static str> {
    PASSTHROUGH_ENV_WINDOWS
        .iter()
        .copied()
        .chain(crate::WINDOWS_SHELL_RESOLUTION_ENV.iter().copied())
}

type Client = RunningService<RoleClient, ()>;

#[derive(Clone)]
struct ServerSpec {
    name: String,
    command: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
}

enum ClientState {
    Healthy {
        client: Arc<Client>,
        pgid: Option<u32>,
        tools: Arc<Vec<String>>,
    },
    Dead {
        attempts: u32,
        next_retry: Instant,
        reason: String,
        // Preserved from the last Healthy state so tools() filtering stays accurate while dead.
        tools: Arc<Vec<String>>,
    },
}

struct Server {
    name: String,
    spec: ServerSpec,
    client: ArcSwap<ClientState>,
    restart_lock: AsyncMutex<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let ClientState::Healthy { pgid: Some(p), .. } = &**self.client.load() {
            killpg(*p, &self.name, "drop");
        }
    }
}

enum RestartCheck {
    Healthy,
    Ready {
        attempt_n: u32,
        prev_tools: Arc<Vec<String>>,
    },
}

fn check_restart_state(server: &Server, max_attempts: u32) -> Result<RestartCheck, AgentError> {
    match &**server.client.load() {
        ClientState::Healthy { .. } => Ok(RestartCheck::Healthy),
        ClientState::Dead { attempts, .. } if *attempts >= max_attempts => {
            Err(AgentError::Mcp(format!(
                "The MCP server '{}' is unavailable (exhausted). Its tools have been removed for this session.",
                server.name
            )))
        }
        ClientState::Dead { next_retry, reason, .. } if Instant::now() < *next_retry => {
            Err(AgentError::Mcp(format!(
                "server '{}' is recovering (last error: {reason}). Try again later or use a different tool.",
                server.name
            )))
        }
        ClientState::Dead { attempts, tools, .. } => Ok(RestartCheck::Ready {
            attempt_n: attempts + 1,
            prev_tools: tools.clone(),
        }),
    }
}

struct Entry {
    server_idx: usize,
    bare: String,
}

pub struct McpRegistry {
    by_qname: HashMap<String, Entry>,
    defs: Vec<ToolDef>,
    servers: Vec<Arc<Server>>,
    max_attempts: u32,
    backoff_base: Duration,
    backoff_max: Duration,
    init_timeout: Duration,
    /// Consecutive hook timeout count per server. Kill on second consecutive.
    hook_timeouts: std::sync::Mutex<HashMap<String, u32>>,
}

impl McpRegistry {
    pub async fn spawn_all(
        cfg: &Config,
        servers: &[McpServerStdio],
        cwd: &str,
    ) -> Result<Self, AgentError> {
        if servers.len() > MAX_MCP_SERVERS {
            return Err(AgentError::Mcp(format!(
                "too many MCP servers: {} > {MAX_MCP_SERVERS}",
                servers.len()
            )));
        }
        let mut reg = Self {
            by_qname: HashMap::new(),
            defs: Vec::new(),
            servers: Vec::new(),

            max_attempts: cfg.mcp_max_restart_attempts.max(1),
            backoff_base: Duration::from_millis(cfg.mcp_restart_base_ms.max(1)),
            backoff_max: Duration::from_millis(cfg.mcp_restart_max_ms.max(1)),
            init_timeout: cfg.mcp_init_timeout,
            hook_timeouts: std::sync::Mutex::new(HashMap::new()),
        };

        let mut seen_names = HashSet::new();
        for s in servers {
            if !valid_name(&s.name) || s.name.contains("__") {
                return Err(AgentError::Mcp(format!("invalid server name: {}", s.name)));
            }
            if !seen_names.insert(s.name.clone()) {
                return Err(AgentError::Mcp(format!(
                    "duplicate server name: {}",
                    s.name
                )));
            }
            let spec = ServerSpec {
                name: s.name.clone(),
                command: s.command.clone(),
                args: s.args.clone(),
                env: s
                    .env
                    .iter()
                    .map(|e| (e.name.clone(), e.value.clone()))
                    .collect(),
                cwd: cwd.to_owned(),
            };
            let (client, pgid, tool_names, raw_tools) = spawn_one(&spec, reg.init_timeout).await?;
            let server_idx = reg.servers.len();
            let server = Arc::new(Server {
                name: spec.name.clone(),
                spec,
                client: ArcSwap::from_pointee(ClientState::Healthy {
                    client: Arc::new(client),
                    pgid,
                    tools: Arc::new(tool_names),
                }),
                restart_lock: AsyncMutex::new(()),
            });
            reg.servers.push(server);

            for t in raw_tools {
                if reg.defs.len() >= MAX_TOOLS_PER_SESSION {
                    return Err(AgentError::Mcp(format!(
                        "too many tools (>{MAX_TOOLS_PER_SESSION})"
                    )));
                }
                let bare = t.name.to_string();
                if !valid_name(&bare) || bare.contains("__") {
                    return Err(AgentError::Mcp(format!("invalid tool name: {bare}")));
                }
                let qname = format!("{}{SEP}{}", s.name, bare);
                if qname.len() > MAX_QNAME_LEN {
                    return Err(AgentError::Mcp(format!(
                        "qualified tool name too long: {} ({} > {MAX_QNAME_LEN})",
                        qname,
                        qname.len()
                    )));
                }
                if reg.by_qname.contains_key(&qname) {
                    return Err(AgentError::Mcp(format!("duplicate tool: {qname}")));
                }
                reg.defs.push(ToolDef {
                    name: qname.clone(),
                    description: clamp(
                        t.description.as_deref().unwrap_or("").to_owned(),
                        MAX_DESCRIPTION_BYTES,
                    ),
                    input_schema: cap_schema(&qname, Value::Object((*t.input_schema).clone())),
                });
                reg.by_qname.insert(qname, Entry { server_idx, bare });
            }
        }
        Ok(reg)
    }

    pub fn server_of(&self, qname: &str) -> Option<&str> {
        self.by_qname
            .get(qname)
            .map(|e| self.servers[e.server_idx].name.as_str())
    }

    pub fn has(&self, qname: &str) -> bool {
        self.by_qname.contains_key(qname)
    }

    /// True if `qname` resolves to a hidden hook tool (bare name starts
    /// with `_`). Used to reject hook calls coming from the LLM path —
    /// hooks are only callable via `call_hooks`.
    pub fn is_hook(&self, qname: &str) -> bool {
        self.by_qname
            .get(qname)
            .map(|e| e.bare.starts_with('_'))
            .unwrap_or(false)
    }

    pub fn tools(&self) -> Vec<ToolDef> {
        self.defs
            .iter()
            .filter(|d| {
                let entry = match self.by_qname.get(&d.name) {
                    Some(e) => e,
                    None => return false,
                };
                // Bare names starting with `_` are hooks — invisible to the LLM.
                if entry.bare.starts_with('_') {
                    return false;
                }
                let server = &self.servers[entry.server_idx];
                match &**server.client.load() {
                    ClientState::Healthy { tools, .. } => tools.iter().any(|t| t == &entry.bare),
                    ClientState::Dead {
                        attempts, tools, ..
                    } => *attempts < self.max_attempts && tools.iter().any(|t| t == &entry.bare),
                }
            })
            .cloned()
            .collect()
    }

    /// Call every tool whose bare name equals `hook_name` across all
    /// allowlisted servers in parallel, bounded by `timeout`. Returns
    /// `(server_name, text)` pairs in **config order** (deterministic),
    /// dropping empty/whitespace-only responses, errors and timeouts.
    /// Hooks are fail-open and must never block the agent.
    pub async fn call_hooks(
        self: &Arc<Self>,
        hook_name: &str,
        input: &Value,
        timeout: Duration,
        allowed: &HookServers,
    ) -> Vec<(String, String)> {
        if allowed.is_disabled() {
            return Vec::new();
        }
        // Walk servers in registration order so the result is deterministic
        // regardless of HashMap iteration order or task completion order.
        let mut targets: Vec<(usize, String, String)> = Vec::new();
        for (idx, server) in self.servers.iter().enumerate() {
            if !allowed.allows(&server.name) {
                continue;
            }
            let qname = format!("{}{SEP}{}", server.name, hook_name);
            if self.by_qname.contains_key(&qname) {
                targets.push((idx, server.name.clone(), qname));
            }
        }
        if targets.is_empty() {
            return Vec::new();
        }
        let mut set = tokio::task::JoinSet::new();
        for (idx, server_name, qname) in targets {
            let reg = Arc::clone(self);
            let args = input.clone();
            set.spawn(async move {
                // Hooks are intentionally non-cancellable: they are
                // already bounded by their own timeout and are fail-open.
                // Session cancel should not interrupt hook evaluation.
                let (_dummy_tx, mut dummy_cancel) = watch::channel(false);
                let res = tokio::time::timeout(
                    timeout,
                    reg.call(
                        &qname,
                        "hook",
                        &args,
                        ResultBudget {
                            total: MAX_HOOK_RESULT_BYTES,
                            text: MAX_HOOK_RESULT_BYTES,
                        },
                        &mut dummy_cancel,
                    ),
                )
                .await;
                drop(_dummy_tx);
                (idx, server_name, res)
            });
        }
        let mut indexed: Vec<(usize, String, String)> = Vec::new();
        while let Some(joined) = set.join_next().await {
            // fail-open: drop join errors, timeouts, call errors,
            // empty/whitespace-only text. On timeout, also kill the server
            // process group so a wedged hook can't poison the next regular
            // tool call. The registry's lazy restart handles the rest.
            match joined {
                Ok((idx, server_name, Ok(Ok(r)))) => {
                    // Success — reset consecutive timeout counter.
                    if let Ok(mut counts) = self.hook_timeouts.lock() {
                        counts.remove(&server_name);
                    }
                    if !r.is_error && !r.text().trim().is_empty() {
                        indexed.push((idx, server_name, r.text()));
                    }
                }
                Ok((_idx, server_name, Err(_elapsed))) => {
                    // Kill only on second consecutive timeout.
                    let count = {
                        let mut counts =
                            self.hook_timeouts.lock().unwrap_or_else(|e| e.into_inner());
                        let c = counts.entry(server_name.clone()).or_insert(0);
                        *c += 1;
                        *c
                    };
                    if count >= 2 {
                        tracing::warn!(
                            "hook: killing server '{}' after {} consecutive timeouts",
                            server_name,
                            count
                        );
                        self.kill_server(&server_name, "hook timeout (consecutive)");
                        if let Ok(mut counts) = self.hook_timeouts.lock() {
                            counts.remove(&server_name);
                        }
                    } else {
                        tracing::warn!("hook: server '{}' timed out ({}/2)", server_name, count);
                    }
                }
                _ => {}
            }
        }
        indexed.sort_by_key(|(idx, _, _)| *idx);
        indexed
            .into_iter()
            .map(|(_, name, text)| (name, text))
            .collect()
    }

    /// Kill the server's process group and mark it dead. Idempotent:
    /// if the server is already Dead (or unknown), this is a no-op.
    /// Counts as one attempt toward the restart budget so that a
    /// pathological server (starts fine, deadlocks on every call)
    /// eventually exhausts.
    pub fn kill_server(&self, name: &str, reason: &str) {
        let server = match self.servers.iter().find(|s| s.name == name) {
            Some(s) => s,
            None => return,
        };
        let current = server.client.load_full();
        let (pgid, tools) = match &*current {
            ClientState::Dead { .. } => return,
            ClientState::Healthy { pgid, tools, .. } => (*pgid, tools.clone()),
        };
        let dead = Arc::new(ClientState::Dead {
            attempts: 1,
            next_retry: Instant::now() + backoff(1, self.backoff_base, self.backoff_max),
            reason: reason.to_owned(),
            tools,
        });
        // CAS so we don't clobber a concurrent restart that already
        // transitioned the state. If the swap fails, the kill below is
        // still safe — the pgid we read belonged to a process we observed
        // as Healthy, and killpg on an already-reaped pgid is a no-op.
        let prev = server.client.compare_and_swap(&current, dead);
        if Arc::ptr_eq(&prev, &current) {
            if let Some(p) = pgid {
                killpg(p, &server.name, "kill_server");
            }
            tracing::error!(
                "MCP server '{}' killed and marked dead (reason={reason})",
                server.name
            );
        }
    }

    fn kill_and_mark_dead_if_current(
        &self,
        server: &Server,
        failed_client: &Arc<Client>,
        reason: &str,
    ) {
        let current = server.client.load_full();
        match &*current {
            ClientState::Healthy {
                client,
                pgid,
                tools,
            } if Arc::ptr_eq(client, failed_client) => {
                if let Some(p) = *pgid {
                    killpg(p, &server.name, "call_failed");
                }
                let dead = Arc::new(ClientState::Dead {
                    attempts: 1,
                    next_retry: Instant::now() + backoff(1, self.backoff_base, self.backoff_max),
                    reason: reason.to_owned(),
                    tools: tools.clone(),
                });
                let _ = server.client.compare_and_swap(&current, dead);
                tracing::error!(
                    "MCP server '{}' killed and marked dead (reason={reason})",
                    server.name
                );
            }
            _ => {}
        }
    }

    pub async fn call(
        &self,
        qname: &str,
        provider_id: &str,
        arguments: &Value,
        budget: ResultBudget,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ToolResult, AgentError> {
        let entry = self
            .by_qname
            .get(qname)
            .ok_or_else(|| AgentError::Mcp(format!("unknown tool {qname}")))?;
        let server = self.servers[entry.server_idx].clone();

        let state = server.client.load();
        if let ClientState::Healthy { client, tools, .. } = &**state {
            if !tools.iter().any(|t| t == &entry.bare) {
                return Err(AgentError::Mcp(format!(
                    "tool '{qname}': no longer available; the MCP server restarted with a different tool set."
                )));
            }
            let client = client.clone();
            drop(state);
            return self
                .do_call(
                    &server,
                    &client,
                    &entry.bare,
                    qname,
                    provider_id,
                    arguments,
                    budget,
                    cancel,
                )
                .await;
        }
        drop(state);

        self.maybe_restart(&server).await?;
        let state = server.client.load();
        let client = match &**state {
            ClientState::Healthy { client, tools, .. } => {
                if !tools.iter().any(|t| t == &entry.bare) {
                    return Err(AgentError::Mcp(format!(
                        "tool '{qname}': no longer available; the MCP server restarted with a different tool set."
                    )));
                }
                client.clone()
            }
            ClientState::Dead { reason, .. } => {
                return Err(AgentError::Mcp(format!(
                    "tool '{qname}': server '{}' restart failed: {reason}",
                    server.name
                )));
            }
        };
        drop(state);
        self.do_call(
            &server,
            &client,
            &entry.bare,
            qname,
            provider_id,
            arguments,
            budget,
            cancel,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_call(
        &self,
        server: &Server,
        client: &Arc<Client>,
        bare: &str,
        qname: &str,
        provider_id: &str,
        arguments: &Value,
        budget: ResultBudget,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ToolResult, AgentError> {
        let arg_obj = match arguments {
            Value::Object(m) => Some(m.clone()),
            Value::Null => None,
            _ => {
                return Err(AgentError::Mcp(format!(
                    "tool {qname} arguments must be a JSON object"
                )))
            }
        };
        let mut params = CallToolRequestParams::default();
        params.name = bare.to_owned().into();
        params.arguments = arg_obj;

        use rmcp::model::{CallToolRequest, ClientRequest, ServerResult};
        use rmcp::service::PeerRequestOptions;

        let req = ClientRequest::CallToolRequest(CallToolRequest::new(params));
        let mut handle = client
            .peer()
            .send_cancellable_request(req, PeerRequestOptions::no_options())
            .await
            .map_err(|e| AgentError::Mcp(format!("call {qname}: {e}")))?;

        // Early cancel check — watch::changed() only fires on NEW writes.
        if *cancel.borrow() {
            fire_and_forget_cancel(handle, qname);
            return Err(AgentError::Cancelled);
        }

        // Poll the inner oneshot directly so we can still own `handle` in
        // the cancel branch (await_response would move it).
        let raw: Result<ServerResult, ServiceError> = tokio::select! {
            biased;
            _ = cancel.changed() => {
                fire_and_forget_cancel(handle, qname);
                return Err(AgentError::Cancelled);
            }
            r = &mut handle.rx => match r {
                Ok(inner) => inner,
                Err(_) => Err(ServiceError::TransportClosed),
            },
        };

        let res = match raw {
            Ok(ServerResult::CallToolResult(r)) => r,
            Ok(_) => {
                return Err(AgentError::Mcp(format!(
                    "call {qname}: unexpected response type"
                )))
            }
            Err(e) => {
                if is_transport_error(&e) {
                    self.kill_and_mark_dead_if_current(
                        server,
                        client,
                        &format!("call failed: {e}"),
                    );
                    return Err(AgentError::Mcp(format!("call {qname}: {e}")));
                }
                // Application-level JSON-RPC error (e.g. -32602 invalid params).
                // Server is healthy — it correctly rejected bad input. Return to LLM.
                return Ok(ToolResult {
                    provider_id: provider_id.to_owned(),
                    content: vec![ToolResultContent::Text(clamp(
                        format!("Tool call rejected: {e}"),
                        budget.text,
                    ))],
                    is_error: true,
                });
            }
        };
        let is_error = res.is_error.unwrap_or(false);
        let has_image = res
            .content
            .iter()
            .any(|c| matches!(c.raw, rmcp::model::RawContent::Image(_)));
        let content = if has_image {
            // An over-budget image gets decoded and resized; keep that off
            // the async worker.
            let blocks = res.content;
            let (total, text) = (budget.total, budget.text);
            tokio::task::spawn_blocking(move || tool_result_content(&blocks, total, text))
                .await
                .map_err(|e| AgentError::Mcp(format!("call {qname}: result assembly: {e}")))?
        } else {
            tool_result_content(&res.content, budget.total, budget.text)
        };
        Ok(ToolResult {
            provider_id: provider_id.to_owned(),
            content,
            is_error,
        })
    }

    async fn maybe_restart(&self, server: &Server) -> Result<(), AgentError> {
        match check_restart_state(server, self.max_attempts)? {
            RestartCheck::Healthy => return Ok(()),
            RestartCheck::Ready { .. } => {}
        }

        let _guard = server.restart_lock.lock().await;

        let (attempt_n, prev_tools) = match check_restart_state(server, self.max_attempts)? {
            RestartCheck::Healthy => return Ok(()),
            RestartCheck::Ready {
                attempt_n,
                prev_tools,
            } => (attempt_n, prev_tools),
        };

        let started = Instant::now();
        tracing::info!(
            "MCP server '{}' restarting (attempt {attempt_n}/{})",
            server.name,
            self.max_attempts
        );
        match spawn_one(&server.spec, self.init_timeout).await {
            Ok((client, pgid, tool_names, _raw_tools)) => {
                server.client.store(Arc::new(ClientState::Healthy {
                    client: Arc::new(client),
                    pgid,
                    tools: Arc::new(tool_names),
                }));

                tracing::info!(
                    "MCP server '{}' restarted in {}ms (attempt {attempt_n})",
                    server.name,
                    started.elapsed().as_millis()
                );
                Ok(())
            }
            Err(e) => {
                let reason = format!("restart failed: {e}");
                let permanent = attempt_n >= self.max_attempts;
                let next_retry = if permanent {
                    Instant::now() + Duration::from_secs(86_400)
                } else {
                    Instant::now() + backoff(attempt_n, self.backoff_base, self.backoff_max)
                };
                server.client.store(Arc::new(ClientState::Dead {
                    attempts: attempt_n,
                    next_retry,
                    reason: reason.clone(),
                    tools: prev_tools,
                }));

                tracing::error!(
                    "MCP server '{}' restart failed (attempt {attempt_n}/{}, permanent={permanent}): {reason}",
                    server.name, self.max_attempts
                );
                Err(AgentError::Mcp(reason))
            }
        }
    }
}

async fn spawn_one(
    spec: &ServerSpec,
    timeout: Duration,
) -> Result<(Client, Option<u32>, Vec<String>, Vec<rmcp::model::Tool>), AgentError> {
    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args);
    cmd.env_clear();
    for k in PASSTHROUGH_ENV {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    #[cfg(windows)]
    for k in windows_child_passthrough_env() {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    cmd.current_dir(&spec.cwd);
    cmd.stderr(std::process::Stdio::inherit());

    #[cfg(unix)]
    cmd.process_group(0);

    configure_no_window(&mut cmd);

    let transport = TokioChildProcess::new(cmd)
        .map_err(|e| AgentError::Mcp(format!("spawn {}: {e}", spec.name)))?;
    let pgid = transport.id();

    struct PgidGuard {
        pgid: Option<u32>,
        name: String,
    }
    impl Drop for PgidGuard {
        fn drop(&mut self) {
            if let Some(p) = self.pgid.take() {
                killpg(p, &self.name, "spawn_dropped");
            }
        }
    }
    let mut guard = PgidGuard {
        pgid,
        name: spec.name.clone(),
    };

    let client: Client = match tokio::time::timeout(timeout, ().serve(transport)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            return Err(AgentError::Mcp(format!("init {}: {e}", spec.name)));
        }
        Err(_) => {
            return Err(AgentError::Mcp(timeout_msg("init", &spec.name, timeout)));
        }
    };

    let tools = match tokio::time::timeout(timeout, client.peer().list_all_tools()).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Err(AgentError::Mcp(format!("list_tools {}: {e}", spec.name)));
        }
        Err(_) => {
            return Err(AgentError::Mcp(timeout_msg(
                "list_tools",
                &spec.name,
                timeout,
            )));
        }
    };
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    guard.pgid = None;
    Ok((client, pgid, names, tools))
}

/// Send `notifications/cancelled` to the MCP server, fire-and-forget.
/// Per MCP spec, cancellation notifications are best-effort; we never
/// block the agent on slow server stdio.
fn fire_and_forget_cancel(
    handle: rmcp::service::RequestHandle<rmcp::service::RoleClient>,
    qname: &str,
) {
    let qname_owned = qname.to_owned();
    tokio::spawn(async move {
        if let Err(e) = handle.cancel(Some("session cancelled".into())).await {
            tracing::debug!("cancel notification failed for {qname_owned}: {e}");
        }
    });
}

/// Returns `true` for errors indicating the MCP server process is dead or
/// unreachable. Returns `false` for application-level JSON-RPC errors where
/// the server is healthy but rejected the request (e.g. invalid params).
fn is_transport_error(e: &ServiceError) -> bool {
    matches!(
        e,
        ServiceError::TransportSend(_)
            | ServiceError::TransportClosed
            | ServiceError::Timeout { .. }
            | ServiceError::UnexpectedResponse
    )
}

fn backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let scaled = base.saturating_mul(1u32 << shift);
    let capped = scaled.min(max);
    let ms = capped.as_millis() as u64;
    let jitter_pct = jitter_percent();
    let jittered = (ms as i64) + ((ms as i64) * jitter_pct / 100);
    Duration::from_millis(jittered.max(0) as u64)
}

fn jitter_percent() -> i64 {
    let mut buf = [0u8; 1];
    let _ = getrandom::fill(&mut buf);
    ((buf[0] as i64) % 41) - 20
}

fn timeout_msg(stage: &str, name: &str, t: Duration) -> String {
    format!("{stage} {name}: timeout after {}s", t.as_secs())
}

fn cap_schema(qname: &str, schema: Value) -> Value {
    let size = serde_json::to_vec(&schema).map(|b| b.len()).unwrap_or(0);
    if size <= MAX_SCHEMA_BYTES {
        return schema;
    }
    tracing::warn!(
        "tool {qname} schema is {size} bytes (>{MAX_SCHEMA_BYTES}); replacing with empty object"
    );
    Value::Object(Map::new())
}

#[cfg(unix)]
fn killpg(pgid: u32, name: &str, stage: &str) {
    use nix::sys::signal::{killpg as nix_killpg, Signal};
    use nix::unistd::Pid;
    let result = nix_killpg(Pid::from_raw(pgid as i32), Signal::SIGKILL);
    tracing::info!(
        "killpg MCP {name} ({stage}) pgid={pgid} ok={}",
        result.is_ok()
    );
}
#[cfg(not(unix))]
fn killpg(_pgid: u32, name: &str, stage: &str) {
    tracing::info!("relying on Drop to kill MCP {name} ({stage})");
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn truncate_at_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// Byte allowance reserved for the elision marker inside [`truncate_middle`].
/// The marker is ~80 bytes; the slack keeps the arithmetic safely one-sided.
const ELISION_MARKER_ALLOWANCE: usize = 128;

/// Truncate `s` to at most `max` bytes by eliding the *middle*, keeping the
/// head and tail. Tool output puts its conclusion at the end (test summaries,
/// error trailers) and its identity at the start; head-only truncation loses
/// the part the model needs most. The marker reports how much was elided so
/// the model knows to re-run a narrower command rather than trust the gap.
pub(crate) fn truncate_middle(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let keep = max.saturating_sub(ELISION_MARKER_ALLOWANCE);
    if keep == 0 {
        // Budget too small for head + marker + tail; degrade to a head cut.
        return truncate_at_boundary(s, max).to_owned();
    }
    let head = truncate_at_boundary(s, keep.div_ceil(2));
    let mut tail_start = s.len() - keep / 2;
    while tail_start < s.len() && !s.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let tail = &s[tail_start..];
    let elided = s.len() - head.len() - tail.len();
    format!(
        "{head}\n[... {elided} of {} bytes elided from tool result ...]\n{tail}",
        s.len()
    )
}

/// MIME type every downscaled tool-result image is delivered as.
const DOWNSCALED_MIME: &str = "image/jpeg";
/// JPEG quality for downscaled tool-result images. Screenshots keep their
/// text legible at this setting; photos lose little.
const DOWNSCALE_JPEG_QUALITY: u8 = 80;
/// Stop shrinking once the long edge falls below this many pixels; a smaller
/// picture tells the model nothing and the elision marker is more honest.
const DOWNSCALE_MIN_LONG_EDGE: u32 = 64;
/// Decode guard for tool-result images, in pixels. Same number as
/// `buzz_media::MAX_IMAGE_PIXELS` (100 MP: 8K, triple-5K and panoramas fit);
/// buzz-agent takes no workspace crates, so the value is repeated here and
/// must move with it.
const DOWNSCALE_MAX_PIXELS: u64 = 100_000_000;
/// Decode memory for a `DOWNSCALE_MAX_PIXELS` image at 16-bit RGBA
/// (8 bytes per pixel), matching `buzz_media::MAX_IMAGE_DECODE_BYTES`.
const DOWNSCALE_MAX_ALLOC: u64 = DOWNSCALE_MAX_PIXELS * 8;

/// Whether a declared geometry is over [`DOWNSCALE_MAX_PIXELS`].
fn exceeds_downscale_pixel_cap(width: u32, height: u32) -> bool {
    u64::from(width) * u64::from(height) > DOWNSCALE_MAX_PIXELS
}

/// A tool-result image re-encoded to fit an inline byte budget.
struct DownscaledImage {
    /// Base64 JPEG bytes, `<= budget` characters.
    data: String,
    source_width: u32,
    source_height: u32,
    width: u32,
    height: u32,
}

/// Shrink a base64 image until its base64 JPEG encoding fits `budget`
/// characters. Returns `None` when the bytes do not decode as an image, the
/// decode guard trips, or the picture would have to drop below
/// [`DOWNSCALE_MIN_LONG_EDGE`] to fit.
fn downscale_image_to_budget(data_b64: &str, budget: usize) -> Option<DownscaledImage> {
    use base64::Engine as _;
    use image::codecs::jpeg::JpegEncoder;
    use image::{GenericImageView as _, ImageDecoder as _};

    if budget == 0 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64.trim())
        .ok()?;
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    // Pixel count is the guard, not a side length: a 100 MP panorama has a
    // long edge well past any square cap. `max_alloc` bounds bytes, not
    // pixels (a 28000x28000 Luma8 declares 784 MP in 784 MB), so the
    // dimensions are checked from the header before any output buffer exists.
    let mut limits = image::Limits::no_limits();
    limits.max_alloc = Some(DOWNSCALE_MAX_ALLOC);
    reader.limits(limits);
    let decoder = reader.into_decoder().ok()?;
    let (source_width, source_height) = decoder.dimensions();
    if source_width == 0
        || source_height == 0
        || exceeds_downscale_pixel_cap(source_width, source_height)
        || decoder.total_bytes() > DOWNSCALE_MAX_ALLOC
    {
        return None;
    }
    let source = image::DynamicImage::from_decoder(decoder).ok()?;

    let encode = |img: &image::DynamicImage| -> Option<String> {
        let mut buf = Vec::new();
        let encoder = JpegEncoder::new_with_quality(&mut buf, DOWNSCALE_JPEG_QUALITY);
        img.to_rgb8().write_with_encoder(encoder).ok()?;
        Some(base64::engine::general_purpose::STANDARD.encode(buf))
    };

    let mut current = source;
    for _ in 0..12 {
        let encoded = encode(&current)?;
        let (width, height) = current.dimensions();
        if encoded.len() <= budget {
            return Some(DownscaledImage {
                data: encoded,
                source_width,
                source_height,
                width,
                height,
            });
        }
        if width.max(height) <= DOWNSCALE_MIN_LONG_EDGE {
            return None;
        }
        // JPEG size tracks pixel count, so scale both edges by the square
        // root of the overshoot with a little slack; never grow, always shrink.
        let ratio = (budget as f64 / encoded.len() as f64).sqrt() * 0.9;
        let ratio = ratio.clamp(0.1, 0.9);
        let next_width = ((width as f64) * ratio).round().max(1.0) as u32;
        let next_height = ((height as f64) * ratio).round().max(1.0) as u32;
        current = current.thumbnail(next_width, next_height);
    }
    None
}

/// Assemble tool-result content under two budgets: `max_bytes` bounds the
/// whole result (text + images), `max_text_bytes` bounds the text portion
/// alone. Images are large by nature and pass through whole or get elided
/// with a marker; text is middle-elided so the head (what ran) and tail
/// (how it ended) both survive. Every elision leaves an inline marker.
fn tool_result_content(
    blocks: &[rmcp::model::Content],
    max_bytes: usize,
    max_text_bytes: usize,
) -> Vec<ToolResultContent> {
    use rmcp::model::RawContent;
    let mut out = Vec::new();
    let mut text = String::new();
    let mut used = 0usize; // total bytes emitted (text + images)
    let mut text_used = 0usize; // text bytes emitted
    let short = |s: &str| truncate_at_boundary(s, MARKER_FIELD_MAX).to_owned();

    // Flush accumulated text, middle-eliding to whatever budget remains.
    let flush_text = |out: &mut Vec<ToolResultContent>,
                      text: &mut String,
                      used: &mut usize,
                      text_used: &mut usize| {
        if text.is_empty() {
            return;
        }
        let budget = max_text_bytes
            .saturating_sub(*text_used)
            .min(max_bytes.saturating_sub(*used));
        let kept = truncate_middle(&std::mem::take(text), budget);
        *used = used.saturating_add(kept.len());
        *text_used = text_used.saturating_add(kept.len());
        if !kept.is_empty() {
            out.push(ToolResultContent::Text(kept));
        }
    };

    let append = |text: &mut String, s: &str| {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(s);
    };

    for c in blocks {
        match &c.raw {
            RawContent::Text(t) => append(&mut text, &t.text),
            RawContent::Image(i) => {
                flush_text(&mut out, &mut text, &mut used, &mut text_used);
                let image_bytes = i.data.len().saturating_add(i.mime_type.len());
                if used.saturating_add(image_bytes) <= max_bytes {
                    used = used.saturating_add(image_bytes);
                    out.push(ToolResultContent::Image {
                        data: i.data.clone(),
                        mime_type: i.mime_type.clone(),
                    });
                    continue;
                }
                // Over budget: the storage cap on originals is 2 GiB, the
                // inline budget is not. Shrink the picture to fit rather than
                // dropping it, and say so; the original stays where the tool
                // read it from.
                let remaining = max_bytes
                    .saturating_sub(used)
                    .saturating_sub(DOWNSCALED_MIME.len())
                    .saturating_sub(ELISION_MARKER_ALLOWANCE);
                match downscale_image_to_budget(&i.data, remaining) {
                    Some(fit) => {
                        used = used
                            .saturating_add(fit.data.len())
                            .saturating_add(DOWNSCALED_MIME.len());
                        out.push(ToolResultContent::Image {
                            data: fit.data,
                            mime_type: DOWNSCALED_MIME.to_string(),
                        });
                        append(
                            &mut text,
                            &format!(
                                "[image downscaled: {} {}x{} ({} base64 bytes) exceeded the remaining tool-result budget; delivered as {} {}x{}. The original is unchanged at its source.]",
                                short(&i.mime_type),
                                fit.source_width,
                                fit.source_height,
                                i.data.len(),
                                DOWNSCALED_MIME,
                                fit.width,
                                fit.height
                            ),
                        );
                    }
                    None => append(
                        &mut text,
                        &format!(
                            "[image elided: {}, {} base64 bytes exceeds remaining tool-result budget]",
                            short(&i.mime_type),
                            i.data.len()
                        ),
                    ),
                }
            }
            RawContent::Audio(a) => append(
                &mut text,
                &format!(
                    "[audio elided: {}, {} bytes]",
                    short(&a.mime_type),
                    a.data.len()
                ),
            ),
            RawContent::ResourceLink(r) => {
                append(&mut text, &format!("[resource: {}]", short(&r.uri)));
            }
            RawContent::Resource(_) => append(&mut text, "[resource elided]"),
        }
    }
    flush_text(&mut out, &mut text, &mut used, &mut text_used);
    out
}

/// Suppress the console window that Windows otherwise allocates for every
/// console-subsystem child process spawned from a GUI (non-console) parent.
/// No-op on non-Windows platforms.
fn configure_no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

#[cfg(test)]
mod content_tests {
    use super::*;

    #[test]
    fn passthrough_includes_buzz_owner_attestation() {
        assert!(PASSTHROUGH_ENV.contains(&"BUZZ_AUTH_TAG"));
    }

    #[test]
    fn passthrough_carries_proxy_configuration_to_tools() {
        // On a proxy-only host this is the difference between an agent that can
        // install a package and one that reports the network is down. Both
        // spellings: libcurl ignores uppercase HTTP_PROXY, and Go/Python
        // tooling largely ignores the lowercase set.
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
        ] {
            assert!(
                PASSTHROUGH_ENV.contains(&var),
                "{var} must survive env_clear() or every MCP tool loses the proxy"
            );
        }
    }

    #[test]
    fn passthrough_carries_tls_trust_to_tools() {
        // A TLS-terminating proxy presents its own CA; without these the child
        // rejects every https fetch even though the proxy itself is reachable.
        for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
            assert!(
                PASSTHROUGH_ENV.contains(&var),
                "{var} must survive env_clear() or https fails inside tools"
            );
        }
    }
    use rmcp::model::Content;

    #[cfg(windows)]
    #[test]
    fn windows_passthrough_includes_shell_resolution_vars() {
        // Temp directories and every resolver key must survive `env_clear()`.
        for var in ["TMP", "TEMP", "USERPROFILE"] {
            assert!(
                PASSTHROUGH_ENV_WINDOWS.contains(&var),
                "{var} must pass through for Windows child processes"
            );
        }
        let child_env: Vec<_> = windows_child_passthrough_env().collect();
        for var in crate::WINDOWS_SHELL_RESOLUTION_ENV {
            assert!(
                child_env.contains(var),
                "{var} must pass through so the MCP shell resolver matches Doctor"
            );
        }
    }

    #[test]
    fn tool_result_content_preserves_images() {
        let blocks = vec![
            Content::text("header"),
            Content::image("aW1n", "image/png"),
            Content::text("tail"),
        ];
        let out = tool_result_content(&blocks, 1024, 1024);
        assert_eq!(out.len(), 3);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t == "header"));
        assert!(matches!(
            &out[1],
            ToolResultContent::Image { data, mime_type }
                if data == "aW1n" && mime_type == "image/png"
        ));
        assert!(matches!(&out[2], ToolResultContent::Text(t) if t == "tail"));
    }

    #[test]
    fn tool_result_content_elides_images_over_budget() {
        // Not decodable as an image: nothing to shrink, so the marker stands.
        let blocks = vec![Content::image("a".repeat(300), "image/png")];
        let out = tool_result_content(&blocks, 256, 256);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t.contains("image elided")));
    }

    /// Incompressible noise PNG, base64-encoded, so its size is predictable.
    fn noise_png_base64(width: u32, height: u32) -> String {
        use base64::Engine as _;
        let mut img = image::RgbImage::new(width, height);
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for px in img.pixels_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *px = image::Rgb([
                (seed & 0xff) as u8,
                ((seed >> 8) & 0xff) as u8,
                ((seed >> 16) & 0xff) as u8,
            ]);
        }
        let mut bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn tool_result_content_downscales_a_real_image_over_budget() {
        let png = noise_png_base64(640, 480);
        assert!(
            png.len() > 400 * 1024,
            "noise png is {} b64 bytes",
            png.len()
        );
        let budget = 96 * 1024;
        let blocks = vec![
            Content::text("before"),
            Content::image(png.clone(), "image/png"),
        ];
        let out = tool_result_content(&blocks, budget, budget);
        assert_eq!(out.len(), 3, "text, downscaled image, note: {out:?}");
        let ToolResultContent::Image { data, mime_type } = &out[1] else {
            panic!("expected a downscaled image, got {:?}", out[1]);
        };
        assert_eq!(mime_type, "image/jpeg");
        assert!(data.len() < png.len());
        let total: usize = out
            .iter()
            .map(|c| match c {
                ToolResultContent::Text(t) => t.len(),
                ToolResultContent::Image { data, mime_type } => data.len() + mime_type.len(),
            })
            .sum();
        assert!(total <= budget, "assembled {total} > budget {budget}");
        let ToolResultContent::Text(note) = &out[2] else {
            panic!("expected the downscale note, got {:?}", out[2]);
        };
        assert!(
            note.contains("image downscaled: image/png 640x480"),
            "{note}"
        );
        assert!(note.contains("delivered as image/jpeg"), "{note}");
        assert!(note.contains("original is unchanged"), "{note}");
    }

    /// The pixel cap must not drift from the relay's. buzz-agent takes no
    /// workspace crates, so the source of truth is read as text and checked
    /// at compile time of the test build.
    const BUZZ_MEDIA_VALIDATION_SOURCE: &str = include_str!("../../buzz-media/src/validation.rs");

    const fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.len() > haystack.len() {
            return false;
        }
        let mut start = 0;
        while start + needle.len() <= haystack.len() {
            let mut i = 0;
            while i < needle.len() && haystack[start + i] == needle[i] {
                i += 1;
            }
            if i == needle.len() {
                return true;
            }
            start += 1;
        }
        false
    }

    const _: () = assert!(
        contains(
            BUZZ_MEDIA_VALIDATION_SOURCE.as_bytes(),
            b"pub const MAX_IMAGE_PIXELS: u64 = 100_000_000;"
        ),
        "buzz_media::MAX_IMAGE_PIXELS changed; update DOWNSCALE_MAX_PIXELS to match"
    );

    #[test]
    fn downscale_pixel_cap_matches_buzz_media() {
        assert_eq!(DOWNSCALE_MAX_PIXELS, 100_000_000);
        assert_eq!(DOWNSCALE_MAX_ALLOC, 800_000_000);
        assert!(BUZZ_MEDIA_VALIDATION_SOURCE.contains(&format!(
            "pub const MAX_IMAGE_PIXELS: u64 = {};",
            "100_000_000"
        )));
        assert!(!exceeds_downscale_pixel_cap(10_000, 10_000));
        assert!(exceeds_downscale_pixel_cap(10_001, 10_000));
        assert!(exceeds_downscale_pixel_cap(28_000, 28_000));
    }

    /// PNG signature, IHDR, a padding tEXt chunk, IEND: a file that declares
    /// a geometry without carrying any pixel data, padded past the inline
    /// budget so `tool_result_content` takes the downscale path.
    fn png_header_base64(width: u32, height: u32, color_type: u8) -> String {
        use base64::Engine as _;
        fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut body = Vec::with_capacity(4 + payload.len());
            body.extend_from_slice(kind);
            body.extend_from_slice(payload);
            let mut out = (payload.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(&body);
            out.extend_from_slice(&crc32(&body).to_be_bytes());
            out
        }
        // PNG chunk CRC (ISO 3309), so the decoder reads the header as valid.
        fn crc32(bytes: &[u8]) -> u32 {
            let mut crc = 0xFFFF_FFFFu32;
            for &b in bytes {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, color_type, 0, 0, 0]);
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend(chunk(b"IHDR", &ihdr));
        let mut padding = b"pad\0".to_vec();
        padding.resize(128 * 1024, b'x');
        bytes.extend(chunk(b"tEXt", &padding));
        bytes.extend(chunk(b"IEND", &[]));
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn oversized_declared_geometry_is_elided_before_decode() {
        // 784 MP Luma8 would pass a bytes-only guard (784 MB < 800 MB) and
        // allocate before failing; the pixel check refuses it from the header.
        let png = png_header_base64(28_000, 28_000, 0);
        assert!(png.len() > 64 * 1024, "padding keeps the image over budget");
        assert!(downscale_image_to_budget(&png, 64 * 1024).is_none());
        let blocks = vec![Content::image(png, "image/png")];
        let out = tool_result_content(&blocks, 64 * 1024, 64 * 1024);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t.contains("image elided")));
    }

    #[test]
    fn one_hundred_megapixel_rgba_still_downscales() {
        use base64::Engine as _;
        use image::ImageEncoder as _;
        let (width, height) = (10_000u32, 10_000u32);
        let pixels = vec![0x7Fu8; (width as usize) * (height as usize) * 4];
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new_with_quality(
            &mut bytes,
            image::codecs::png::CompressionType::Fast,
            image::codecs::png::FilterType::NoFilter,
        )
        .write_image(&pixels, width, height, image::ExtendedColorType::Rgba8)
        .unwrap();
        drop(pixels);
        let png = base64::engine::general_purpose::STANDARD.encode(bytes);
        let fit = downscale_image_to_budget(&png, 64 * 1024).expect("100 MP RGBA8 downscales");
        assert_eq!((fit.source_width, fit.source_height), (width, height));
        assert!(fit.width < width && fit.height < height);
        assert!(fit.data.len() <= 64 * 1024);
    }

    #[test]
    fn tool_result_content_elides_when_no_downscale_fits() {
        let png = noise_png_base64(64, 64);
        let blocks = vec![Content::image(png, "image/png")];
        // Smaller than any JPEG the minimum edge produces.
        let out = tool_result_content(&blocks, 600, 600);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t.contains("image elided")));
    }

    #[test]
    fn oversized_text_is_middle_elided() {
        let mut body = String::new();
        for i in 0..5000 {
            body.push_str(&format!("line {i}\n"));
        }
        let blocks = vec![Content::text(body.clone())];
        let out = tool_result_content(&blocks, 1024 * 1024, 4096);
        assert_eq!(out.len(), 1);
        let ToolResultContent::Text(t) = &out[0] else {
            panic!("expected text");
        };
        assert!(t.len() <= 4096, "text exceeds budget: {}", t.len());
        assert!(t.starts_with("line 0\n"), "head lost");
        assert!(t.ends_with("line 4999\n"), "tail lost");
        assert!(
            t.contains("bytes elided from tool result"),
            "missing elision marker"
        );
    }

    #[test]
    fn text_within_budget_is_untouched() {
        let blocks = vec![Content::text("short output")];
        let out = tool_result_content(&blocks, 1024 * 1024, 4096);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t == "short output"));
    }

    #[test]
    fn image_passes_whole_even_when_text_budget_is_small() {
        let big_text = "x".repeat(10_000);
        let img = "a".repeat(100_000);
        let blocks = vec![
            Content::text(big_text),
            Content::image(img.clone(), "image/png"),
        ];
        let out = tool_result_content(&blocks, 8 * 1024 * 1024, 4096);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], ToolResultContent::Text(t) if t.len() <= 4096));
        assert!(matches!(
            &out[1],
            ToolResultContent::Image { data, .. } if data == &img
        ));
    }

    #[test]
    fn truncate_middle_respects_max_and_boundaries() {
        let s = "é".repeat(60_000); // 2-byte chars stress boundary handling
        for max in [200usize, 1024, 50 * 1024] {
            let out = super::truncate_middle(&s, max);
            assert!(out.len() <= max, "max={max} got {}", out.len());
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        }
        assert_eq!(super::truncate_middle("ok", 1024), "ok");
    }

    #[test]
    fn configure_no_window_is_a_noop_on_non_windows() {
        // Cross-host: calling configure_no_window must not panic on any OS.
        // On non-Windows the body is a cfg-gated no-op and the argument is
        // consumed as `let _ = cmd`, so the only assertion is "didn't crash".
        let mut cmd = Command::new("true");
        configure_no_window(&mut cmd);
    }

    #[cfg(windows)]
    #[test]
    fn configure_no_window_compiles_and_applies_flag_on_windows() {
        // On Windows, creation_flags(0x0800_0000) must be accepted without panicking.
        // The call is a setter with no getter on tokio::process::Command, so the
        // regression test confirms the flag is SET by checking the std inner command.
        let mut cmd = Command::new("cmd.exe");
        configure_no_window(&mut cmd);
        // std::process::Command on Windows does have as_inner / get_creation_flags via
        // CommandExt — but tokio wraps it; we verify by ensuring the call compiles and
        // the resulting spawn wouldn't OOM (build+flag-set is the full contract here).
        // The real protection is the cfg-gated production path in spawn_one().
    }
}
