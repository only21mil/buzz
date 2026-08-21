use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::{geteuid, Pid};
use sha2::{Digest, Sha256};

use crate::{
    CleanupProof, CommandExecution, CommandOutput, CommandSpec, GitBackend, GitOperation,
    MaterializeError, NetworkScope, Sha256Digest,
};

const PIPE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Root-owned observations that the unprivileged process runner cannot derive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHostObservation {
    /// Bytes read from the exact lease-bound nft counter delta.
    pub network_bytes: u64,
    /// True only after the exact materializer cgroup was read empty.
    pub cgroup_descendants_empty: bool,
    /// Trusted host wall clock after cgroup cleanup and counter readback.
    pub completed_at_unix_seconds: u64,
}

/// Host seam for lease-bound network and cgroup evidence.
///
/// `ProcessGitBackend` owns the child process group, output pipes, and timeout.
/// The ordinary lease machine owns nft counters and cgroup descriptors, so it
/// must supply this observer. A command never succeeds without both readbacks.
pub trait GitHostObserver {
    /// Opaque counter/readback checkpoint captured before spawn.
    type Checkpoint;

    /// Capture the exact lease-bound state before a command starts.
    fn before_command(&mut self, command: &CommandSpec) -> Result<Self::Checkpoint, String>;

    /// Read the counter delta and exact cgroup state after process-group cleanup.
    fn after_command(
        &mut self,
        checkpoint: Self::Checkpoint,
        command: &CommandSpec,
        process_group_empty: bool,
    ) -> Result<GitHostObservation, String>;
}

/// Result retained for broker evidence translation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommandResultLog {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_sha256: Sha256Digest,
    pub stderr_sha256: Sha256Digest,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// Exact command and result retained until execd publishes `commands.jsonl`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommandLog {
    pub sequence: u64,
    pub command: CommandSpec,
    pub result: GitCommandResultLog,
    pub started_at_unix_ns: u64,
    pub finished_at_unix_ns: u64,
}

/// Concrete no-shell Git runner for one already-isolated materializer lease.
pub struct ProcessGitBackend<O> {
    program: PathBuf,
    required_uid: u32,
    lease_id: String,
    cgroup_token: String,
    netns_token: String,
    observer: O,
    command_logs: Vec<GitCommandLog>,
}

impl<O> ProcessGitBackend<O> {
    /// Bind the runner to one root-owned program and lease capability set.
    pub fn new(
        program: PathBuf,
        required_uid: u32,
        lease_id: String,
        cgroup_token: String,
        netns_token: String,
        observer: O,
    ) -> Result<Self, MaterializeError> {
        if !program.is_absolute()
            || lease_id.is_empty()
            || cgroup_token.is_empty()
            || netns_token.is_empty()
        {
            return Err(MaterializeError::InvalidPolicy(
                "Git backend binding is incomplete".into(),
            ));
        }
        Ok(Self {
            program,
            required_uid,
            lease_id,
            cgroup_token,
            netns_token,
            observer,
            command_logs: Vec::new(),
        })
    }

    /// Ordered command records ready for execd evidence translation.
    pub fn command_logs(&self) -> &[GitCommandLog] {
        &self.command_logs
    }

    /// Consume the backend and return its host observer and command records.
    pub fn into_parts(self) -> (O, Vec<GitCommandLog>) {
        (self.observer, self.command_logs)
    }
}

impl<O: GitHostObserver> GitBackend for ProcessGitBackend<O> {
    fn now_unix_seconds(&self) -> u64 {
        unix_time().map(|value| value.0).unwrap_or(u64::MAX)
    }

    fn run(&mut self, command: &CommandSpec, workspace_directory: &File) -> CommandExecution {
        if let Err(error) = self.validate_command(command, workspace_directory) {
            return CommandExecution {
                output: Err(error),
                cleanup: failed_cleanup(command),
            };
        }
        let checkpoint = match self.observer.before_command(command) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                return CommandExecution {
                    output: Err(bounded_diagnostic(&error)),
                    cleanup: failed_cleanup(command),
                };
            }
        };
        let started_at_unix_ns = unix_time().map(|value| value.1).unwrap_or(0);
        let process = run_process(command, workspace_directory);
        let finished_at_unix_ns = unix_time()
            .map(|value| value.1.max(started_at_unix_ns))
            .unwrap_or(started_at_unix_ns);
        let observation =
            self.observer
                .after_command(checkpoint, command, process.process_group_empty);
        self.command_logs.push(GitCommandLog {
            sequence: self.command_logs.len() as u64 + 1,
            command: command.clone(),
            result: GitCommandResultLog {
                exit_code: process.exit_code,
                timed_out: process.timed_out,
                stdout_sha256: process.stdout.digest(),
                stderr_sha256: process.stderr.digest(),
                stdout_bytes: process.stdout.observed_bytes,
                stderr_bytes: process.stderr.observed_bytes,
                stdout_truncated: process.stdout.truncated,
                stderr_truncated: process.stderr.truncated,
            },
            started_at_unix_ns,
            finished_at_unix_ns,
        });

        let observation = match observation {
            Ok(observation) => observation,
            Err(error) => {
                return CommandExecution {
                    output: Err(bounded_diagnostic(&error)),
                    cleanup: failed_cleanup(command),
                };
            }
        };
        let cleanup = CleanupProof {
            lease_id: command.lease_id.clone(),
            cgroup_token: command.cgroup_token.clone(),
            netns_token: command.netns_token.clone(),
            descendants_empty: process.process_group_empty && observation.cgroup_descendants_empty,
            completed_at_unix_seconds: observation.completed_at_unix_seconds,
        };
        let output = process.output(command, observation.network_bytes, self.required_uid);
        CommandExecution { output, cleanup }
    }
}

fn failed_cleanup(command: &CommandSpec) -> CleanupProof {
    CleanupProof {
        lease_id: command.lease_id.clone(),
        cgroup_token: command.cgroup_token.clone(),
        netns_token: command.netns_token.clone(),
        descendants_empty: false,
        completed_at_unix_seconds: unix_time().map(|value| value.0).unwrap_or(u64::MAX),
    }
}

impl<O> ProcessGitBackend<O> {
    fn validate_command(
        &self,
        command: &CommandSpec,
        workspace_directory: &File,
    ) -> Result<(), String> {
        let expected_cwd =
            PathBuf::from(format!("/proc/self/fd/{}", workspace_directory.as_raw_fd()));
        if command.program != self.program
            || command.required_uid != self.required_uid
            || command.required_uid != geteuid().as_raw()
            || command.lease_id != self.lease_id
            || command.cgroup_token != self.cgroup_token
            || command.netns_token != self.netns_token
            || command.current_dir != expected_cwd
            || !workspace_directory
                .metadata()
                .is_ok_and(|metadata| metadata.is_dir())
            || command.deadline_millis == 0
            || command.maximum_stdout_bytes == 0
            || command.maximum_stderr_bytes == 0
            || command.maximum_processes == 0
        {
            return Err("Git command does not match the bound host capability".into());
        }
        validate_environment(command)?;
        let operation = validate_argv(command)?;
        if operation != command.operation {
            return Err("Git operation label does not match its exact argv".into());
        }
        Ok(())
    }
}

fn validate_environment(command: &CommandSpec) -> Result<(), String> {
    if !command.clear_environment {
        return Err("Git command must clear the inherited environment".into());
    }
    let git_exec_path = command
        .environment
        .get("GIT_EXEC_PATH")
        .filter(|value| Path::new(value).is_absolute())
        .cloned()
        .ok_or_else(|| "Git command lacks an absolute GIT_EXEC_PATH".to_owned())?;
    let expected = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("GIT_EXEC_PATH".to_owned(), git_exec_path),
        ("HOME".to_owned(), "/proc/self/cwd/home".to_owned()),
        ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
        ("GIT_CONFIG_COUNT".to_owned(), "2".to_owned()),
        (
            "GIT_CONFIG_KEY_0".to_owned(),
            "credential.helper".to_owned(),
        ),
        ("GIT_CONFIG_VALUE_0".to_owned(), String::new()),
        ("GIT_CONFIG_KEY_1".to_owned(), "core.hooksPath".to_owned()),
        ("GIT_CONFIG_VALUE_1".to_owned(), "/dev/null".to_owned()),
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("GIT_ASKPASS".to_owned(), "/bin/false".to_owned()),
        ("SSH_ASKPASS".to_owned(), "/bin/false".to_owned()),
        ("GIT_LFS_SKIP_SMUDGE".to_owned(), "1".to_owned()),
    ]);
    if command.environment != expected {
        return Err("Git command environment differs from the frozen set".into());
    }
    Ok(())
}

fn validate_argv(command: &CommandSpec) -> Result<GitOperation, String> {
    let arguments = &command.arguments;
    if arguments.first().map(String::as_str) != Some("--git-dir=objects.git") {
        return Err("Git command must use the private bare object database".into());
    }
    if arguments == &["--git-dir=objects.git", "init", "--bare"] {
        return require_no_network(command, GitOperation::Init);
    }
    if arguments.get(1).map(String::as_str) == Some("fetch")
        || arguments.iter().any(|argument| argument == "fetch")
    {
        return validate_fetch(command);
    }
    if arguments.get(1).map(String::as_str) == Some("rev-parse") {
        let prefix = [
            "--git-dir=objects.git",
            "rev-parse",
            "--verify",
            "--end-of-options",
        ];
        if arguments.len() != 5 || !arguments.iter().take(4).map(String::as_str).eq(prefix) {
            return Err("rev-parse argv differs from the frozen form".into());
        }
        let reference = &arguments[4];
        let operation = match reference.as_str() {
            "refs/buzz/materialize/candidate^{commit}" => GitOperation::ReadCommit,
            "refs/buzz/materialize/candidate^{tree}" => GitOperation::ReadTree,
            "refs/buzz/materialize/trusted-base^{commit}" => GitOperation::ReadCommit,
            _ => {
                let path = reference
                    .strip_prefix("refs/buzz/materialize/trusted-base:")
                    .ok_or_else(|| "rev-parse requested an unexpected ref".to_owned())?;
                crate::manifest::validate_relative_path(path)
                    .map_err(|_| "rev-parse requested an unsafe workflow path".to_owned())?;
                GitOperation::ReadWorkflow
            }
        };
        return require_no_network(command, operation);
    }
    if arguments
        == &[
            "--git-dir=objects.git",
            "ls-tree",
            "-r",
            "-z",
            "-l",
            "--full-tree",
            "refs/buzz/materialize/candidate",
        ]
    {
        return require_no_network(command, GitOperation::ReadTree);
    }
    if arguments.len() == 4
        && arguments[1] == "cat-file"
        && arguments[2] == "blob"
        && valid_object_id(&arguments[3])
    {
        if !matches!(
            command.operation,
            GitOperation::ReadBlob | GitOperation::ReadWorkflow
        ) {
            return Err("cat-file operation label is not a raw blob read".into());
        }
        return require_no_network(command, command.operation);
    }
    Err("Git argv is outside the frozen raw-object protocol".into())
}

fn validate_fetch(command: &CommandSpec) -> Result<GitOperation, String> {
    const PREFIX: [&str; 28] = [
        "--git-dir=objects.git",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.http.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "http.followRedirects=false",
        "-c",
        "http.proxy=",
        "-c",
        "submodule.recurse=false",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.process=",
        "-c",
    ];
    const SUFFIX: [&str; 9] = [
        "filter.lfs.required=false",
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        "--no-write-fetch-head",
        "--depth=1",
        "",
        "",
        "",
    ];
    if command.arguments.len() != PREFIX.len() + SUFFIX.len()
        || !command
            .arguments
            .iter()
            .take(PREFIX.len())
            .map(String::as_str)
            .eq(PREFIX)
        || !command.arguments[PREFIX.len()..PREFIX.len() + 6]
            .iter()
            .map(String::as_str)
            .eq(SUFFIX[..6].iter().copied())
    {
        return Err("fetch argv differs from the frozen form".into());
    }
    let origin_index = PREFIX.len() + 6;
    let origin = &command.arguments[origin_index];
    let NetworkScope::Origin { url } = &command.network else {
        return Err("fetch lacks its exact origin network grant".into());
    };
    if origin != url || command.maximum_network_bytes == 0 {
        return Err("fetch origin does not match its network grant".into());
    }
    let parsed = url::Url::parse(origin).map_err(|_| "fetch origin is not a URL".to_owned())?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("fetch origin is not credential-free HTTPS".into());
    }
    validate_refspec(
        &command.arguments[origin_index + 1],
        "refs/buzz/materialize/candidate",
    )?;
    validate_refspec(
        &command.arguments[origin_index + 2],
        "refs/buzz/materialize/trusted-base",
    )?;
    Ok(GitOperation::FetchExactObject)
}

fn validate_refspec(value: &str, destination: &str) -> Result<(), String> {
    let (object_id, actual_destination) = value
        .strip_prefix('+')
        .and_then(|value| value.split_once(':'))
        .ok_or_else(|| "fetch refspec is malformed".to_owned())?;
    if !valid_object_id(object_id) || actual_destination != destination {
        return Err("fetch refspec targets an unexpected ref".into());
    }
    Ok(())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_no_network(
    command: &CommandSpec,
    operation: GitOperation,
) -> Result<GitOperation, String> {
    if !matches!(command.network, NetworkScope::None) || command.maximum_network_bytes != 0 {
        return Err("non-fetch Git command received a network grant".into());
    }
    Ok(operation)
}

struct ProcessRun {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    elapsed_millis: u64,
    process_group_empty: bool,
    transport_error: Option<String>,
}

impl ProcessRun {
    fn output(
        &self,
        command: &CommandSpec,
        network_bytes: u64,
        effective_uid: u32,
    ) -> Result<CommandOutput, String> {
        if let Some(error) = &self.transport_error {
            return Err(bounded_diagnostic(error));
        }
        if self.timed_out {
            return Err("Git command exceeded its timeout".into());
        }
        if self.elapsed_millis > command.deadline_millis {
            return Err("Git command exceeded its timeout".into());
        }
        if self.stdout.truncated || self.stderr.truncated {
            return Err("Git command output exceeded its byte ceiling".into());
        }
        if self.exit_code != Some(0) {
            return Err(bounded_diagnostic(&format!(
                "Git exited nonzero: {}",
                String::from_utf8_lossy(&self.stderr.retained)
            )));
        }
        if !self.process_group_empty {
            return Err("Git process group remained live after cleanup".into());
        }
        Ok(CommandOutput {
            success: true,
            stdout: self.stdout.retained.clone(),
            stderr: self.stderr.retained.clone(),
            network_bytes,
            elapsed_millis: self.elapsed_millis,
            effective_uid,
        })
    }
}

fn run_process(command: &CommandSpec, workspace_directory: &File) -> ProcessRun {
    let started = Instant::now();
    let mut process = Command::new(&command.program);
    process
        .args(&command.arguments)
        .env_clear()
        .envs(&command.environment)
        .current_dir(format!("/proc/self/fd/{}", workspace_directory.as_raw_fd()))
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return ProcessRun::spawn_error(error, started),
    };
    let process_group = child.id();
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return ProcessRun::pipe_error(&mut child, process_group, started),
    };
    let mut stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => return ProcessRun::pipe_error(&mut child, process_group, started),
    };
    if let Err(error) = set_nonblocking(&stdout).and_then(|_| set_nonblocking(&stderr)) {
        let _ = terminate_group(&mut child, process_group);
        return ProcessRun::transport_error(
            error.to_string(),
            started,
            wait_for_empty_group(process_group),
        );
    }
    let mut stdout_state = BoundedOutput::new(command.maximum_stdout_bytes);
    let mut stderr_state = BoundedOutput::new(command.maximum_stderr_bytes);
    let deadline = Duration::from_millis(command.deadline_millis);
    let (exit_code, timed_out) = loop {
        if let Err(error) = stdout_state
            .drain(&mut stdout)
            .and_then(|_| stderr_state.drain(&mut stderr))
        {
            let _ = terminate_group(&mut child, process_group);
            return ProcessRun::transport_error(
                error.to_string(),
                started,
                wait_for_empty_group(process_group),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break (status.code(), started.elapsed() > deadline);
            }
            Ok(None) if started.elapsed() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = terminate_group(&mut child, process_group);
                break (
                    child
                        .try_wait()
                        .ok()
                        .flatten()
                        .and_then(|status| status.code()),
                    true,
                );
            }
            Err(error) => {
                let _ = terminate_group(&mut child, process_group);
                return ProcessRun::transport_error(
                    error.to_string(),
                    started,
                    wait_for_empty_group(process_group),
                );
            }
        }
    };
    let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
    let drain_result = drain_until_closed(
        &mut stdout,
        &mut stderr,
        &mut stdout_state,
        &mut stderr_state,
    );
    let process_group_empty = wait_for_empty_group(process_group);
    ProcessRun {
        exit_code,
        timed_out,
        stdout: stdout_state,
        stderr: stderr_state,
        elapsed_millis: elapsed_millis(started),
        process_group_empty,
        transport_error: drain_result.err().map(|error| error.to_string()),
    }
}

impl ProcessRun {
    fn spawn_error(error: std::io::Error, started: Instant) -> Self {
        Self::transport_error(error.to_string(), started, true)
    }

    fn pipe_error(child: &mut std::process::Child, process_group: u32, started: Instant) -> Self {
        let _ = terminate_group(child, process_group);
        Self::transport_error(
            "Git output pipe was unavailable".into(),
            started,
            wait_for_empty_group(process_group),
        )
    }

    fn transport_error(error: String, started: Instant, process_group_empty: bool) -> Self {
        Self {
            exit_code: None,
            timed_out: false,
            stdout: BoundedOutput::new(1),
            stderr: BoundedOutput::new(1),
            elapsed_millis: elapsed_millis(started),
            process_group_empty,
            transport_error: Some(error),
        }
    }
}

struct BoundedOutput {
    retained: Vec<u8>,
    digest: Sha256,
    observed_bytes: u64,
    maximum_bytes: u64,
    truncated: bool,
    eof: bool,
}

impl BoundedOutput {
    fn new(maximum_bytes: u64) -> Self {
        Self {
            retained: Vec::new(),
            digest: Sha256::new(),
            observed_bytes: 0,
            maximum_bytes,
            truncated: false,
            eof: false,
        }
    }

    fn drain(&mut self, reader: &mut impl Read) -> Result<(), std::io::Error> {
        let mut buffer = [0_u8; 8_192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    self.digest.update(&buffer[..count]);
                    self.observed_bytes = self.observed_bytes.saturating_add(count as u64);
                    let remaining = self
                        .maximum_bytes
                        .saturating_sub(self.retained.len() as u64)
                        .min(usize::MAX as u64) as usize;
                    let copied = remaining.min(count);
                    self.retained.extend_from_slice(&buffer[..copied]);
                    self.truncated |= copied != count;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_sha256_bytes(self.digest.clone().finalize().into())
    }
}

fn set_nonblocking(fd: &impl AsFd) -> Result<(), std::io::Error> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    Ok(())
}

fn terminate_group(child: &mut std::process::Child, process_group: u32) -> Result<(), String> {
    match killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => return Err(error.to_string()),
    }
    child.wait().map_err(|error| error.to_string())?;
    Ok(())
}

fn drain_until_closed(
    stdout: &mut impl Read,
    stderr: &mut impl Read,
    stdout_state: &mut BoundedOutput,
    stderr_state: &mut BoundedOutput,
) -> Result<(), std::io::Error> {
    let started = Instant::now();
    while !(stdout_state.eof && stderr_state.eof) {
        stdout_state.drain(stdout)?;
        stderr_state.drain(stderr)?;
        if started.elapsed() >= PIPE_CLOSE_TIMEOUT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Git output pipes did not close",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

fn wait_for_empty_group(process_group: u32) -> bool {
    let started = Instant::now();
    loop {
        match kill(Pid::from_raw(-(process_group as i32)), None) {
            Err(Errno::ESRCH) => return true,
            Ok(()) | Err(_) if started.elapsed() < PIPE_CLOSE_TIMEOUT => {
                thread::sleep(POLL_INTERVAL)
            }
            Ok(()) | Err(_) => return false,
        }
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn unix_time() -> Result<(u64, u64), std::time::SystemTimeError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok((
        elapsed.as_secs(),
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
    ))
}

fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(8_192).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::process::Stdio;

    #[derive(Default)]
    struct LocalObserver;

    impl GitHostObserver for LocalObserver {
        type Checkpoint = ();

        fn before_command(&mut self, _command: &CommandSpec) -> Result<Self::Checkpoint, String> {
            Ok(())
        }

        fn after_command(
            &mut self,
            _checkpoint: Self::Checkpoint,
            _command: &CommandSpec,
            process_group_empty: bool,
        ) -> Result<GitHostObservation, String> {
            Ok(GitHostObservation {
                network_bytes: 0,
                cgroup_descendants_empty: process_group_empty,
                completed_at_unix_seconds: unix_time().unwrap().0,
            })
        }
    }

    fn backend() -> ProcessGitBackend<LocalObserver> {
        ProcessGitBackend::new(
            "/usr/bin/git".into(),
            geteuid().as_raw(),
            "lease-1".into(),
            "cgroup-token".into(),
            "netns-token".into(),
            LocalObserver,
        )
        .unwrap()
    }

    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("GIT_EXEC_PATH".into(), "/usr/lib/git-core".into()),
            ("HOME".into(), "/proc/self/cwd/home".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ("GIT_CONFIG_COUNT".into(), "2".into()),
            ("GIT_CONFIG_KEY_0".into(), "credential.helper".into()),
            ("GIT_CONFIG_VALUE_0".into(), String::new()),
            ("GIT_CONFIG_KEY_1".into(), "core.hooksPath".into()),
            ("GIT_CONFIG_VALUE_1".into(), "/dev/null".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_ASKPASS".into(), "/bin/false".into()),
            ("SSH_ASKPASS".into(), "/bin/false".into()),
            ("GIT_LFS_SKIP_SMUDGE".into(), "1".into()),
        ])
    }

    fn spec(directory: &File, operation: GitOperation, arguments: Vec<String>) -> CommandSpec {
        CommandSpec {
            operation,
            program: "/usr/bin/git".into(),
            arguments,
            current_dir: PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())),
            clear_environment: true,
            environment: environment(),
            required_uid: geteuid().as_raw(),
            lease_id: "lease-1".into(),
            cgroup_token: "cgroup-token".into(),
            netns_token: "netns-token".into(),
            lease_expires_at_unix_seconds: unix_time().unwrap().0 + 60,
            maximum_stdout_bytes: 4_096,
            maximum_stderr_bytes: 4_096,
            deadline_millis: 2_000,
            network: NetworkScope::None,
            maximum_network_bytes: 0,
            maximum_processes: 32,
        }
    }

    fn init_repository(workspace: &Path, directory: &File) {
        fs::create_dir(workspace.join("home")).unwrap();
        let command = spec(
            directory,
            GitOperation::Init,
            vec![
                "--git-dir=objects.git".into(),
                "init".into(),
                "--bare".into(),
            ],
        );
        let output = backend().run(&command, directory);
        assert!(output.output.is_ok(), "{:?}", output.output);
    }

    fn write_blob(workspace: &Path, bytes: &[u8]) -> String {
        let mut child = Command::new("/usr/bin/git")
            .args(["--git-dir=objects.git", "hash-object", "-w", "--stdin"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn real_git_uses_the_retained_workspace_descriptor_after_path_swap() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspace");
        let moved = temporary.path().join("retained");
        let hostile = temporary.path().join("hostile");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&hostile).unwrap();
        let directory = File::open(&workspace).unwrap();
        fs::rename(&workspace, &moved).unwrap();
        symlink(&hostile, &workspace).unwrap();

        init_repository(&moved, &directory);

        assert!(moved.join("objects.git").is_dir());
        assert!(hostile.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn unexpected_ref_is_rejected_before_git_runs() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let command = spec(
            &directory,
            GitOperation::ReadCommit,
            vec![
                "--git-dir=objects.git".into(),
                "rev-parse".into(),
                "--verify".into(),
                "--end-of-options".into(),
                "refs/heads/main^{commit}".into(),
            ],
        );
        let execution = backend().run(&command, &directory);
        assert!(execution.output.unwrap_err().contains("unexpected ref"));
    }

    #[test]
    fn frozen_fetch_accepts_only_the_two_private_destination_refs() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let mut arguments = vec![
            "--git-dir=objects.git",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.http.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.proxy=",
            "-c",
            "submodule.recurse=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.process=",
            "-c",
            "filter.lfs.required=false",
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--depth=1",
            "https://relay.example/git/owner/repo",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        arguments.push(format!(
            "+{}:refs/buzz/materialize/candidate",
            "a".repeat(40)
        ));
        arguments.push(format!(
            "+{}:refs/buzz/materialize/trusted-base",
            "b".repeat(40)
        ));
        let mut command = spec(&directory, GitOperation::FetchExactObject, arguments);
        command.network = NetworkScope::Origin {
            url: "https://relay.example/git/owner/repo".into(),
        };
        command.maximum_network_bytes = 1_024;
        assert_eq!(validate_argv(&command), Ok(GitOperation::FetchExactObject));

        *command.arguments.last_mut().unwrap() = format!("+{}:refs/heads/main", "b".repeat(40));
        assert!(validate_argv(&command)
            .unwrap_err()
            .contains("unexpected ref"));
    }

    #[test]
    fn oversized_real_git_output_fails_closed_and_is_logged() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path();
        let directory = File::open(workspace).unwrap();
        init_repository(workspace, &directory);
        let object_id = write_blob(workspace, &[b'x'; 8_192]);
        let mut command = spec(
            &directory,
            GitOperation::ReadBlob,
            vec![
                "--git-dir=objects.git".into(),
                "cat-file".into(),
                "blob".into(),
                object_id,
            ],
        );
        command.maximum_stdout_bytes = 32;
        let mut backend = backend();
        let execution = backend.run(&command, &directory);
        assert!(execution.output.unwrap_err().contains("byte ceiling"));
        assert!(backend.command_logs()[0].result.stdout_truncated);
        assert_eq!(backend.command_logs()[0].result.stdout_bytes, 8_192);
    }

    #[test]
    fn real_git_nonzero_exit_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path();
        let directory = File::open(workspace).unwrap();
        init_repository(workspace, &directory);
        let command = spec(
            &directory,
            GitOperation::ReadBlob,
            vec![
                "--git-dir=objects.git".into(),
                "cat-file".into(),
                "blob".into(),
                "a".repeat(40),
            ],
        );
        let execution = backend().run(&command, &directory);
        assert!(execution.output.unwrap_err().contains("nonzero"));
    }

    #[test]
    fn blocked_real_git_read_is_killed_at_the_deadline() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path();
        let directory = File::open(workspace).unwrap();
        init_repository(workspace, &directory);
        let alternates = workspace.join("objects.git/objects/info/alternates");
        mkfifo(&alternates, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let mut command = spec(
            &directory,
            GitOperation::ReadBlob,
            vec![
                "--git-dir=objects.git".into(),
                "cat-file".into(),
                "blob".into(),
                "b".repeat(40),
            ],
        );
        command.deadline_millis = 50;
        let started = Instant::now();
        let mut backend = backend();
        let execution = backend.run(&command, &directory);
        assert!(execution.output.unwrap_err().contains("timeout"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(backend.command_logs()[0].result.timed_out);
    }
}
