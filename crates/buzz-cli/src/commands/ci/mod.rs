use clap::Subcommand;

// Candidate A compiles and tests these pure helpers before relay/API v1.2
// supplies the signer-authority and watch transport wiring used by dispatch.
#[allow(dead_code)]
pub mod evidence;
#[allow(dead_code)]
pub mod reducer;
#[allow(dead_code)]
pub mod run;
#[allow(dead_code)]
pub mod watch;

/// Commands for triggering and inspecting Buzz CI runs.
#[derive(Subcommand)]
pub enum CiCmd {
    /// Trigger a CI run for an exact repository revision
    Run {
        /// Repository owner public key (hex)
        #[arg(long)]
        repo_owner: String,
        /// Repository identifier (`d` tag)
        #[arg(long)]
        repo_id: String,
        /// Exact full source object ID
        #[arg(long)]
        sha: String,
        /// Workflow ID or digest
        #[arg(long)]
        workflow: Option<String>,
        /// Comma-separated job IDs; omit to select the complete workflow job set
        #[arg(long, value_delimiter = ',')]
        jobs: Vec<String>,
    },
    /// Show the current state of a CI run
    Status {
        /// CI run ID
        #[arg(long)]
        run: String,
    },
    /// Read finalized logs for one job attempt
    Logs {
        /// CI run ID
        #[arg(long)]
        run: String,
        /// Workflow job ID
        #[arg(long)]
        job: String,
        /// Exact attempt number; omit to select the greatest known attempt
        #[arg(long)]
        attempt: Option<u32>,
        /// Write raw scrubbed log bytes instead of JSON
        #[arg(long)]
        raw: bool,
    },
    /// Rerun a failed CI job
    Rerun {
        /// CI run ID
        #[arg(long)]
        run: String,
        /// Failed workflow job ID
        #[arg(long)]
        job: String,
    },
    /// Reduce a CI run to its current verdict
    Verdict {
        /// CI run ID
        #[arg(long)]
        run: String,
        /// Exact full source object ID expected by the caller
        #[arg(long)]
        expect_sha: String,
    },
    /// Stream ordered transitions until the run becomes terminal
    Watch {
        /// CI run ID
        #[arg(long)]
        run: String,
    },
}
