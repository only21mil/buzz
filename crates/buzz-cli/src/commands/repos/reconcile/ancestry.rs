//! Exact main refs on both remotes and commit containment, read through git.
//! Refs are read fresh each run; only objects persist in the cache.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::client::BuzzClient;
use crate::commands::repo_sync::{
    auth_from_client, GitHubAuth, GitHubRepo, GitRepo, RemoteAuth, RemoteState, MAIN_REF,
};
use crate::error::CliError;

const BUZZ_TRACKING: &str = "refs/remotes/buzz/main";
const MIRROR_TRACKING: &str = "refs/remotes/github/main";

/// Where one commit sits relative to the two main refs read this run.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct Containment {
    pub(super) in_buzz_main: bool,
    pub(super) in_mirror_main: bool,
    /// First-parent commit of Buzz main that brought this commit in.
    pub(super) landing: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(super) struct GitEvidence {
    pub(super) buzz_main: Option<String>,
    pub(super) mirror_main: Option<String>,
    pub(super) commits: BTreeMap<String, Containment>,
    /// `older:newer` -> older is an ancestor of, or equal to, newer.
    pub(super) pairs: BTreeMap<String, bool>,
}

pub(super) fn pair_key(older: &str, newer: &str) -> String {
    format!("{older}:{newer}")
}

pub(super) struct GitReader {
    repo: GitRepo,
    buzz_url: String,
    mirror_url: Option<String>,
}

impl GitReader {
    pub(super) fn open(
        client: &BuzzClient,
        buzz_url: String,
        mirror: Option<&GitHubRepo>,
        github_auth: GitHubAuth,
        cache: std::path::PathBuf,
    ) -> Result<Self, CliError> {
        let repo = GitRepo::persistent(cache, auth_from_client(client), github_auth)?;
        Ok(Self {
            repo,
            buzz_url,
            mirror_url: mirror.map(|mirror| mirror.clone_url.clone()),
        })
    }

    /// Exact main plus HEAD symref on the relay and, when configured, exact
    /// main on the mirror.
    pub(super) fn read_mains(&self) -> Result<(RemoteState, Option<String>), CliError> {
        let buzz = self
            .repo
            .ls_remote(&self.buzz_url, RemoteAuth::Buzz, "Buzz")?;
        let mirror = match &self.mirror_url {
            Some(url) => self
                .repo
                .remote_ref(url, RemoteAuth::GitHub, "GitHub", MAIN_REF)?,
            None => None,
        };
        Ok((buzz, mirror))
    }

    /// All relay branches with `fully_merged` computed against the exact
    /// Buzz main read this run. Used when the hosted refs endpoint is absent.
    pub(super) fn heads(
        &self,
        buzz_main: Option<&str>,
    ) -> Result<Vec<(String, String, bool)>, CliError> {
        let heads = self.repo.heads(&self.buzz_url, RemoteAuth::Buzz, "Buzz")?;
        if let Some(main) = buzz_main {
            self.repo.fetch_ref(
                &self.buzz_url,
                RemoteAuth::Buzz,
                "Buzz main",
                MAIN_REF,
                BUZZ_TRACKING,
                main,
            )?;
        }
        let mut branches = Vec::with_capacity(heads.len());
        for (name, tip) in heads {
            let merged = match buzz_main {
                Some(main) => self.repo.has_commit(&tip)? && self.repo.is_ancestor(&tip, main)?,
                None => false,
            };
            branches.push((name, tip, merged));
        }
        Ok(branches)
    }

    /// Fetch both mains at the exact values read, then classify every
    /// candidate commit and ancestor pair against them.
    pub(super) fn evidence(
        &self,
        buzz_main: Option<&str>,
        mirror_main: Option<&str>,
        commits: &BTreeSet<String>,
        pairs: &BTreeSet<(String, String)>,
    ) -> Result<GitEvidence, CliError> {
        if let Some(main) = buzz_main {
            self.repo.fetch_ref(
                &self.buzz_url,
                RemoteAuth::Buzz,
                "Buzz main",
                MAIN_REF,
                BUZZ_TRACKING,
                main,
            )?;
        }
        if let (Some(url), Some(main)) = (&self.mirror_url, mirror_main) {
            self.repo.fetch_ref(
                url,
                RemoteAuth::GitHub,
                "GitHub main",
                MAIN_REF,
                MIRROR_TRACKING,
                main,
            )?;
        }
        let chain = match buzz_main {
            Some(main) => self.repo.first_parent_chain(main)?,
            None => Vec::new(),
        };
        let mut evidence = GitEvidence {
            buzz_main: buzz_main.map(str::to_owned),
            mirror_main: mirror_main.map(str::to_owned),
            commits: BTreeMap::new(),
            pairs: BTreeMap::new(),
        };
        for commit in commits {
            let present = self.repo.has_commit(commit)?;
            let landing = match (present, buzz_main) {
                (true, Some(main)) => self.repo.landing_commit(commit, main, &chain)?,
                _ => None,
            };
            let in_mirror_main = match (present, mirror_main) {
                (true, Some(main)) => self.repo.is_ancestor(commit, main)?,
                _ => false,
            };
            evidence.commits.insert(
                commit.clone(),
                Containment {
                    in_buzz_main: landing.is_some(),
                    in_mirror_main,
                    landing,
                },
            );
        }
        for (older, newer) in pairs {
            let contained = older == newer
                || (self.repo.has_commit(older)?
                    && self.repo.has_commit(newer)?
                    && self.repo.is_ancestor(older, newer)?);
            evidence.pairs.insert(pair_key(older, newer), contained);
        }
        Ok(evidence)
    }
}
