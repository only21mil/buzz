//! Provider, model, and credential requirements for managed runtimes.

use super::{EffectiveAgentEnv, Requirement};

/// Requirements for buzz-agent (provider + model + provider-specific creds).
pub(super) fn buzz_agent_requirements(effective: &EffectiveAgentEnv) -> Vec<Requirement> {
    let mut missing = Vec::new();

    #[cfg(windows)]
    if !crate::managed_agents::git_bash_available(&effective.env) {
        missing.push(Requirement::GitBash);
    }

    // Provider is required — maps to BUZZ_AGENT_PROVIDER in the effective env.
    // An empty string is treated as absent: a key set to "" is not a valid
    // provider and must not pass the readiness gate.
    let provider = effective
        .env
        .get("BUZZ_AGENT_PROVIDER")
        .filter(|v| !v.is_empty())
        .map(String::as_str);
    if provider.is_none() {
        missing.push(Requirement::NormalizedField {
            field: "provider".to_string(),
        });
    }

    // Model is required — maps to BUZZ_AGENT_MODEL in the effective env.
    // Same empty-string treatment as provider.
    // Also accept provider-specific model fallback keys, matching buzz-agent's
    // own config.rs `from_env()` resolution order (e.g. DATABRICKS_MODEL for
    // databricks/databricks_v2, ANTHROPIC_MODEL for anthropic, etc.). The
    // baked buzz-releases env sets DATABRICKS_MODEL but not BUZZ_AGENT_MODEL,
    // so without this fallback agents baked from releases appear "not ready".
    let provider_model_key = match provider {
        Some("databricks") | Some("databricks_v2") | Some("databricks-v2") => {
            Some("DATABRICKS_MODEL")
        }
        Some("anthropic") => Some("ANTHROPIC_MODEL"),
        Some("openai") | Some("openai-compat") => Some("OPENAI_COMPAT_MODEL"),
        Some("openrouter") => Some("OPENROUTER_MODEL"),
        _ => None,
    };
    let model_present = effective
        .env
        .get("BUZZ_AGENT_MODEL")
        .filter(|v| !v.is_empty())
        .is_some()
        || provider_model_key
            .and_then(|k| effective.env.get(k))
            .filter(|v| !v.is_empty())
            .is_some();
    if !model_present {
        missing.push(Requirement::NormalizedField {
            field: "model".to_string(),
        });
    }

    // Provider-specific credential requirements.
    // A key present with an empty value is treated as absent — matching the
    // dialog's (envVars[key] ?? "").length === 0 emptiness check.
    let env_key_missing = |key: &str| effective.env.get(key).is_none_or(|v| v.is_empty());
    match provider {
        Some("anthropic")
            if env_key_missing("ANTHROPIC_API_KEY") => {
                missing.push(Requirement::EnvKey {
                    key: "ANTHROPIC_API_KEY".to_string(),
                });
            }
        Some("openai")
            if env_key_missing("OPENAI_COMPAT_API_KEY") => {
                missing.push(Requirement::EnvKey {
                    key: "OPENAI_COMPAT_API_KEY".to_string(),
                });
            }
        Some("databricks") | Some("databricks_v2") | Some("databricks-v2")
            // DATABRICKS_HOST is hard-required; DATABRICKS_TOKEN is optional
            // (OAuth PKCE is the normal path — see buzz-agent/src/config.rs:143).
            if env_key_missing("DATABRICKS_HOST") => {
                missing.push(Requirement::EnvKey {
                    key: "DATABRICKS_HOST".to_string(),
                });
            }
        Some("openrouter")
            if env_key_missing("OPENROUTER_API_KEY") => {
                missing.push(Requirement::EnvKey {
                    key: "OPENROUTER_API_KEY".to_string(),
                });
            }
        _ => {
            // Unknown provider or no provider yet — only the NormalizedField
            // requirement above captures this gap.
        }
    }

    missing
}

/// Requirements for goose (provider + model + provider-specific creds).
///
/// Mirrors buzz-agent requirements but uses GOOSE_PROVIDER / GOOSE_MODEL.
///
/// File-config tier: goose reads `~/.config/goose/config.yaml` at startup.
/// Requirements already satisfied there are silenced — we don't need to
/// require them from Buzz's env layer.  The file layer only *silences*
/// requirements; it never injects values into the spawn env.
///
/// `file_cfg` is injected by the caller (read once at `collect_missing_requirements`)
/// so this function is pure and unit-testable without touching disk.
pub(super) fn goose_requirements(
    effective: &EffectiveAgentEnv,
    file_cfg: Option<&crate::managed_agents::config_bridge::RuntimeFileConfig>,
) -> Vec<Requirement> {
    let mut missing = Vec::new();

    // Empty string treated as absent — same as buzz_agent_requirements.
    let provider = effective
        .env
        .get("GOOSE_PROVIDER")
        .filter(|v| !v.is_empty())
        .map(String::as_str);

    // Effective provider for credential checking: prefer env layer, then file.
    let effective_provider = provider.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.provider.as_deref())
            .filter(|v| !v.is_empty())
    });

    if provider.is_none() {
        // Silenced if the file config provides a provider.
        let file_provides_provider = file_cfg
            .as_ref()
            .and_then(|c| c.provider.as_deref())
            .filter(|v| !v.is_empty())
            .is_some();
        if !file_provides_provider {
            missing.push(Requirement::NormalizedField {
                field: "provider".to_string(),
            });
        }
    }

    let model = effective
        .env
        .get("GOOSE_MODEL")
        .filter(|v| !v.is_empty())
        .map(String::as_str);
    if model.is_none() {
        // Silenced if the file config provides a model.
        let file_provides_model = file_cfg
            .as_ref()
            .and_then(|c| c.model.as_deref())
            .filter(|v| !v.is_empty())
            .is_some();
        if !file_provides_model {
            missing.push(Requirement::NormalizedField {
                field: "model".to_string(),
            });
        }
    }

    // Provider-specific credentials — same empty-string semantics as buzz-agent.
    let env_key_missing = |key: &str| effective.env.get(key).is_none_or(|v| v.is_empty());
    // A credential key is also satisfied when the file config's `extra` map
    // contains it (e.g. DATABRICKS_HOST set in the goose config file).
    let file_key_present = |key: &str| -> bool {
        file_cfg
            .as_ref()
            .map(|c| c.extra.get(key).is_some_and(|v| !v.is_empty()))
            .unwrap_or(false)
    };
    match effective_provider {
        Some("anthropic")
            if env_key_missing("ANTHROPIC_API_KEY") && !file_key_present("ANTHROPIC_API_KEY") =>
        {
            missing.push(Requirement::EnvKey {
                key: "ANTHROPIC_API_KEY".to_string(),
            });
        }
        Some("openai")
            if env_key_missing("OPENAI_COMPAT_API_KEY")
                && !file_key_present("OPENAI_COMPAT_API_KEY") =>
        {
            missing.push(Requirement::EnvKey {
                key: "OPENAI_COMPAT_API_KEY".to_string(),
            });
        }
        Some("databricks") | Some("databricks_v2") | Some("databricks-v2")
            if env_key_missing("DATABRICKS_HOST") && !file_key_present("DATABRICKS_HOST") =>
        {
            missing.push(Requirement::EnvKey {
                key: "DATABRICKS_HOST".to_string(),
            });
        }
        Some("openrouter")
            if env_key_missing("OPENROUTER_API_KEY") && !file_key_present("OPENROUTER_API_KEY") =>
        {
            missing.push(Requirement::EnvKey {
                key: "OPENROUTER_API_KEY".to_string(),
            });
        }
        _ => {}
    }

    missing
}
