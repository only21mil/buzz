//! Layered launch environment shared by readiness, spawn and snapshots.
use super::*;

/// Inner implementation that accepts a pre-fetched `harness_def` to avoid a
/// second registry lookup when the caller (e.g. `resolve_effective_harness_descriptor`)
/// already has the definition in hand.
pub(super) fn resolve_effective_agent_env_with_def(
    record: &ManagedAgentRecord,
    personas: &[AgentDefinition],
    runtime: Option<&KnownAcpRuntime>,
    global: &GlobalAgentConfig,
    harness_def: Option<std::sync::Arc<crate::managed_agents::custom_harnesses::HarnessDefinition>>,
) -> EffectiveAgentEnv {
    let effective_command = crate::managed_agents::record_agent_command(record, personas);

    // Layer 1: baked build defaults (floor — internal builds only; OSS = empty).
    let mut env = baked_build_env();

    let (effective_model, effective_provider) =
        super::super::global_config::resolve_effective_model_provider(record, personas, global);

    if let Some(rt) = runtime {
        for (key, value) in super::super::runtime::runtime_metadata_env_vars(
            rt.model_env_var,
            rt.provider_env_var,
            rt.provider_locked,
            effective_model.as_deref(),
            effective_provider.as_deref(),
        ) {
            env.insert(key.to_string(), value.to_string());
        }
    }

    // Layer 2b: definition env — the harness author's defaults (e.g. CURSOR_ACP=1).
    // Applied as a floor below global so user env always wins on collision.
    // Reserved keys are stripped by the shared `is_reserved_env_key` predicate.
    if let Some(ref def) = harness_def {
        for (key, value) in &def.env {
            if !super::super::env_vars::is_reserved_env_key(key) {
                env.insert(key.clone(), value.clone());
            }
        }
    }

    // Layer 3a: global env vars — the lowest user-settable layer.
    // Injected before persona/agent so per-agent values win on collision.
    // `merged_user_env` with an empty "lower" map applies reserved/malformed-key
    // filtering to the global map for free.
    let global_env = merged_user_env(&BTreeMap::new(), &global.env_vars);
    env.extend(global_env);

    // Layer 3b: merged user env — live persona env under the record's own
    // overrides (last-wins), after reserved/malformed-key filtering. Reading
    // the persona live is what makes persona credential edits refresh on the
    // next spawn instead of being frozen into the record.
    let user_env = merged_user_env(
        &super::super::env_vars::live_persona_env(personas, record.persona_id.as_deref()),
        &record.env_vars,
    );
    env.extend(user_env);
    super::super::config_bridge::effort::apply_launch_effort(
        &mut env,
        record,
        runtime,
        personas,
        &global.env_vars,
        harness_def.as_deref(),
        &baked_build_env(),
    );

    // Buzz shared compute is a native Buzz provider. Translate it to buzz-agent's
    // OpenAI-compatible transport only in the effective runtime environment.
    #[cfg(feature = "mesh-llm")]
    super::super::apply_relay_mesh_env(
        &mut env,
        effective_provider.as_deref(),
        effective_model.as_deref(),
    );

    EffectiveAgentEnv {
        env,
        config_file_path: runtime.and_then(|r| r.config_file_path),
        effective_command,
    }
}
