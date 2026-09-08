use std::collections::BTreeMap;

use serde::Deserialize;

use super::AgentDefinition;

/// Editable content and stable identity bound to an owner draft review.
/// Deserialization normalizes omitted options and collections just like persona reads.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PersonaReviewContent {
    pub id: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub system_prompt: String,
    pub runtime: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    #[serde(default)]
    pub name_pool: Vec<String>,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    pub respond_to: Option<String>,
    #[serde(default)]
    pub respond_to_allowlist: Vec<String>,
    pub parallelism: Option<u32>,
}

impl From<&AgentDefinition> for PersonaReviewContent {
    fn from(persona: &AgentDefinition) -> Self {
        Self {
            id: persona.id.clone(),
            display_name: persona.display_name.clone(),
            avatar_url: persona.avatar_url.clone(),
            system_prompt: persona.system_prompt.clone(),
            runtime: persona.runtime.clone(),
            model: persona.model.clone(),
            provider: persona.provider.clone(),
            name_pool: persona.name_pool.clone(),
            env_vars: persona.env_vars.clone(),
            respond_to: persona.respond_to.clone(),
            respond_to_allowlist: persona.respond_to_allowlist.clone(),
            parallelism: persona.parallelism,
        }
    }
}
