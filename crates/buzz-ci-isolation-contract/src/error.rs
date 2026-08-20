use thiserror::Error;

/// A fail-closed attempt/lease contract validation error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// A field is malformed or violates a Phase-1 invariant.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Stable wire-field name.
        field: &'static str,
        /// Human-readable refusal reason.
        reason: String,
    },
    /// Two fields that must describe the same broker resource disagree.
    #[error("binding mismatch for {field}: {reason}")]
    BindingMismatch {
        /// Stable contract-field name.
        field: &'static str,
        /// Human-readable mismatch reason.
        reason: String,
    },
}

impl ContractError {
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            reason: reason.into(),
        }
    }

    pub(crate) fn mismatch(field: &'static str, reason: impl Into<String>) -> Self {
        Self::BindingMismatch {
            field,
            reason: reason.into(),
        }
    }
}
