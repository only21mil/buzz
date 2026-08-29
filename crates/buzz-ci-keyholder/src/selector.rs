use crate::{Operation, PublicIdentity};

/// Fixed credential selected by one signing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySelector {
    /// Kind 46101 through 46106 event signer.
    CiEvent,
    /// NIP-98 authorization signer.
    Nip98,
    /// CI manifest signer.
    Manifest,
}

impl KeySelector {
    /// Return the only selector valid for a signing operation.
    pub const fn for_operation(operation: Operation) -> Option<Self> {
        match operation {
            Operation::Describe => None,
            Operation::DescribeAcceptance => None,
            Operation::SignCiEvent => Some(Self::CiEvent),
            Operation::Nip98Authorize => Some(Self::Nip98),
            Operation::SignManifest => Some(Self::Manifest),
            Operation::SignAcceptanceMutation => None,
        }
    }

    /// Fixed systemd credential name. No caller-selected credential path is accepted.
    pub const fn credential_name(self) -> &'static str {
        match self {
            Self::CiEvent => "ci-event.key",
            Self::Nip98 => "nip98.key",
            Self::Manifest => "manifest.key",
        }
    }
}

/// Closed public selector state for the three signing domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectorSet {
    ci_event: PublicIdentity,
    nip98: PublicIdentity,
    manifest: PublicIdentity,
}

impl SelectorSet {
    /// Construct selector state. Keys must be nonzero and pairwise distinct;
    /// every generation must be nonzero.
    pub fn new(
        ci_event: PublicIdentity,
        nip98: PublicIdentity,
        manifest: PublicIdentity,
    ) -> Option<Self> {
        ([ci_event, nip98, manifest]
            .iter()
            .all(|identity| identity.public_key != [0; 32] && identity.generation != 0)
            && ci_event.public_key != nip98.public_key
            && ci_event.public_key != manifest.public_key
            && nip98.public_key != manifest.public_key)
            .then_some(Self {
                ci_event,
                nip98,
                manifest,
            })
    }

    /// Return the public identity pinned to one fixed selector.
    pub const fn identity(self, selector: KeySelector) -> PublicIdentity {
        match selector {
            KeySelector::CiEvent => self.ci_event,
            KeySelector::Nip98 => self.nip98,
            KeySelector::Manifest => self.manifest,
        }
    }

    pub(crate) const fn ci_event(self) -> PublicIdentity {
        self.ci_event
    }

    pub(crate) const fn nip98(self) -> PublicIdentity {
        self.nip98
    }

    pub(crate) const fn manifest(self) -> PublicIdentity {
        self.manifest
    }
}
