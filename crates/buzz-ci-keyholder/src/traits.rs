use crate::{
    DescribeRequest, DescribeResponse, ErrorResponse, Nip98AuthorizeRequest, PeerIdentity,
    SignCiEventRequest, SignManifestRequest, SignatureResponse,
};

/// Transport-neutral client contract for the four keyholder operations.
pub trait KeyholderClient {
    /// Transport or protocol error type.
    type Error;

    /// Fetch public identities, generations, and peer policy.
    fn describe(&mut self, request: DescribeRequest) -> Result<DescribeResponse, Self::Error>;

    /// Request a policy-checked CI event signature.
    fn sign_ci_event(
        &mut self,
        request: SignCiEventRequest,
    ) -> Result<SignatureResponse, Self::Error>;

    /// Request a policy-checked NIP-98 authorization signature.
    fn nip98_authorize(
        &mut self,
        request: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error>;

    /// Request a policy-checked manifest signature.
    fn sign_manifest(
        &mut self,
        request: SignManifestRequest,
    ) -> Result<SignatureResponse, Self::Error>;
}

/// Transport-neutral server contract; a transport must establish peer identity
/// before invoking any method.
pub trait KeyholderServer {
    /// Backend error type, converted to a sanitized [`ErrorResponse`].
    type Error;

    /// Fetch public identities, generations, and peer policy.
    fn describe(
        &self,
        peer: PeerIdentity,
        request: DescribeRequest,
    ) -> Result<DescribeResponse, Self::Error>;

    /// Validate and sign one canonical CI event.
    fn sign_ci_event(
        &self,
        peer: PeerIdentity,
        request: SignCiEventRequest,
    ) -> Result<SignatureResponse, Self::Error>;

    /// Validate and authorize one exact NIP-98 request.
    fn nip98_authorize(
        &self,
        peer: PeerIdentity,
        request: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error>;

    /// Validate and sign one canonical CI manifest.
    fn sign_manifest(
        &self,
        peer: PeerIdentity,
        request: SignManifestRequest,
    ) -> Result<SignatureResponse, Self::Error>;

    /// Convert a backend error into a bounded public failure.
    fn public_error(&self, error: &Self::Error) -> ErrorResponse;
}
