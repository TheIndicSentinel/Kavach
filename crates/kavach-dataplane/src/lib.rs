//! Kavach agent data plane (ADR-007): the authorization core now; the
//! resource gateway and credential broker join it in H5b. Agents reach
//! backends only through this process.

pub mod authorize;
pub mod detect;

pub use authorize::{
    policy_versions, validate_request_id, AgentIdentity, AuthorizeConfig, AuthorizeCore,
    CommitStatus, CredentialGrant, Decided, MandateVerifier, Mode, ToolCall,
};
