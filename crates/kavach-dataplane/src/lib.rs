//! Kavach agent data plane (ADR-007): the tool registry and the
//! authorization core; the resource gateway and credential broker join them
//! in H5b. Agents reach backends only through this process.

pub mod authorize;
pub mod detect;
pub mod tools;

pub use authorize::{
    policy_versions, validate_request_id, AgentIdentity, AuthorizeConfig, AuthorizeCore,
    CommitStatus, CredentialGrant, Decided, MandateVerifier, Mode, ToolCall,
};
pub use tools::{RegistryTrust, ToolRegistry, ToolRequest, Trust};
