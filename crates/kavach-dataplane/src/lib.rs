//! Kavach agent data plane (ADR-007): the tool registry and the
//! authorization core; the resource gateway and credential broker join them
//! in H5b. Agents reach backends only through this process.

pub mod authorize;
pub mod checkpointer;
pub mod detect;
pub mod gateway;
pub mod resolve;
pub mod revocation_evidence;
pub mod tools;
pub mod whatif;

pub use authorize::{
    policy_versions, validate_request_id, AgentIdentity, AuthorizeConfig, AuthorizeCore,
    CommitStatus, CredentialGrant, Decided, MandateVerifier, Mode, ToolCall,
};
pub use checkpointer::{
    CheckpointPolicy, CheckpointStatus, Checkpointer, Skip, StallChange, Tick, TickReport,
};
pub use gateway::{
    execute, ForwardResult, Forwarder, GatewayDeps, GatewayError, GatewayObserver, GatewayReply,
    Stage,
};
pub use resolve::FixtureResolver;
pub use revocation_evidence::{reconcile_revocations, ReconcileConfig, ReconcileReport};
pub use tools::{Refusal, RefusalCode, RegistryTrust, ToolRegistry, ToolRequest, Trust};
pub use whatif::WhatIfStore;
