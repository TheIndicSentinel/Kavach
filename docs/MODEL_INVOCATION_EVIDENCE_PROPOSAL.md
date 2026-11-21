# Proposal: authorize and evidence model inference

**Status:** approved by owner; implementation in progress. Slice 1 adds distinct mandate-bound Cedar actions; model proxy invocation remains outside this governed path until evidence and routing slices are complete.
**Scope:** FR-13 reference collections and translation models only.

## Problem

The current Ollama proxy authenticates an agent and checks that it has a configured passport. It does not prove that a particular subject, task, or model role was authorized, and it does not create signed evidence for an inference. The proxy is therefore a plumbing boundary, not yet a governed model-use boundary.

ADR-007 says model endpoints are governed resources, while PRD FR-1/FR-2/FR-7 require mandate-derived authority, a Cedar decision, and signed evidence. Those documents do not define the model invocation request, the role-to-agent binding, or how an inference result is represented in evidence.

## Recommended contract

1. Add two registered model tools with separate Cedar actions: `invoke_collections_model` and `invoke_translation_model`. Each maps to exactly one pinned Ollama model. Agents do not choose model IDs or upstream URLs.
2. A request carries `mandate_id`, `request_id`, `subject_ref`, and transient `prompt`; the tool role is determined by the registered tool path. The proxy hashes the prompt server-side. Only the prompt digest enters parameter-MAC/evidence processing; prompt text stays in memory and is never logged or persisted.
3. The mandate must name the matching action and subject. The configured passport must grant that action. Authorization is re-evaluated by Kavach before every inference. A translation mandate cannot invoke the collections tool, or vice versa.
4. Before forwarding, commit a versioned signed `model_invocation` decision record to the existing agent evidence chain. It contains the authenticated agent, mandate chain, subject pseudonym, tool/action, model role and pinned model digest, prompt digest, policy versions, trusted time, and authorization result. It contains no prompt or completion text.
5. After a valid Ollama response, append a typed signed `model_outcome` record linked to the invocation record, containing only the response digest, completion status and bounded timing metadata. No model response text is retained. An error before sending records `failed`; an ambiguous timeout records `unknown` and is never automatically retried.
6. A retry with the same request ID does not invoke the model again. It returns the recorded status; if the first completion was lost, the caller starts a new request ID and the evidence shows the earlier `unknown` invocation.
7. Extend offline bundle export/verification and checkpoints for the new record kinds. Keep existing Agent Decision Record canonical bytes and old bundles verifiable. Update `SECURITY_PROPERTIES.md` with the limited guarantee: evidence proves the digests and authorization, not the model's semantic correctness.

## Required tests

- A missing, expired, wrong-subject, wrong-action, or wrong-role mandate never reaches Ollama and creates a signed refusal record.
- A valid call writes its authorization record before forwarding; a simulated evidence-store failure sends nothing.
- Prompt text, completion text, and raw borrower data never appear in logs, database records, bundles or API error bodies; only digests appear.
- Exact request replay does not invoke Ollama twice; timeout remains `unknown` and is not retried automatically.
- Offline bundle verification covers both model record kinds and detects edits, omissions and reorderings.
- Formal Cedar analysis proves role separation and no model action without the matching mandate/passport grant.

## Compatibility and rollout

This changes the evidence schema and tool registry contract. Implement it as a versioned evidence extension with a migration and verifier vectors, preserving the existing `/v1/tools/*` contracts and previously issued evidence. The current identity-only `/proxy/{role}/api/chat` route must remain disabled for governed agent workflows until the new action path is active; alternatively, replace it atomically with the registered model tools.

Full production deployment acceptance remains separate: Docker/network-isolation work is still on hold, and the current demo has no Ollama service.

## Decision record

Owner approved the recommended design on 2026-11-20. Prompts and completions remain transient; only digests are approved for evidence. Implementation is staged, and the identity-only proxy must not be represented as governed until the approved path is complete.

### Implementation record

- Slice 1: added distinct `invoke_collections_model` and `invoke_translation_model` Cedar actions. Each action requires the authenticated mandate holder and its exact action grant. Restricted, quarantined, and revoked agents are denied model invocation. The formal Cedar property set and scenario tests cover action separation. This slice does not expose a model tool or change proxy routing.
- Slice 2: registered fixed `collections` and `translation` model roles against their matching Cedar actions. The registry rejects mismatched role/action bindings. Both tools remain read-only/non-forwardable through the generic gateway until the signed invocation/outcome execution path is complete. The registry edit must be signed by each deployment's trusted `tool` signer before secure startup.
- Slice 3: added a tenant-scoped mandate-service check for exact passport action grants, with tests for missing, wrong-tenant, wrong-agent, wrong-role, and matching grants. This is an additional ceiling; active mandate verification and Cedar authorization remain required. The existing inference proxy is unchanged and still does not use this check; routing stays gated until the complete evidence path is implemented.
- Slice 4: extended registered model tool parameters with `prompt_digest`, accepting only a 64-character lowercase SHA-256 hex digest. Authorization parameter MACs bind the digest and the raw-identifier scanner skips this typed digest. The future model handler must compute it from transient prompt text; no handler or inference route was enabled in this slice. Registered tools remain non-forwardable until invocation and outcome evidence are both available.
- Slice 5: added the typed `model_invocation` payload/record/draft, including policy and returned decisions, strict role/action and digest-form checks, v2 signing, and `ChainRecord` decoding/verification support. It contains no prompt or completion field. Existing bundle versions reject it until a versioned export format is added. Storage append/export and the runtime call path remain pending; model inference is still not enabled.
