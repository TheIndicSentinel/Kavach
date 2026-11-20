# FR-13 Reference model pins

**Status:** selected for the local reference workflow; the authenticated Ollama chat proxy is implemented. Model quality remains to be validated in the full workflow.

FR-13 requires two pinned, Apache-2.0 models served by local Ollama. These are small quantized artifacts so they can be pulled on a temporary Colab runtime for experiments; downloading them to the owner's Mac is not required.

| Role | Ollama reference | Quantization / catalogue size | License evidence |
|---|---|---|---|
| Collections agent | `granite3.3:2b` | Q4_K_M; 1.5 GB | [Ollama model card](https://ollama.com/library/granite3.3:2b) identifies Apache 2.0 and function-calling capability. |
| Read-only translation sub-agent | `qwen2.5:1.5b` | Q4_K_M; 986 MB | [Ollama model card](https://ollama.com/library/qwen2.5:1.5b) identifies Apache 2.0 and multilingual support; the [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct) independently identifies Apache-2.0. |

The `granite3.3:2b` choice favors the planned collections agent's structured tool-use workflow. The smaller Qwen model is assigned to translation to reduce resource use while retaining multilingual capability. These are reference/demo models, not a claim of production translation quality or suitability for consequential decisions. Model outputs never grant authority; Kavach's mandate and gateway remain authoritative.

Ollama's library page displays short model-layer identifiers (`07bd1f170855` for Granite and `65ec06548149` for Qwen) and sizes. They are recorded here as provenance hints, not treated as immutable manifest digests. Before making a supply-chain pin guarantee, deployment must capture and verify each full Ollama manifest digest and the Ollama runtime version. The available network in the implementation environment could not retrieve the registry manifests, so this stronger digest lock is still open.

## Gateway implementation boundary

Agents must not contact Ollama directly. The ADR-007 `/proxy/*` model gateway path is implemented at `POST /proxy/{role}/api/chat`, with the two model IDs above as its allowlist. It authenticates agent OIDC identity and requires a configured passport; the caller can select only a role, never a model id or URL. It forwards only to the configured Ollama `/api/chat` endpoint, refuses streaming, bounds request/response size, context, output and concurrency, avoids logging prompts or completions, and fails closed on an upstream error. Ollama's administrative/model-management endpoints are not exposed. The current proxy authorization is identity/passport based; per-inference mandate binding and signed model-call evidence are not implemented. This document does not authorize direct model egress, public tunnels, or a hosted model service.

Model invocation output is untrusted input. The LangGraph workflow must not interpret model output as authority, and untrusted tool/model content must follow the planned taint behavior before critical actions.

## Validation record

- License and size review: 2026-11-20, based on the official Ollama catalogue and publisher model card linked above.
- Model execution quality, Hindi and other target-language translation quality, per-inference mandate/evidence binding, and immutable digest verification: pending FR-13 implementation and validation.
