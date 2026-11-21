# FR-13 Reference model pins

**Status:** selected for the local reference workflow; mandate-governed Ollama invocation and exact manifest pinning are implemented. Model quality remains to be validated in the full workflow.

FR-13 requires two pinned, Apache-2.0 models served by local Ollama. These are small quantized artifacts so they can be pulled on a temporary Colab runtime for experiments; downloading them to the owner's Mac is not required.

| Role | Ollama reference | Quantization / catalogue size | License evidence |
|---|---|---|---|
| Collections agent | `granite3.3:2b` | Q4_K_M; 1.5 GB | [Ollama model card](https://ollama.com/library/granite3.3:2b) identifies Apache 2.0 and function-calling capability. |
| Read-only translation sub-agent | `qwen2.5:1.5b` | Q4_K_M; 986 MB | [Ollama model card](https://ollama.com/library/qwen2.5:1.5b) identifies Apache 2.0 and multilingual support; the [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct) independently identifies Apache-2.0. |

The `granite3.3:2b` choice favors the planned collections agent's structured tool-use workflow. The smaller Qwen model is assigned to translation to reduce resource use while retaining multilingual capability. These are reference/demo models, not a claim of production translation quality or suitability for consequential decisions. Model outputs never grant authority; Kavach's mandate and gateway remain authoritative.

The [official Ollama tag page for Granite](https://ollama.com/library/granite3.3/tags) publishes prefix `07bd1f170855`; the [official Qwen tag page](https://ollama.com/library/qwen2.5/tags) publishes prefix `65ec06548149`. On 2026-11-21, the exact manifest response bodies were fetched from the official [Granite registry manifest](https://registry.ollama.ai/v2/library/granite3.3/manifests/2b) and [Qwen registry manifest](https://registry.ollama.ai/v2/library/qwen2.5/manifests/1.5b), then hashed with SHA-256. The resulting full pins are:

| Role | Exact SHA-256 manifest digest |
|---|---|
| Collections (`granite3.3:2b`) | `07bd1f170855240f9e162bf54ea494a8bc1c73d8cbd1365d7fccbeb7d2504947` |
| Translation (`qwen2.5:1.5b`) | `65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b` |

The governed adapter requires the local `/api/tags` digest to equal the role's entire 64-hex pin. It then sends Ollama the exact `sha256:<digest>` model reference, so a tag update between inspection and inference cannot select different model bytes. Ollama resolves digest references to local model blobs; see its [model resolver](https://github.com/ollama/ollama/blob/main/server/model_resolver.go) and [model name grammar](https://github.com/ollama/ollama/blob/main/types/model/name.go). If the configured Ollama version or local store cannot resolve that exact digest, the request fails closed. The legacy identity-only `/proxy/*` route continues using the mutable role tag and is not a governed model route.

The exact manifest pin removes reliance on a 48-bit prefix and the governed route's execution is bound to the digest instead of the mutable tag. This still trusts the configured local Ollama endpoint and its digest-reference handling; it is not an attestation of the Ollama binary, host, or model runtime and does not establish model quality.

## Gateway implementation boundary

Agents must not contact Ollama directly. Governed workflows use `POST /v1/models/{role}/invoke`: it requires agent authentication, an active mandate, the exact passport action grant and Cedar approval, records signed invocation/outcome evidence, and forwards only the exact pinned model digest. The legacy `POST /proxy/{role}/api/chat` remains identity/passport based and ungoverned; do not use it for governed workflows. Both routes expose only fixed roles and chat inference, never model-management endpoints. This document does not authorize direct model egress, public tunnels, or a hosted model service.

Model invocation output is untrusted input. The LangGraph workflow must not interpret model output as authority, and untrusted tool/model content must follow the planned taint behavior before critical actions.

## Validation record

- License and size review: 2026-11-20, based on the official Ollama catalogue and publisher model card linked above.
- Exact registry manifest retrieval, SHA-256 recomputation, and match against the tag-page prefixes: verified 2026-11-21. Runtime exact digest selection is covered by the governed model route integration test.
- Model execution quality and Hindi/other target-language translation quality: pending the full FR-13 workflow validation.
