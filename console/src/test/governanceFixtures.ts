// Governance response bodies typed from openapi.d.ts, so a spec change breaks the tests.
import type { RuntimeInfo } from "../lib/api";

export const runtime: RuntimeInfo = {
  pack_id: "finance-core",
  pack_version: "1.4.0",
  model_id: "credit-risk",
  model_version: "2.1.0",
  sector: "finance",
  governance_mode: "enforce",
  pack_path: "packs/finance-core.yaml",
  model_path: "models/credit-risk.yaml",
  pack_sha256: "a1b2c3",
  pointer_version: 7,
  model_sha256: "d4e5f6",
  model_pack_mismatch: false,
  stored_pointer_version: 7,
  pointer_drift: false,
  insecure_dev: false,
  require_hardening: false,
  agent_only: false,
  relaxations: [],
};
