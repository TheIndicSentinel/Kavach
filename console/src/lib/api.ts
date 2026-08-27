const PRINCIPAL_KEY = "kavach.principal";

export function getPrincipal(): string {
  return sessionStorage.getItem(PRINCIPAL_KEY) ?? "";
}

export function setPrincipal(value: string): void {
  if (value.trim()) {
    sessionStorage.setItem(PRINCIPAL_KEY, value.trim());
  } else {
    sessionStorage.removeItem(PRINCIPAL_KEY);
  }
}

function authHeaders(): HeadersInit {
  const principal = getPrincipal();
  return principal ? { "X-Kavach-Principal": principal } : {};
}

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function fetchHealth(): Promise<{ status: string }> {
  const response = await fetch("/health", { headers: authHeaders() });
  if (!response.ok) {
    throw new ApiError(`Health check failed (${response.status})`, response.status);
  }
  return response.json() as Promise<{ status: string }>;
}

export type EvaluateResponse = {
  returned_decision: string;
  policy_decision: string;
  evidence_id?: string;
  reason_codes: string[];
  policy_hits: string[];
};

export async function evaluateRequest(
  body: unknown,
): Promise<EvaluateResponse> {
  const response = await fetch("/v1/evaluate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    const message =
      typeof payload?.error === "string"
        ? payload.error
        : `Evaluate failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload as EvaluateResponse;
}
