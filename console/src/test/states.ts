// The phases a page's read can be in, and the failures every page is tested
// with: problem bodies for 401, 403, 404 and 500 (each with a request_id),
// and a non-JSON 502 from a proxy, which `request()` reports by its status.
import type { Lookup } from "../hooks/useLookup";
import type { Resource } from "../hooks/useResource";
import { ApiError } from "../lib/api";

export const loading: Resource<never> = { phase: "loading" };

export function ok<T>(data: T): Resource<T> {
  return { phase: "ok", data };
}

export function failed(error: unknown): Resource<never> {
  return { phase: "error", error };
}

/** An RFC 9457 problem the API sent, as `request()` throws it. */
export function problem(status: number, detail: string): ApiError {
  return new ApiError(`${detail} (request req-${status})`, status, `req-${status}`, detail);
}

export const unauthorized = problem(401, "missing or invalid credentials");
export const forbidden = problem(403, "not permitted for this principal");
export const notFound = problem(404, "no such record");
export const serverError = problem(500, "storage unavailable");

/** A proxy's HTML 502: no problem body, so no request_id. */
export function badGateway(path: string): ApiError {
  return new ApiError(`GET ${path} failed (502 Bad Gateway)`, 502);
}

export const lookupLoading = <T,>(what: string): Lookup<T> => ({ phase: "loading", what });
export const lookupFailed = <T,>(what: string, error: unknown): Lookup<T> => ({
  phase: "error",
  what,
  error,
});
