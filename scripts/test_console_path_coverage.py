"""Self-test of scripts/console_path_coverage.py (standard library only).

python3 -I -m unittest discover -s scripts -p 'test_console_path_coverage.py' -v
"""

import unittest
from pathlib import Path

import console_path_coverage as cov

SPEC = """\
openapi: 3.1.0
paths:
  # a comment
  /health:
    x-kavach-listeners: [operator, agent]
    get:
      operationId: getHealth
  "/v1/things":
    get:
      operationId: listThings
    post:
      operationId: makeThing
  /v1/things/{thing_id}:
    parameters:
      - { name: thing_id, in: path }
    get:
      operationId: getThing
  /v1/things/{thing_id}/stop:
    post:
      operationId: stopThing
  /v1/things/{thing_id}/pause:
    post:
      operationId: pauseThing
  /v1/things/latest:
    get:
      operationId: latestThing
  /auth/login:
    get:
      operationId: login
components:
  schemas:
    get:
      type: object
"""

API = """\
export async function request<T>(path: string, init: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<T> {
  const response = await fetch(path, { method: init.method ?? "GET" });
  return (await response.json()) as T;
}
function changeFetch<T>(path: string, body?: unknown): Promise<T> {
  return request(path, { method: "POST", body });
}
export function fetchHealth() {
  return request("/health");
}
export function makeThing(name: string) {
  return changeFetch("/v1/things", { name });
}
export function fetchThing(id: string) {
  return request(`/v1/things/${encodeURIComponent(id)}?full=1`);
}
export function thingsPath(cursor?: string): string {
  return cursor ? `/v1/things?cursor=${cursor}` : "/v1/things";
}
export function fetchThings(cursor?: string) {
  return request(thingsPath(cursor));
}
export const ACTIONS = ["stop", "pause"] as const;
export function act(id: string, action: (typeof ACTIONS)[number]) {
  return request(`/v1/things/${encodeURIComponent(id)}/${action}`, { method: "POST" });
}
"""

PAGE = """\
import { fetchHealth, makeThing, fetchThing, fetchThings, act } from "../lib/api";
export const LOGIN_PATH = "/auth/login";
export default function Page() {
  void fetchHealth(); void makeThing("x"); void fetchThing("a"); void fetchThings(); void act("a", "stop");
  return (
    <p>
      Don't use GET /v1/things/latest here; it's documented in "/v1/things/latest".
      <a href={LOGIN_PATH}>Sign in</a>
    </p>
  );
}
"""

APP = """\
import Page from "./pages/Page";
export default function App() {
  return <Page />;
}
"""

ALL_OPS = {
    ("GET", "/health"),
    ("GET", "/v1/things"),
    ("POST", "/v1/things"),
    ("GET", "/v1/things/{thing_id}"),
    ("POST", "/v1/things/{thing_id}/stop"),
    ("POST", "/v1/things/{thing_id}/pause"),
    ("GET", "/v1/things/latest"),
    ("GET", "/auth/login"),
}


def called(spec: str, sources: dict) -> set:
    found = cov.coverage(spec, sources)
    return {op for op, uses in found.items() if any(u.method and u.reachable for u in uses)}


class SpecTest(unittest.TestCase):
    def test_reads_every_operation_and_nothing_else(self):
        self.assertEqual(set(cov.parse_spec(SPEC)), ALL_OPS)

    def test_refuses_a_spec_without_paths(self):
        with self.assertRaises(ValueError):
            cov.parse_spec("openapi: 3.1.0\ninfo:\n  title: x\n")


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.sources = {"src/lib/api.ts": API, "src/pages/Page.tsx": PAGE, "src/App.tsx": APP}

    def test_recognises_wrappers_builders_constants_and_templates(self):
        self.assertEqual(
            called(SPEC, self.sources),
            ALL_OPS - {("GET", "/v1/things/latest")},
        )

    def test_a_get_does_not_cover_a_post(self):
        api = API.replace('changeFetch("/v1/things"', 'request("/v1/things"')
        got = called(SPEC, {**self.sources, "src/lib/api.ts": api})
        self.assertNotIn(("POST", "/v1/things"), got)
        self.assertIn(("GET", "/v1/things"), got)

    def test_an_undecidable_init_covers_nothing(self):
        api = API.replace('return request("/health");', 'const init = {}; return request("/health", init);')
        self.assertNotIn(("GET", "/health"), called(SPEC, {**self.sources, "src/lib/api.ts": api}))

    def test_a_helper_nothing_calls_covers_nothing(self):
        page = PAGE.replace("void fetchThing(\"a\");", "")
        self.assertNotIn(("GET", "/v1/things/{thing_id}"), called(SPEC, {**self.sources, "src/pages/Page.tsx": page}))

    def test_a_placeholder_matches_a_literal_segment_only_if_the_console_names_it(self):
        api = API.replace('["stop", "pause"]', '["stop"]')
        page = PAGE.replace('act("a", "stop")', "act")
        got = called(SPEC, {"src/lib/api.ts": api, "src/pages/Page.tsx": page, "src/App.tsx": APP})
        self.assertIn(("POST", "/v1/things/{thing_id}/stop"), got)
        self.assertNotIn(("POST", "/v1/things/{thing_id}/pause"), got)

    def test_a_literal_segment_wins_over_a_parameter(self):
        api = API + 'export function latest() { return request("/v1/things/latest"); }\n'
        page = PAGE.replace("void fetchHealth();", "void fetchHealth(); void latest();")
        got = cov.coverage(SPEC, {"src/lib/api.ts": api, "src/pages/Page.tsx": page, "src/App.tsx": APP})
        self.assertTrue(any(u.method == "GET" for u in got[("GET", "/v1/things/latest")]))
        lines = {u.line for u in got[("GET", "/v1/things/{thing_id}")]}
        self.assertEqual(lines, {15})  # fetchThing only

    def test_comments_and_jsx_text_are_not_calls(self):
        api = "// request(\"/health\")\n/* request('/health') */\n" + API.replace('return request("/health");', "return null;")
        self.assertNotIn(("GET", "/health"), called(SPEC, {**self.sources, "src/lib/api.ts": api}))

    def test_test_files_fixtures_and_declarations_are_not_read(self):
        root = Path("/repo/console/src")
        for name in ("lib/api.test.ts", "pages/Page.test.tsx", "lib/openapi.d.ts", "test/fixtures.ts"):
            self.assertFalse(cov.is_scanned(root / name, root), name)
        for name in ("lib/api.ts", "pages/Page.tsx"):
            self.assertTrue(cov.is_scanned(root / name, root), name)


class ExemptTest(unittest.TestCase):
    sources = {"src/lib/api.ts": API, "src/pages/Page.tsx": PAGE, "src/App.tsx": APP}

    def test_passes_when_every_missing_operation_is_exempt(self):
        errors, _ = cov.check(SPEC, self.sources, "GET /v1/things/latest not used by the console\n")
        self.assertEqual(errors, [])

    def test_fails_on_a_missing_operation(self):
        errors, _ = cov.check(SPEC, self.sources, "")
        self.assertEqual(len(errors), 1)
        self.assertIn("GET /v1/things/latest", errors[0])

    def test_fails_on_a_stale_exemption(self):
        exempt = "GET /v1/things/latest unused\nPOST /v1/gone the spec dropped it\nGET /health the console calls it\n"
        errors, _ = cov.check(SPEC, self.sources, exempt)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any("POST /v1/gone" in e and "no such operation" in e for e in errors))
        self.assertTrue(any("GET /health" in e and "calls it" in e for e in errors))

    def test_fails_on_a_line_without_a_reason_or_a_duplicate(self):
        exempt = "GET /v1/things/latest\nGET /v1/things/latest unused\nGET /v1/things/latest unused\n"
        errors, _ = cov.check(SPEC, self.sources, exempt)
        self.assertTrue(any("expected 'METHOD /path reason'" in e for e in errors))
        self.assertTrue(any("listed twice" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
