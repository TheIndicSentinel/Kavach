// The read states of the governance pages, rendered to static markup (no
// effects run, so nothing is fetched): loading, empty, a problem with its
// request_id, a proxy's 502 with none, 401, 403, and 404 on detail pages.
import type { ReactElement } from "react";
import { describe, expect, it } from "vitest";
import type { Resource } from "../hooks/useResource";
import type { RetentionSettings } from "../lib/api";
import { byRole, render, renderAt, text } from "../test/markup";
import {
  badGateway,
  failed,
  forbidden,
  loading,
  notFound,
  ok,
  serverError,
  unauthorized,
} from "../test/states";
import AuditPage from "./AuditPage";
import BatchJobDetailPage from "./BatchJobDetailPage";
import BatchJobsPage from "./BatchJobsPage";
import ChangeRequestsPage from "./ChangeRequestsPage";
import IncidentsPage from "./IncidentsPage";
import ModelDetailPage from "./ModelDetailPage";
import ModelsPage from "./ModelsPage";
import NotFoundPage from "./NotFoundPage";
import PoliciesPage from "./PoliciesPage";
import PolicyDetailPage from "./PolicyDetailPage";
import RetentionPage from "./RetentionPage";

const SKELETON = 'class="animate-pulse';

/** The failures every read is tested with, and what its alert must say. */
function expectFailures(page: (resource: Resource<never>) => string) {
  const alert = (error: unknown) => byRole(page(failed(error)), "alert")[0];
  expect(alert(serverError)).toBe("storage unavailable HTTP 500 · request_id req-500");
  expect(alert(badGateway("/v1/x"))).toContain("no request_id was returned");
  expect(alert(unauthorized)).toContain("Sign in again");
  expect(alert(unauthorized)).toContain("request_id req-401");
  expect(alert(forbidden)).toContain("Not permitted");
  expect(alert(forbidden)).toContain("request_id req-403");
  const html = page(failed(serverError));
  expect(text(html)).toContain("Try again");
  expect(html).not.toContain(SKELETON);
}

const lists: {
  name: string;
  page: (resource: Resource<never[]>) => ReactElement;
  loadingText: string;
  emptyText: string;
}[] = [
  {
    name: "PoliciesPage",
    page: (resource) => <PoliciesPage resource={resource} />,
    loadingText: "Loading policy packs…",
    emptyText: "No policy packs in the packs directory yet.",
  },
  {
    name: "ModelsPage",
    page: (resource) => <ModelsPage resource={resource} />,
    loadingText: "Loading models…",
    emptyText: "No model records yet.",
  },
  {
    name: "BatchJobsPage",
    page: (resource) => <BatchJobsPage resource={resource} />,
    loadingText: "Loading batch jobs…",
    emptyText: "No batch jobs recorded yet.",
  },
  {
    name: "AuditPage",
    page: (resource) => <AuditPage resource={resource} />,
    loadingText: "Loading the audit log…",
    emptyText: "No admin actions recorded yet.",
  },
  {
    name: "IncidentsPage",
    page: (resource) => <IncidentsPage resource={resource} />,
    loadingText: "Loading incidents…",
    emptyText: "No incidents recorded.",
  },
];

for (const { name, page, loadingText, emptyText } of lists) {
  describe(`${name} states`, () => {
    const at = (resource: Resource<never[]>) => render(page(resource));

    it("loading: role=status says so, a skeleton, an empty alert", () => {
      const html = at(loading);
      expect(byRole(html, "status")).toEqual([loadingText]);
      expect(byRole(html, "alert")).toEqual([""]);
      expect(html).toContain(SKELETON);
    });

    it("empty: the empty message, and no alert", () => {
      const html = at(ok([]));
      expect(text(html)).toContain(emptyText);
      expect(byRole(html, "alert")).toEqual([""]);
      expect(html).not.toContain(SKELETON);
    });

    it("error, a non-JSON 502, 401 and 403, each with Try again", () => {
      expectFailures(at);
    });
  });
}

const details: {
  name: string;
  path: string;
  pattern: string;
  id: string;
  page: (resource: Resource<never>) => ReactElement;
  loadingText: string;
  missing: string;
}[] = [
  {
    name: "PolicyDetailPage",
    path: "/policies/pack-x",
    pattern: "/policies/:packId",
    id: "pack-x",
    page: (resource) => <PolicyDetailPage resource={resource} />,
    loadingText: "Loading policy pack…",
    missing: "No policy pack pack-x on this server.",
  },
  {
    name: "ModelDetailPage",
    path: "/models/model-x",
    pattern: "/models/:modelId",
    id: "model-x",
    page: (resource) => <ModelDetailPage resource={resource} />,
    loadingText: "Loading model…",
    missing: "No model model-x on this server.",
  },
  {
    name: "BatchJobDetailPage",
    path: "/batch/job-x",
    pattern: "/batch/:jobId",
    id: "job-x",
    page: (resource) => <BatchJobDetailPage resource={resource} />,
    loadingText: "Loading batch job…",
    missing: "No batch job job-x on this server.",
  },
];

for (const { name, path, pattern, id, page, loadingText, missing } of details) {
  describe(`${name} states`, () => {
    const at = (resource: Resource<never>) => renderAt(path, pattern, page(resource));

    it("loading: the id as the heading, role=status says so, a skeleton", () => {
      const html = at(loading);
      expect(html).toMatch(new RegExp(`<h1[^>]*>${id}</h1>`));
      expect(byRole(html, "status")).toEqual([loadingText]);
      expect(byRole(html, "alert")).toEqual([""]);
      expect(html).toContain(SKELETON);
    });

    it("404: says the record doesn't exist, with the detail and request_id, and no Try again", () => {
      const html = at(failed(notFound));
      expect(byRole(html, "alert")).toEqual([`${missing} no such record · HTTP 404 · request_id req-404`]);
      expect(text(html)).not.toContain("Try again");
      expect(html).toMatch(new RegExp(`<h1[^>]*>${id}</h1>`));
    });

    it("error, a non-JSON 502, 401 and 403, each with Try again", () => {
      expectFailures(at);
    });

    it("offers no proposal before the record is read", () => {
      for (const resource of [loading, failed(serverError), failed(notFound)]) {
        expect(text(at(resource))).not.toMatch(/Propose/);
      }
    });
  });
}

describe("RetentionPage states", () => {
  const settings: RetentionSettings = {
    evidence_retention_days: 400,
    updated_at: "2026-11-01T10:00:00Z",
    updated_by: "admin-1",
    approved_by: "approver-1",
  };

  it("loading: both reads say so in their own role=status", () => {
    const html = render(<RetentionPage settings={loading} tombstones={loading} />);
    expect(byRole(html, "status")).toEqual(["Loading the retention policy…", "Loading tombstones…"]);
    expect(text(html)).not.toMatch(/Propose/);
  });

  it("loaded and empty: the window the server holds, and no tombstones", () => {
    const html = render(<RetentionPage settings={ok(settings)} tombstones={ok([])} />);
    expect(html).toContain('value="400"');
    expect(text(html)).toContain("by admin-1");
    expect(text(html)).toContain("No tombstoned evidence yet.");
    expect(byRole(html, "status")).toContain("0 tombstones.");
  });

  it("each read fails on its own, with its request_id", () => {
    const html = render(<RetentionPage settings={ok(settings)} tombstones={failed(forbidden)} />);
    const alerts = byRole(html, "alert").filter(Boolean);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toContain("request_id req-403");
    expect(text(html)).toContain("Propose policy change");
  });

  it("error, a non-JSON 502, 401 and 403 on the policy read", () => {
    expectFailures((resource) => render(<RetentionPage settings={resource} tombstones={ok([])} />));
  });
});

describe("ChangeRequestsPage states", () => {
  const at = (resource: Resource<never[]>) => render(<ChangeRequestsPage resource={resource} />);

  it("loading: role=status says so, a skeleton", () => {
    const html = at(loading);
    expect(byRole(html, "status")).toEqual(["Loading change requests…"]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(html).toContain(SKELETON);
  });

  it("empty: no pending change requests (the default filter)", () => {
    const html = at(ok([]));
    expect(text(html)).toContain("No pending change requests.");
    expect(html).not.toContain(SKELETON);
  });

  it("error, a non-JSON 502, 401 and 403, each with Try again", () => {
    expectFailures(at);
  });
});

describe("NotFoundPage", () => {
  const html = renderAt("/no-such-page", "*", <NotFoundPage />);

  it("names the path and links to Overview", () => {
    expect(html).toMatch(/<h1[^>]*>Page not found<\/h1>/);
    expect(text(html)).toContain("The console has no page at /no-such-page.");
    expect(html).toContain('href="/overview"');
  });
});
