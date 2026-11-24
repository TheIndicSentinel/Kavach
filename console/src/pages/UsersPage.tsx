// Users & roles (ADR-019 §4, §8, §9): who has signed in, who holds which
// role, a grant or revoke proposed as a change request, and the access
// review. Every read and every proposal is decided by the server; the role
// hints only leave out what the viewer's groups and roles are expected to
// be refused.
import { useCallback, useRef, useState, type FormEvent } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { DataTable } from "../components/ui/DataTable";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { ProposalStatus } from "../components/ui/ProposalStatus";
import { ResourceState } from "../components/ui/ResourceState";
import { RoleHint } from "../components/ui/RoleHint";
import { TextField } from "../components/ui/TextField";
import { useProposal } from "../hooks/useProposal";
import { useResource, type Resource } from "../hooks/useResource";
import {
  fetchAccessReview,
  fetchAccessReviewCsv,
  fetchPrincipals,
  fetchRoleBindings,
  type AccessReview,
  type Principal,
  type PrincipalPage,
  type RoleBinding,
} from "../lib/api";
import { useViewer } from "../lib/changeRequests";
import { formatDateTime } from "../lib/format";
import { ROLES, approveAction, proposeAction, roleHint, type Viewer } from "../lib/permissions";
import {
  EMPTY_GRANT,
  MAX_FIELD,
  ROLE_PURPOSES,
  grantErrors,
  grantParams,
  roleChangeProposed,
  staleLabel,
  type GrantErrors,
  type GrantForm,
} from "../lib/roles";

const selectClass =
  "w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20";

type UsersPageProps = {
  /** For tests: who is signed in, and the reads of the directory and the bindings. */
  viewer?: Viewer;
  principals?: Resource<PrincipalPage>;
  bindings?: Resource<RoleBinding[]>;
};

export default function UsersPage({ viewer: given, principals, bindings }: UsersPageProps = {}) {
  const current = useViewer();
  const viewer = given ?? current;
  const readHint = roleHint(viewer, "read_principals", "read users and role bindings");
  const reviewHint = roleHint(viewer, "read_access_review", "export the access review");
  const grantHint = roleHint(viewer, proposeAction("grant_role"), "propose role grants");
  const revokeHint = roleHint(viewer, proposeAction("revoke_role"), "propose role revokes");
  const [form, setForm] = useState<GrantForm>(EMPTY_GRANT);
  const roleRef = useRef<HTMLSelectElement>(null);

  /** Fills the grant form with a person from the directory and moves to the role. */
  function grantTo(person: Principal) {
    setForm({ ...form, kind: "principal", issuer: person.issuer, value: person.subject });
    roleRef.current?.focus();
  }

  const header = (
    <PageHeader
      title="Users & roles"
      hindi="उपयोगकर्ता और भूमिकाएँ"
      subtitle="Who has signed in, which roles they hold, and the access review. A role is granted or revoked only when a second person approves the change request."
    />
  );

  // Every read here is role-only. With the groups known, wait for GET /v1/me
  // rather than send a read the roles will show is refused.
  if (viewer.rolesPending && viewer.groups !== null) {
    return (
      <section>
        {header}
        <p role="status" className="text-sm text-muted">
          Checking your roles…
        </p>
      </section>
    );
  }

  return (
    <section>
      {header}

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>People</CardTitle>
            <CardDescription>
              Everyone who has signed in to this tenant. A person appears after their first sign-in.
            </CardDescription>
          </CardHeader>
          {readHint ? (
            <RoleHint>{readHint}</RoleHint>
          ) : (
            <Directory given={principals} onGrant={grantHint ? null : grantTo} />
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Grant a role</CardTitle>
            <CardDescription>
              Proposes a grant_role change request. Only a superadmin may grant superadmin, and nobody may grant a
              role to themselves or to a group they are in.
            </CardDescription>
          </CardHeader>
          {grantHint ? (
            <RoleHint>{grantHint}</RoleHint>
          ) : (
            <GrantRole form={form} setForm={setForm} roleRef={roleRef} />
          )}
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Role bindings</CardTitle>
          <CardDescription>
            Who holds which role now. A revoke takes effect on the next request after it is approved; the last
            superadmin or user_admin person binding cannot be revoked.
          </CardDescription>
        </CardHeader>
        {readHint ? <RoleHint>{readHint}</RoleHint> : <Bindings given={bindings} revokeHint={revokeHint} />}
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Access review</CardTitle>
          <CardDescription>
            One row per active binding: who proposed and who approved it, and when the person was last seen. Every
            export, shown here or downloaded, is recorded in the admin audit.
          </CardDescription>
        </CardHeader>
        {reviewHint ? <RoleHint>{reviewHint}</RoleHint> : <Review />}
      </Card>

      {!grantHint && approveHintNote(viewer)}
    </section>
  );
}

/** Where approving a role change happens, said once for a viewer who may propose one. */
function approveHintNote(viewer: Viewer) {
  const hint = roleHint(viewer, approveAction("grant_role"), "approve role changes");
  return (
    <p className="mt-6 text-sm text-muted">
      Proposed role changes wait on the Change requests page for a second person to approve them.
      {hint ? ` ${hint}` : ""}
    </p>
  );
}

// --- the directory -----------------------------------------------------------

type DirectoryProps = {
  given?: Resource<PrincipalPage>;
  /** Fills the grant form; null when the viewer may not propose a grant. */
  onGrant: ((person: Principal) => void) | null;
};

function Directory({ given, onGrant }: DirectoryProps) {
  const [typed, setTyped] = useState("");
  const [query, setQuery] = useState<{ q: string; cursors: string[] }>({ q: "", cursors: [] });
  const cursor = query.cursors.at(-1);
  const load = useCallback(
    () => fetchPrincipals({ q: query.q || undefined, cursor }),
    [query.q, cursor],
  );
  const read = useResource(load);
  const resource = given ?? read.resource;
  const pageNo = query.cursors.length + 1;

  function onSearch(event: FormEvent) {
    event.preventDefault();
    setQuery({ q: typed.trim(), cursors: [] });
  }

  return (
    <div className="space-y-4">
      <form onSubmit={onSearch} className="flex flex-col gap-2 sm:flex-row sm:items-end" role="search">
        <TextField
          id="users-search"
          label="Name or subject contains"
          value={typed}
          onChange={setTyped}
          maxLength={200}
          className="flex-1"
        />
        <Button type="submit" variant="secondary">
          Search
        </Button>
      </form>
      <ResourceState
        resource={resource}
        loading="Loading people…"
        summary={(page) =>
          `Page ${pageNo}: ${page.items.length} ${page.items.length === 1 ? "person" : "people"}${
            page.next_cursor ? "; more follow." : "; no more follow."
          }`
        }
        onRetry={read.retry}
      >
        {(page) => (
          <>
            <DataTable
              rows={page.items}
              rowKey={(row) => `${row.issuer}#${row.subject}`}
              emptyMessage={query.q ? "Nobody matches that search." : "Nobody has signed in yet."}
              columns={[
                {
                  key: "name",
                  header: "Name",
                  render: (row) => row.display_name || "—",
                },
                { key: "subject", header: "Subject", render: (row) => <code className="break-all">{row.subject}</code> },
                { key: "issuer", header: "Issuer", render: (row) => <code className="break-all">{row.issuer}</code> },
                { key: "seen", header: "Last seen", render: (row) => formatDateTime(row.last_seen_at) },
                ...(onGrant
                  ? [
                      {
                        key: "grant",
                        header: "",
                        render: (row: Principal) => (
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-label={`Grant a role to ${row.subject}`}
                            onClick={() => onGrant(row)}
                          >
                            Grant a role
                          </Button>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            <div className="mt-3 flex gap-2">
              {query.cursors.length > 0 && (
                <Button size="sm" variant="ghost" onClick={() => setQuery({ ...query, cursors: [] })}>
                  First page
                </Button>
              )}
              {page.next_cursor && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setQuery({ ...query, cursors: [...query.cursors, page.next_cursor as string] })}
                >
                  Next page
                </Button>
              )}
            </div>
          </>
        )}
      </ResourceState>
    </div>
  );
}

// --- the grant form ----------------------------------------------------------

type GrantRoleProps = {
  form: GrantForm;
  setForm: (form: GrantForm) => void;
  roleRef: React.RefObject<HTMLSelectElement | null>;
};

function GrantRole({ form, setForm, roleRef }: GrantRoleProps) {
  const { proposal, propose } = useProposal();
  const [errors, setErrors] = useState<GrantErrors>({});
  const valueName = form.kind === "group" ? "Group name" : "Subject";
  const issuerRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLInputElement>(null);

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (proposal.phase === "busy") return;
    const found = grantErrors(form);
    setErrors(found);
    if (found.role) roleRef.current?.focus();
    else if (found.issuer) issuerRef.current?.focus();
    else if (found.value) valueRef.current?.focus();
    if (Object.keys(found).length > 0) return;
    void propose("grant_role", grantParams(form));
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <div>
        <label htmlFor="grant-role" className="mb-1.5 block text-sm font-medium text-ink">
          Role
        </label>
        <select
          id="grant-role"
          ref={roleRef}
          value={form.role}
          aria-invalid={errors.role ? true : undefined}
          aria-describedby={errors.role ? "grant-role-error" : form.role ? "grant-role-purpose" : undefined}
          onChange={(event) => setForm({ ...form, role: event.target.value as GrantForm["role"] })}
          className={selectClass}
        >
          <option value="">Choose a role</option>
          {ROLES.map((role) => (
            <option key={role} value={role}>
              {role}
            </option>
          ))}
        </select>
        {form.role && !errors.role && (
          <p id="grant-role-purpose" className="mt-1 text-xs text-muted">
            {ROLE_PURPOSES[form.role]}
          </p>
        )}
        {errors.role && (
          <p id="grant-role-error" className="mt-1 text-xs font-medium text-decision-block">
            {errors.role}
          </p>
        )}
      </div>
      <div>
        <label htmlFor="grant-kind" className="mb-1.5 block text-sm font-medium text-ink">
          Grant to
        </label>
        <select
          id="grant-kind"
          value={form.kind}
          onChange={(event) => setForm({ ...form, kind: event.target.value as GrantForm["kind"] })}
          className={selectClass}
        >
          <option value="principal">A person</option>
          <option value="group">An IdP group</option>
        </select>
      </div>
      <TextField
        id="grant-issuer"
        ref={issuerRef}
        label="Issuer"
        value={form.issuer}
        onChange={(issuer) => setForm({ ...form, issuer })}
        hint="The OIDC issuer, as the directory shows it."
        error={errors.issuer}
        maxLength={MAX_FIELD}
      />
      <TextField
        id="grant-value"
        ref={valueRef}
        label={valueName}
        value={form.value}
        onChange={(value) => setForm({ ...form, value })}
        hint={form.kind === "group" ? "The group as the IdP's groups claim names it." : "The person's subject."}
        error={errors.value}
        maxLength={MAX_FIELD}
      />
      <Button type="submit" aria-disabled={proposal.phase === "busy"} className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50">
        Propose grant
      </Button>
      <ProposalStatus proposal={proposal} proposed={roleChangeProposed} />
    </form>
  );
}

// --- the bindings ------------------------------------------------------------

function Bindings({ given, revokeHint }: { given?: Resource<RoleBinding[]>; revokeHint: string | null }) {
  const [includeEnded, setIncludeEnded] = useState(false);
  const load = useCallback(() => fetchRoleBindings(includeEnded), [includeEnded]);
  const read = useResource(load);
  const resource = given ?? read.resource;
  const { proposal, propose } = useProposal();

  return (
    <div className="space-y-4">
      <label className="flex items-center gap-2 text-sm text-ink">
        <input
          type="checkbox"
          checked={includeEnded}
          onChange={(event) => setIncludeEnded(event.target.checked)}
          className="h-4 w-4 rounded border-border"
        />
        Include ended bindings
      </label>
      {revokeHint && <RoleHint>{revokeHint}</RoleHint>}
      <ResourceState
        resource={resource}
        loading="Loading role bindings…"
        summary={(rows) => `${rows.length} ${rows.length === 1 ? "binding" : "bindings"}.`}
        onRetry={read.retry}
      >
        {(rows) => (
          <DataTable
            rows={rows}
            rowKey={(row) => row.id}
            emptyMessage="No role bindings."
            columns={[
              { key: "role", header: "Role", render: (row) => <Badge>{row.role}</Badge> },
              {
                key: "holder",
                header: "Held by",
                render: (row) => (
                  <span>
                    {row.subject.kind === "group" ? "Group " : ""}
                    <code className="break-all">{row.subject.value}</code>
                  </span>
                ),
              },
              { key: "issuer", header: "Issuer", render: (row) => <code className="break-all">{row.subject.issuer}</code> },
              {
                key: "granted",
                header: "Granted",
                render: (row) =>
                  `${formatDateTime(row.granted_at)}${
                    row.granted_by_change_request ? ` (${row.granted_by_change_request})` : " (bootstrap)"
                  }`,
              },
              {
                key: "ended",
                header: "Ended",
                render: (row) => (row.ended_at ? formatDateTime(row.ended_at) : "—"),
              },
              ...(revokeHint
                ? []
                : [
                    {
                      key: "revoke",
                      header: "",
                      render: (row: RoleBinding) =>
                        row.ended_at ? null : (
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-disabled={proposal.phase === "busy"}
                            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
                            aria-label={`Propose revoking ${row.role} from ${row.subject.value}`}
                            onClick={() => {
                              if (proposal.phase !== "busy") void propose("revoke_role", { binding_id: row.id });
                            }}
                          >
                            Propose revoke
                          </Button>
                        ),
                    },
                  ]),
            ]}
          />
        )}
      </ResourceState>
      <ProposalStatus proposal={proposal} proposed={roleChangeProposed} />
    </div>
  );
}

// --- the access review -------------------------------------------------------

type ReviewState =
  | { phase: "idle" }
  | { phase: "busy" }
  | { phase: "shown"; review: AccessReview }
  | { phase: "downloaded" }
  | { phase: "error"; error: unknown };

/** Saves `text` as a file through a temporary link; nothing is kept. */
function save(text: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  // Revoked a little later: a browser may still be reading it when click() returns.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function Review() {
  const [state, setState] = useState<ReviewState>({ phase: "idle" });
  const [shown, setShown] = useState<AccessReview | null>(null);

  async function show() {
    if (state.phase === "busy") return;
    setState({ phase: "busy" });
    try {
      const review = await fetchAccessReview();
      setShown(review);
      setState({ phase: "shown", review });
    } catch (error) {
      setState({ phase: "error", error });
    }
  }

  async function download() {
    if (state.phase === "busy") return;
    setState({ phase: "busy" });
    try {
      save(await fetchAccessReviewCsv(), "access-review.csv");
      setState({ phase: "downloaded" });
    } catch (error) {
      setState({ phase: "error", error });
    }
  }

  const status =
    state.phase === "busy"
      ? "Exporting the access review…"
      : state.phase === "shown"
        ? `Access review generated ${formatDateTime(state.review.generated_at)}: ${state.review.rows.length} ${
            state.review.rows.length === 1 ? "binding" : "bindings"
          }. The export is recorded in the admin audit.`
        : state.phase === "downloaded"
          ? "Downloaded access-review.csv. The export is recorded in the admin audit."
          : "";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <Button
          variant="secondary"
          aria-disabled={state.phase === "busy"}
          className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          onClick={() => void show()}
        >
          Show review
        </Button>
        <Button
          variant="ghost"
          aria-disabled={state.phase === "busy"}
          className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
          onClick={() => void download()}
        >
          Download CSV
        </Button>
      </div>
      <ProblemAlert error={state.phase === "error" ? state.error : null} className="empty:mb-0" />
      <p role="status" aria-live="polite" className="text-sm text-muted">
        {status}
      </p>
      {shown && (
        <>
          <p className="text-sm text-muted">
            {shown.note} A person not seen for more than {shown.stale_after_days} days, or never, is stale.
          </p>
          <DataTable
            rows={shown.rows}
            rowKey={(row) => row.binding_id}
            emptyMessage="No active role bindings."
            columns={[
              { key: "role", header: "Role", render: (row) => <Badge>{row.role}</Badge> },
              {
                key: "holder",
                header: "Held by",
                render: (row) => (
                  <span>
                    {row.subject_kind === "group" ? "Group " : ""}
                    <code className="break-all">{row.subject}</code>
                    {row.display_name && row.display_name !== row.subject ? ` (${row.display_name})` : ""}
                  </span>
                ),
              },
              { key: "proposer", header: "Proposed by", render: (row) => row.proposer || "—" },
              { key: "approver", header: "Approved by", render: (row) => row.approver || "—" },
              { key: "granted", header: "Granted", render: (row) => formatDateTime(row.granted_at) },
              {
                key: "seen",
                header: "Last seen",
                render: (row) => (row.last_seen_at ? formatDateTime(row.last_seen_at) : "Never"),
              },
              { key: "stale", header: "Stale", render: (row) => staleLabel(row.stale) },
            ]}
          />
        </>
      )}
    </div>
  );
}
