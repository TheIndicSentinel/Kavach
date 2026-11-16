import { useCallback, useState, type FormEvent, type ReactNode } from "react";
import { useResource, type Resource } from "../hooks/useResource";
import {
  fetchPrincipals,
  fetchRoleBindings,
  proposeChange,
  type Principal,
  type PrincipalPage,
  type RoleBinding,
  type RoleName,
} from "../lib/api";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { Dialog } from "../components/ui/Dialog";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { ResourceState } from "../components/ui/ResourceState";
import { RoleHint } from "../components/ui/RoleHint";
import { TextField } from "../components/ui/TextField";
import { roleHint, proposeAction, mayProbably } from "../lib/permissions";
import { useViewer } from "../lib/changeRequests";

const PAGE_SIZE = 50;
const QUERY_LIMIT = 512;

function PagingButton({
  enabled,
  onClick,
  children,
}: {
  enabled: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-disabled={!enabled}
      onClick={() => {
        if (enabled) onClick();
      }}
      className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
    >
      {children}
    </Button>
  );
}

function seenAt(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown" : date.toLocaleString();
}

export function roleGrantParams(role: RoleName, principal: Principal) {
  return {
    role,
    subject: { kind: "principal" as const, issuer: principal.issuer, value: principal.subject },
  };
}

export function roleRevokeParams(binding: RoleBinding) {
  return { binding_id: binding.id };
}

function PrincipalRows({ principals, onGrant, canGrant }: {
  principals: readonly Principal[];
  onGrant: (principal: Principal) => void;
  canGrant: boolean;
}) {
  if (principals.length === 0) {
    return <p className="py-6 text-sm text-muted">No people match this directory view.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[42rem] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase tracking-wide text-muted">
            <th scope="col" className="px-3 py-3 font-semibold">Person</th>
            <th scope="col" className="px-3 py-3 font-semibold">Identity provider</th>
            <th scope="col" className="px-3 py-3 font-semibold">First seen</th>
            <th scope="col" className="px-3 py-3 font-semibold">Last seen</th>
            {canGrant && <th scope="col" className="px-3 py-3 font-semibold">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {principals.map((principal) => (
            <tr key={`${principal.issuer}\0${principal.subject}`} className="border-b border-border last:border-0">
              <th scope="row" className="px-3 py-3 font-medium text-ink">
                <span className="block">{principal.display_name || "Unnamed person"}</span>
                <code className="mt-1 block break-all text-xs font-normal text-muted">{principal.subject}</code>
              </th>
              <td className="break-all px-3 py-3 text-muted">{principal.issuer}</td>
              <td className="px-3 py-3 text-muted">{seenAt(principal.first_seen_at)}</td>
              <td className="px-3 py-3 text-muted">{seenAt(principal.last_seen_at)}</td>
              {canGrant && (
                <td className="px-3 py-3">
                  <Button variant="secondary" size="sm" aria-label={`Grant role to ${principal.display_name || principal.subject}`} onClick={() => onGrant(principal)}>
                    Grant role
                  </Button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RoleBindingRows({ bindings, canRevoke, onRevoke }: {
  bindings: readonly RoleBinding[];
  canRevoke: boolean;
  onRevoke: (binding: RoleBinding) => void;
}) {
  if (bindings.length === 0) {
    return <p className="py-6 text-sm text-muted">No active role bindings.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[42rem] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase tracking-wide text-muted">
            <th scope="col" className="px-3 py-3 font-semibold">Role</th>
            <th scope="col" className="px-3 py-3 font-semibold">Subject</th>
            <th scope="col" className="px-3 py-3 font-semibold">Identity provider</th>
            <th scope="col" className="px-3 py-3 font-semibold">Granted</th>
            {canRevoke && <th scope="col" className="px-3 py-3 font-semibold">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {bindings.map((binding) => (
            <tr key={binding.id} className="border-b border-border last:border-0">
              <th scope="row" className="px-3 py-3 font-medium text-ink">{binding.role}</th>
              <td className="px-3 py-3 text-ink">
                <span className="block">{binding.subject.value}</span>
                <span className="mt-1 block text-xs text-muted">{binding.subject.kind}</span>
              </td>
              <td className="break-all px-3 py-3 text-muted">{binding.subject.issuer}</td>
              <td className="px-3 py-3 text-muted">{seenAt(binding.granted_at)}</td>
              {canRevoke && (
                <td className="px-3 py-3">
                  <Button variant="secondary" size="sm" aria-label={`Propose revoke for ${binding.role} role held by ${binding.subject.value}`} onClick={() => onRevoke(binding)}>
                    Propose revoke
                  </Button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type UsersPageProps = {
  /** For static page-state tests: the first directory read. */
  resource?: Resource<PrincipalPage>;
  /** For static page-state tests: the active role-binding read. */
  bindingsResource?: Resource<RoleBinding[]>;
};

export default function UsersPage({ resource: given, bindingsResource: givenBindings }: UsersPageProps = {}) {
  const viewer = useViewer();
  const grantAction = proposeAction("grant_role");
  const canGrant = mayProbably(viewer, grantAction);
  const grantHint = roleHint(viewer, grantAction, "grant roles");
  const revokeAction = proposeAction("revoke_role");
  const canRevoke = mayProbably(viewer, revokeAction);
  const revokeHint = roleHint(viewer, revokeAction, "revoke roles");
  const [grantTarget, setGrantTarget] = useState<Principal | null>(null);
  const [grantRole, setGrantRole] = useState<RoleName>("viewer");
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantError, setGrantError] = useState<unknown>(null);
  const [grantNotice, setGrantNotice] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<RoleBinding | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState<unknown>(null);
  const [revokeNotice, setRevokeNotice] = useState("");
  const [searchText, setSearchText] = useState("");
  const [query, setQuery] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const load = useCallback(
    () => fetchPrincipals({ limit: PAGE_SIZE, ...(query ? { q: query } : {}), ...(cursor ? { cursor } : {}) }),
    [query, cursor],
  );
  const { resource: read, retry } = useResource(load);
  const { resource: bindingsRead, retry: retryBindings } = useResource(fetchRoleBindings);
  const resource = given ?? read;
  const bindingsResource = givenBindings ?? bindingsRead;
  const page = resource.phase === "ok" ? resource.data : undefined;

  function submitSearch(event: FormEvent) {
    event.preventDefault();
    setQuery(searchText.trim());
    setCursors([]);
  }

  async function submitGrant(event: FormEvent) {
    event.preventDefault();
    if (!grantTarget || grantBusy) return;
    setGrantBusy(true);
    setGrantError(null);
    try {
      const request = await proposeChange("grant_role", roleGrantParams(grantRole, grantTarget));
      setGrantTarget(null);
      setGrantNotice(`Role grant proposal ${request.id} is pending. The role takes effect only after a different authorized person approves it.`);
    } catch (error) {
      setGrantError(error);
    } finally {
      setGrantBusy(false);
    }
  }

  async function submitRevoke(event: FormEvent) {
    event.preventDefault();
    if (!revokeTarget || revokeBusy) return;
    setRevokeBusy(true);
    setRevokeError(null);
    try {
      const request = await proposeChange("revoke_role", roleRevokeParams(revokeTarget));
      setRevokeTarget(null);
      setRevokeNotice(`Role revoke proposal ${request.id} is pending. The binding remains active unless a different authorized person approves it.`);
    } catch (error) {
      setRevokeError(error);
    } finally {
      setRevokeBusy(false);
    }
  }

  return (
    <section>
      <PageHeader
        title="Users & roles"
        hindi="उपयोगकर्ता और भूमिकाएँ"
        subtitle="People the server has seen in this tenant. Role changes require an approved change request."
      />

      <Card>
        <CardHeader>
          <CardTitle>People directory</CardTitle>
          <CardDescription>
            Search by display name or subject. Results are ordered by identity provider and subject, up to {PAGE_SIZE} per page.
          </CardDescription>
        </CardHeader>

        {grantHint && <RoleHint>{grantHint}</RoleHint>}
        {grantNotice && <p role="status" className="mb-4 text-sm text-ink">{grantNotice}</p>}

        <form onSubmit={submitSearch} className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end">
          <TextField
            id="principal-search"
            label="Name or subject"
            value={searchText}
            onChange={setSearchText}
            maxLength={QUERY_LIMIT}
            className="flex-1"
          />
          <Button type="submit" variant="secondary" className="sm:mb-0.5">Search</Button>
        </form>

        <ResourceState
          resource={resource}
          loading="Loading people…"
          summary={(data) => `${data.items.length} ${data.items.length === 1 ? "person" : "people"} on this page.`}
          onRetry={retry}
        >
          {(data) => (
            <PrincipalRows principals={data.items} canGrant={canGrant} onGrant={(principal) => {
              setGrantTarget(principal);
              setGrantError(null);
            }} />
          )}
        </ResourceState>

        <nav aria-label="People directory pages" className="mt-4 flex flex-wrap items-center gap-2">
          <PagingButton enabled={cursors.length > 0} onClick={() => setCursors([])}>First page</PagingButton>
          <PagingButton
            enabled={cursors.length > 0}
            onClick={() => setCursors((previous) => previous.slice(0, -1))}
          >
            Previous page
          </PagingButton>
          <PagingButton
            enabled={Boolean(page?.next_cursor)}
            onClick={() => {
              const nextCursor = page?.next_cursor;
              if (nextCursor) setCursors((previous) => [...previous, nextCursor]);
            }}
          >
            Next page
          </PagingButton>
          <span className="text-sm text-muted">Page {cursors.length + 1}</span>
        </nav>
      </Card>

      {grantTarget && (
        <Dialog
          titleId="grant-role-title"
          title={`Propose a role for ${grantTarget.display_name || grantTarget.subject}`}
          descriptionId="grant-role-description"
          onCancel={() => { if (!grantBusy) setGrantTarget(null); }}
          busy={grantBusy}
        >
          <p id="grant-role-description" className="mb-4 text-sm text-muted">
            This submits a maker-checker request. It does not grant access unless a different authorized person approves it.
          </p>
          <form onSubmit={submitGrant} className="space-y-4">
            <label htmlFor="grant-role" className="block text-sm font-medium text-ink">Role</label>
            <select id="grant-role" value={grantRole} onChange={(event) => setGrantRole(event.target.value as RoleName)} className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink">
              {(["viewer", "auditor", "operator", "approver", "policy_admin", "user_admin", "superadmin"] satisfies RoleName[]).map((role) => (
                <option key={role} value={role}>{role}</option>
              ))}
            </select>
            <ProblemAlert error={grantError} />
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" aria-disabled={grantBusy} onClick={() => { if (!grantBusy) setGrantTarget(null); }}>Cancel</Button>
              <Button type="submit" aria-disabled={grantBusy}>{grantBusy ? "Submitting…" : "Propose grant"}</Button>
            </div>
          </form>
        </Dialog>
      )}

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Active role bindings</CardTitle>
          <CardDescription>Roles assigned to people or identity-provider groups in this tenant.</CardDescription>
        </CardHeader>
        {revokeHint && <RoleHint>{revokeHint}</RoleHint>}
        {revokeNotice && <p role="status" className="mb-4 text-sm text-ink">{revokeNotice}</p>}
        <ResourceState
          resource={bindingsResource}
          loading="Loading active role bindings…"
          summary={(items) => `${items.length} active ${items.length === 1 ? "binding" : "bindings"}.`}
          onRetry={retryBindings}
        >
          {(items) => <RoleBindingRows bindings={items} canRevoke={canRevoke} onRevoke={(binding) => {
            setRevokeTarget(binding);
            setRevokeError(null);
          }} />}
        </ResourceState>
      </Card>

      {revokeTarget && (
        <Dialog
          titleId="revoke-role-title"
          title={`Propose revoking ${revokeTarget.role} from ${revokeTarget.subject.value}`}
          descriptionId="revoke-role-description"
          onCancel={() => { if (!revokeBusy) setRevokeTarget(null); }}
          busy={revokeBusy}
        >
          <p id="revoke-role-description" className="mb-4 text-sm text-muted">
            This submits a maker-checker request. The active binding stays in effect unless a different authorized person approves it.
          </p>
          <form onSubmit={submitRevoke} className="space-y-4">
            <ProblemAlert error={revokeError} />
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" aria-disabled={revokeBusy} onClick={() => { if (!revokeBusy) setRevokeTarget(null); }}>Cancel</Button>
              <Button type="submit" aria-disabled={revokeBusy}>{revokeBusy ? "Submitting…" : "Propose revoke"}</Button>
            </div>
          </form>
        </Dialog>
      )}
    </section>
  );
}
