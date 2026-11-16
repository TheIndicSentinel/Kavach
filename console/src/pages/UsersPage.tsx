import { useCallback, useState, type FormEvent, type ReactNode } from "react";
import { useResource, type Resource } from "../hooks/useResource";
import {
  fetchPrincipals,
  fetchRoleBindings,
  type Principal,
  type PrincipalPage,
  type RoleBinding,
} from "../lib/api";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { TextField } from "../components/ui/TextField";

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

function PrincipalRows({ principals }: { principals: readonly Principal[] }) {
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RoleBindingRows({ bindings }: { bindings: readonly RoleBinding[] }) {
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
            <PrincipalRows
              principals={data.items}
            />
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

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Active role bindings</CardTitle>
          <CardDescription>Roles assigned to people or identity-provider groups in this tenant.</CardDescription>
        </CardHeader>
        <ResourceState
          resource={bindingsResource}
          loading="Loading active role bindings…"
          summary={(items) => `${items.length} active ${items.length === 1 ? "binding" : "bindings"}.`}
          onRetry={retryBindings}
        >
          {(items) => <RoleBindingRows bindings={items} />}
        </ResourceState>
      </Card>
    </section>
  );
}
