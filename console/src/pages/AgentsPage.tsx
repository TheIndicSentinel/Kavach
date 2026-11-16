import { useCallback, useReducer, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { AgentTable, agentPath } from "../components/agents/AgentViews";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { TextField } from "../components/ui/TextField";
import {
  AGENT_STATES,
  AGENTS_PAGE_SIZE,
  LOOKUP_MAX_LENGTH,
  agentListQuery,
  agentPageEmptyMessage,
  agentPageSummary,
  agentPagingReducer,
  idProblem,
  initialAgentPaging,
} from "../lib/agents";
import { useResource, type Resource } from "../hooks/useResource";
import { fetchAgents, type AgentStateName, type AgentStatePage } from "../lib/api";

function isAgentState(value: string): value is AgentStateName {
  return (AGENT_STATES as readonly string[]).includes(value);
}

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

function AgentLookup() {
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const [agentId, setAgentId] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  function submit(event: FormEvent) {
    event.preventDefault();
    const id = agentId.trim();
    const why = idProblem("agent id", id);
    setProblem(why);
    if (why) {
      input.current?.focus();
      return;
    }
    navigate(agentPath(id));
  }

  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Look up an agent</CardTitle>
        <CardDescription>
          By its exact id, as a passport names it. Any other id is not found.
        </CardDescription>
      </CardHeader>
      <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <TextField
          id="agent-lookup"
          label="Agent id"
          value={agentId}
          onChange={setAgentId}
          error={problem}
          maxLength={LOOKUP_MAX_LENGTH}
          ref={input}
          className="flex-1"
        />
        <Button type="submit" variant="secondary" className="sm:mt-7">
          Look up
        </Button>
      </form>
    </Card>
  );
}

type AgentsPageProps = {
  /** For tests: the first page's read, in place of the API's answer. */
  resource?: Resource<AgentStatePage>;
};

export default function AgentsPage({ resource: given }: AgentsPageProps = {}) {
  const [paging, dispatch] = useReducer(agentPagingReducer, initialAgentPaging);
  const load = useCallback(() => fetchAgents(agentListQuery(paging)), [paging]);
  const { resource: read, retry } = useResource(load);
  const resource = given ?? read;
  const page = resource.phase === "ok" ? resource.data : undefined;
  const pageNo = paging.cursors.length + 1;

  return (
    <section>
      <PageHeader
        title="Agents"
        hindi="एजेंट"
        subtitle="Every agent a passport names in this tenant, and its state. Open an agent for the actions its state allows."
      />

      <AgentLookup />

      <Card>
        <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <CardTitle>All agents</CardTitle>
            <CardDescription>In ascending agent-id order, {AGENTS_PAGE_SIZE} to a page.</CardDescription>
          </div>
          <div>
            <label htmlFor="agent-state-filter" className="mb-1.5 block text-sm font-medium text-ink">
              State
            </label>
            <select
              id="agent-state-filter"
              value={paging.state ?? ""}
              onChange={(event) => {
                const value = event.target.value;
                dispatch({ type: "filter", state: isAgentState(value) ? value : undefined });
              }}
              className="rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
            >
              <option value="">All states</option>
              {AGENT_STATES.map((state) => (
                <option key={state} value={state}>
                  {state}
                </option>
              ))}
            </select>
          </div>
        </CardHeader>

        <ResourceState
          resource={resource}
          loading="Loading agents…"
          summary={(data) => agentPageSummary(paging, data.items.length, data.next_cursor != null)}
          onRetry={retry}
        >
          {(data) => (
            <AgentTable
              agents={data.items}
              emptyMessage={agentPageEmptyMessage(paging, data.next_cursor != null)}
            />
          )}
        </ResourceState>

        {/* aria-disabled, not disabled: a button that disables itself mid-load
            would drop keyboard focus to the page body. */}
        <nav aria-label="Agent pages" className="mt-4 flex flex-wrap items-center gap-2">
          <PagingButton enabled={pageNo > 1} onClick={() => dispatch({ type: "first" })}>
            First page
          </PagingButton>
          <PagingButton enabled={pageNo > 1} onClick={() => dispatch({ type: "previous" })}>
            Previous page
          </PagingButton>
          <PagingButton
            enabled={Boolean(page?.next_cursor)}
            onClick={() => {
              if (page?.next_cursor) dispatch({ type: "next", cursor: page.next_cursor });
            }}
          >
            Next page
          </PagingButton>
          <span className="text-sm text-muted">Page {pageNo}</span>
        </nav>
      </Card>
    </section>
  );
}
