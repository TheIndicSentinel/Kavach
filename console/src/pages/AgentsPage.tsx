import { useEffect, useReducer, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { AgentTable, agentPath } from "../components/agents/AgentViews";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { Skeleton } from "../components/ui/Skeleton";
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
import { agentsPath, fetchAgents, type AgentStateName, type AgentStatePage } from "../lib/api";

type Loaded = { key: string; page?: AgentStatePage; error?: unknown };

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

export default function AgentsPage() {
  const [paging, dispatch] = useReducer(agentPagingReducer, initialAgentPaging);
  const [attempt, setAttempt] = useState(0);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const key = `${agentsPath(agentListQuery(paging))}#${attempt}`;

  // State is set only when the request settles, never synchronously here.
  useEffect(() => {
    let cancelled = false;
    const query = agentListQuery(paging);
    const settledKey = `${agentsPath(query)}#${attempt}`;
    fetchAgents(query)
      .then((page) => {
        if (!cancelled) setLoaded({ key: settledKey, page });
      })
      .catch((error: unknown) => {
        if (!cancelled) setLoaded({ key: settledKey, error });
      });
    return () => {
      cancelled = true;
    };
  }, [paging, attempt]);

  const current = loaded?.key === key ? loaded : null;
  const page = current?.page;
  const more = page?.next_cursor != null;
  const pageNo = paging.cursors.length + 1;

  const status = !current
    ? "Loading agents…"
    : page
      ? agentPageSummary(paging, page.items.length, more)
      : "";

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

        <ProblemAlert error={current?.error ?? null} className="mb-4 empty:mb-0" />
        <p role="status" aria-live="polite" className="mb-4 text-sm text-muted empty:mb-0">
          {status}
        </p>

        {!current && (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {current?.error !== undefined && (
          <Button variant="ghost" size="sm" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </Button>
        )}

        {page && (
          <AgentTable agents={page.items} emptyMessage={agentPageEmptyMessage(paging, more)} />
        )}

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
