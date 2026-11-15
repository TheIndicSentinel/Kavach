import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AgentActions } from "../components/agents/AgentActions";
import { AgentStateDetails } from "../components/agents/AgentViews";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { Skeleton } from "../components/ui/Skeleton";
import { stopResultState } from "../lib/agentActions";
import { fetchAgent, type AgentStateView } from "../lib/api";
import { useViewer } from "../lib/changeRequests";

type Loaded = { key: string; agent?: AgentStateView; error?: unknown };

export default function AgentDetailPage() {
  const { agentId = "" } = useParams();
  const viewer = useViewer();
  const [attempt, setAttempt] = useState(0);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  // The state a stop returned, shown until the agent is read again.
  const [stopped, setStopped] = useState<Loaded | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const key = `${agentId}#${attempt}`;

  // State is set only when the request settles, never synchronously here.
  useEffect(() => {
    let cancelled = false;
    const settledKey = `${agentId}#${attempt}`;
    fetchAgent(agentId)
      .then((agent) => {
        if (!cancelled) setLoaded({ key: settledKey, agent });
      })
      .catch((error: unknown) => {
        if (!cancelled) setLoaded({ key: settledKey, error });
      });
    return () => {
      cancelled = true;
    };
  }, [agentId, attempt]);

  const current = loaded?.key === key ? loaded : null;
  const agent = (stopped?.key === key ? stopped.agent : undefined) ?? current?.agent;

  return (
    <section>
      <PageHeader
        title="Agent"
        hindi="एजेंट"
        subtitle="The agent's state, the last change to it, and the actions its state allows."
        action={
          <Link
            to="/agents"
            className="text-sm font-medium text-kavach-700 hover:text-saffron-600"
          >
            Back to agents
          </Link>
        }
      />

      <Card>
        <CardHeader>
          {/* Focus lands here when a dialog closes and its button is gone. */}
          <CardTitle ref={title} tabIndex={-1}>
            <span className="break-all font-mono">{agentId}</span>
          </CardTitle>
          <CardDescription>State, change number, reason, and who changed it.</CardDescription>
        </CardHeader>

        <ProblemAlert error={current?.error ?? null} className="mb-4 empty:mb-0" />
        <p role="status" aria-live="polite" className="mb-4 text-sm text-muted empty:mb-0">
          {!current ? "Loading agent…" : agent ? `Agent ${agent.agent_id} is ${agent.state}.` : ""}
        </p>

        {!current && <Skeleton className="h-40 w-full" />}
        {current?.error !== undefined && (
          <Button variant="ghost" size="sm" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </Button>
        )}
        {agent && <AgentStateDetails agent={agent} />}
      </Card>

      {agent && current && (
        <AgentActions
          agent={agent}
          onStopped={(result) => setStopped({ key, agent: stopResultState(result) })}
          onStale={() => setAttempt((n) => n + 1)}
          fallbackFocus={title}
          viewer={viewer}
        />
      )}
    </section>
  );
}
