import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AgentStateDetails } from "../components/agents/AgentViews";
import { Button } from "../components/ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ProblemAlert } from "../components/ui/ProblemAlert";
import { Skeleton } from "../components/ui/Skeleton";
import { fetchAgent, type AgentStateView } from "../lib/api";

type Loaded = { key: string; agent?: AgentStateView; error?: unknown };

export default function AgentDetailPage() {
  const { agentId = "" } = useParams();
  const [attempt, setAttempt] = useState(0);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
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
  const agent = current?.agent;

  return (
    <section>
      <PageHeader
        title="Agent"
        hindi="एजेंट"
        subtitle="The agent's state and the last change to it. Read-only."
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
          <CardTitle>
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
    </section>
  );
}
