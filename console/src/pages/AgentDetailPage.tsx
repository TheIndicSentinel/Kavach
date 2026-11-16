import { useCallback, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AgentActions } from "../components/agents/AgentActions";
import { AgentStateDetails } from "../components/agents/AgentViews";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { ResourceState } from "../components/ui/ResourceState";
import { Skeleton } from "../components/ui/Skeleton";
import { useResource, type Resource } from "../hooks/useResource";
import { stopResultState } from "../lib/agentActions";
import { fetchAgent, type AgentStateView } from "../lib/api";
import { useViewer } from "../lib/changeRequests";

type AgentDetailPageProps = {
  /** For tests: the agent's read, in place of the API's answer. */
  resource?: Resource<AgentStateView>;
};

export default function AgentDetailPage({ resource: given }: AgentDetailPageProps = {}) {
  const { agentId = "" } = useParams();
  const viewer = useViewer();
  const load = useCallback(() => fetchAgent(agentId), [agentId]);
  const { resource: read, retry } = useResource(load);
  const resource = given ?? read;
  // The state a stop returned, shown until the agent is read again.
  const [stopped, setStopped] = useState<{ load: typeof load; agent: AgentStateView } | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const agent =
    resource.phase === "ok"
      ? ((stopped?.load === load ? stopped.agent : undefined) ?? resource.data)
      : undefined;

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

        <ResourceState
          resource={resource}
          loading="Loading agent…"
          summary={() => (agent ? `Agent ${agent.agent_id} is ${agent.state}.` : "")}
          notFound={`Agent ${agentId} doesn't exist on this server.`}
          onRetry={retry}
          skeleton={<Skeleton className="h-40 w-full" />}
        >
          {() => agent && <AgentStateDetails agent={agent} />}
        </ResourceState>
      </Card>

      {agent && (
        <AgentActions
          agent={agent}
          onStopped={(result) => setStopped({ load, agent: stopResultState(result) })}
          onStale={() => {
            setStopped(null);
            retry();
          }}
          fallbackFocus={title}
          viewer={viewer}
        />
      )}
    </section>
  );
}
