import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Badge } from "../ui/Badge";
import { DataTable } from "../ui/DataTable";
import { AGENT_STATE_VARIANT } from "../../lib/agents";
import type { AgentStateName, AgentStateView } from "../../lib/api";
import { formatDateTime } from "../../lib/format";

/** The state as text; the colour only repeats it. */
export function AgentStateBadge({ state }: { state: AgentStateName }) {
  return <Badge variant={AGENT_STATE_VARIANT[state]}>{state}</Badge>;
}

export function agentPath(agentId: string): string {
  return `/agents/${encodeURIComponent(agentId)}`;
}

/** A label and value list; a missing value reads "none". */
export function FieldList({ fields }: { fields: [label: string, value: ReactNode][] }) {
  return (
    <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(10rem,auto)_1fr]">
      {fields.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="font-medium text-muted">{label}</dt>
          <dd className="break-all text-ink">
            {value === undefined || value === null || value === "" ? (
              <span className="text-muted">none</span>
            ) : (
              value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// The helpers below return null for a missing value, so FieldList shows "none".

export function timestamp(value?: string | null): ReactNode {
  if (!value) return null;
  return (
    <time dateTime={value} title={value}>
      {formatDateTime(value)}
    </time>
  );
}

export function mono(value?: string | null): ReactNode {
  if (!value) return null;
  return <code className="font-mono text-xs">{value}</code>;
}

type AgentTableProps = {
  agents: AgentStateView[];
  emptyMessage: string;
};

export function AgentTable({ agents, emptyMessage }: AgentTableProps) {
  return (
    <DataTable
      rows={agents}
      rowKey={(row) => row.agent_id}
      emptyMessage={emptyMessage}
      columns={[
        {
          key: "agent",
          header: "Agent",
          render: (row) => (
            <Link
              to={agentPath(row.agent_id)}
              className="break-all font-mono text-sm font-semibold text-kavach-700 hover:text-saffron-600"
            >
              {row.agent_id}
            </Link>
          ),
        },
        { key: "state", header: "State", render: (row) => <AgentStateBadge state={row.state} /> },
        {
          key: "change",
          header: "Change no.",
          render: (row) => (row.change_no === 0 ? "0 (never changed)" : row.change_no),
        },
        { key: "reason", header: "Reason code", render: (row) => row.reason_code ?? "none" },
        { key: "changed_by", header: "Changed by", render: (row) => row.changed_by ?? "none" },
        {
          key: "changed_at",
          header: "Changed at",
          render: (row) => timestamp(row.changed_at) ?? "none",
        },
      ]}
    />
  );
}

/** Every field of an agent's state; an agent never changed says so. */
export function AgentStateDetails({ agent }: { agent: AgentStateView }) {
  if (agent.change_no === 0) {
    return (
      <div className="space-y-4">
        <p className="text-sm font-medium text-ink">active, never changed</p>
        <FieldList
          fields={[
            ["Agent", mono(agent.agent_id)],
            ["State", <AgentStateBadge state={agent.state} />],
            ["Change number", "0"],
          ]}
        />
      </div>
    );
  }
  return (
    <FieldList
      fields={[
        ["Agent", mono(agent.agent_id)],
        ["State", <AgentStateBadge state={agent.state} />],
        ["Change number", String(agent.change_no)],
        ["Reason code", agent.reason_code],
        ["Note", agent.note],
        ["Changed by", agent.changed_by],
        ["Approved by", agent.approved_by],
        ["Change request", mono(agent.change_request_id)],
        ["Changed at", timestamp(agent.changed_at)],
      ]}
    />
  );
}
