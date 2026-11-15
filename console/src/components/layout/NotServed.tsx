import { Link } from "react-router-dom";
import { Card, CardDescription, CardHeader, CardTitle } from "../ui/Card";
import { PageHeader } from "../ui/PageHeader";

/**
 * In place of a credit-track page when the server runs --agent-only: the
 * page's API routes are not served there, so the page could only fail.
 */
export function NotServed() {
  return (
    <section>
      <PageHeader title="Not served on this server" />
      <Card>
        <CardHeader>
          <CardTitle>This server runs agent-only</CardTitle>
          <CardDescription>
            It was started with <code>--agent-only</code>, so it does not serve the credit track:
            evaluate, policy packs, models, batch jobs, incidents, retention and decision events.
          </CardDescription>
        </CardHeader>
        <p className="text-sm text-muted">
          The agent pages, change requests and the audit log are available.{" "}
          <Link to="/agents" className="font-medium text-kavach-700 underline hover:text-saffron-600">
            Go to Agents
          </Link>
        </p>
      </Card>
    </section>
  );
}
