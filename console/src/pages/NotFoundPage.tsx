import { Link, useLocation } from "react-router-dom";
import { PageHeader } from "../components/ui/PageHeader";

/**
 * A path the console has no page for. It says so, names the path, and links
 * to Overview, instead of sending the operator somewhere they did not ask for.
 */
export default function NotFoundPage() {
  const { pathname } = useLocation();

  return (
    <section>
      <PageHeader
        title="Page not found"
        hindi="पृष्ठ नहीं मिला"
        subtitle={`The console has no page at ${pathname}.`}
      />
      <Link
        to="/overview"
        className="inline-flex items-center rounded-lg border border-border px-3 py-1.5 text-sm font-semibold text-kavach-900 hover:bg-kavach-900/5"
      >
        Go to Overview
      </Link>
    </section>
  );
}
