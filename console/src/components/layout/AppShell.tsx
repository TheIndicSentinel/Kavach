import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { NotServed } from "./NotServed";
import { Sidebar } from "./Sidebar";
import { SuperadminBanner } from "./SuperadminBanner";
import { TopBar } from "./TopBar";
import { useAgentOnly } from "../../hooks/useAgentOnly";
import { cn } from "../../lib/cn";
import { useViewer } from "../../lib/changeRequests";
import { isCreditTrackPath } from "../../lib/creditTrack";

export function AppShell() {
  const [navOpen, setNavOpen] = useState(false);
  const { settled, agentOnly } = useAgentOnly();
  const viewer = useViewer();
  const { pathname } = useLocation();
  // A credit-track page waits for GET /v1/runtime, so on an agent-only
  // server it never calls a route that is not served.
  const creditPage = isCreditTrackPath(pathname);
  const page = !creditPage ? <Outlet /> : !settled ? null : agentOnly === true ? <NotServed /> : <Outlet />;

  // The open drawer closes on Escape, like any modal panel (WCAG 2.1.2).
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);

  return (
    <div className="flex min-h-screen bg-surface">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[60] focus:rounded-md focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-ink focus:shadow"
      >
        Skip to content
      </a>
      {navOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-kavach-950/60 backdrop-blur-[2px] lg:hidden"
          onClick={() => setNavOpen(false)}
        />
      )}

      <Sidebar open={navOpen} onNavigate={() => setNavOpen(false)} agentOnly={agentOnly} viewer={viewer} />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenNav={() => setNavOpen(true)} />
        <SuperadminBanner roles={viewer.roles ?? null} />
        <main id="main" tabIndex={-1} className={cn("flex-1 p-4 outline-none sm:p-6 lg:p-8")}>
          {page}
        </main>
      </div>
    </div>
  );
}
