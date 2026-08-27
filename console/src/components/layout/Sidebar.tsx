import { NavLink } from "react-router-dom";
import {
  Boxes,
  ClipboardList,
  FileSearch,
  Layers,
  LayoutDashboard,
  ScrollText,
  Settings,
  ShieldOff,
  TriangleAlert,
} from "lucide-react";
import { KavachLogo } from "../brand/KavachLogo";
import { cn } from "../../lib/cn";

const primaryNav = [
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/evaluate", label: "Evaluate", icon: FileSearch },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

const governanceNav = [
  { to: "/policies", label: "Policies", icon: ScrollText },
  { to: "/models", label: "Models", icon: Boxes },
  { to: "/batch", label: "Batch jobs", icon: Layers },
  { to: "/audit", label: "Audit", icon: ClipboardList },
  { to: "/incidents", label: "Incidents", icon: TriangleAlert },
  { to: "/retention", label: "Retention", icon: ShieldOff },
] as const;

type SidebarProps = {
  open: boolean;
  onNavigate: () => void;
};

export function Sidebar({ open, onNavigate }: SidebarProps) {
  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-50 flex h-full w-72 max-w-[85vw] shrink-0 flex-col bg-kavach-950 text-stone-300 shadow-(--shadow-sidebar) transition-transform duration-200 ease-out lg:static lg:z-auto lg:w-64 lg:max-w-none lg:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full",
      )}
      aria-label="Sidebar"
    >
      <div className="border-b border-white/10 px-5 py-5">
        <KavachLogo />
        <p className="mt-3 text-xs leading-relaxed text-stone-400">
          On-prem AI governance for regulated credit decisions.
        </p>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4" aria-label="Main navigation">
        {primaryNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-white/10 text-white"
                  : "text-stone-300 hover:bg-white/5 hover:text-white",
              )
            }
          >
            <item.icon className="h-4 w-4 shrink-0 opacity-80" aria-hidden />
            {item.label}
          </NavLink>
        ))}

        <div className="pt-6">
          <p className="px-3 pb-2 text-[0.65rem] font-semibold uppercase tracking-widest text-stone-500">
            Governance
          </p>
          {governanceNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-white/10 text-white"
                    : "text-stone-300 hover:bg-white/5 hover:text-white",
                )
              }
            >
              <item.icon className="h-4 w-4 shrink-0 opacity-80" aria-hidden />
              {item.label}
            </NavLink>
          ))}
        </div>
      </nav>

      <footer className="border-t border-white/10 px-5 py-4 text-xs text-stone-500">
        <p className="font-medium text-stone-400">कवच · Shield</p>
        <p className="mt-1">DPDP-aware · RBI-aligned posture</p>
      </footer>
    </aside>
  );
}
