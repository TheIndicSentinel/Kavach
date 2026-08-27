import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/overview", label: "Overview" },
  { to: "/evaluate", label: "Evaluate" },
  { to: "/settings", label: "Settings" },
];

export default function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">K</span>
          <div>
            <strong>Kavach</strong>
            <p>Governance Console</p>
          </div>
        </div>
        <nav>
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                isActive ? "nav-link active" : "nav-link"
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
