import { useState } from "react";
import { getPrincipal, setPrincipal } from "../api";

export default function SettingsPage() {
  const [principal, setPrincipalInput] = useState(getPrincipal());
  const [saved, setSaved] = useState(false);

  function onSave(event: React.FormEvent) {
    event.preventDefault();
    setPrincipal(principal);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  }

  return (
    <section>
      <header className="page-header">
        <h1>Settings</h1>
        <p>Configure headers sent with console API calls.</p>
      </header>

      <form className="card settings-form" onSubmit={onSave}>
        <label htmlFor="principal">X-Kavach-Principal</label>
        <input
          id="principal"
          value={principal}
          onChange={(event) => setPrincipalInput(event.target.value)}
          placeholder="operator-1"
          autoComplete="off"
        />
        <p className="muted">
          Required when Cedar RBAC is enabled on the API. Stored in session
          storage for this browser tab.
        </p>
        <div className="form-actions">
          <button type="submit">Save</button>
          {saved && <span className="saved">Saved</span>}
        </div>
      </form>
    </section>
  );
}
