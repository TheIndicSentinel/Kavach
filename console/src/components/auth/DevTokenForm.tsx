import { useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { Button } from "../ui/Button";
import { getAccessToken, getPrincipal, setAccessToken, setPrincipal } from "../../lib/api";

type DevTokenFormProps = {
  /** After saving: by default the page reloads, so every view uses the new credential. */
  afterSave?: () => void;
};

const inputClass =
  "w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink placeholder:text-stone-400 focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20";

/**
 * The development fallback (ADR-018 decision 6): offered only when console
 * login is not configured and the server runs with --insecure-dev. The values
 * are kept in this tab's sessionStorage, where any script on the page can
 * read them.
 */
export function DevTokenForm({ afterSave = () => window.location.reload() }: DevTokenFormProps) {
  const [principal, setPrincipalInput] = useState(getPrincipal());
  const [token, setTokenInput] = useState(getAccessToken());
  const [saved, setSaved] = useState(false);

  function onSave(event: React.FormEvent) {
    event.preventDefault();
    setPrincipal(principal);
    setAccessToken(token);
    setSaved(true);
    window.setTimeout(() => {
      setSaved(false);
      afterSave();
    }, 800);
  }

  return (
    <form onSubmit={onSave} className="space-y-4" aria-describedby="dev-token-note">
      <p id="dev-token-note" className="rounded-lg border border-decision-alert/30 bg-decision-alert-bg px-3 py-2 text-sm text-ink">
        <span className="font-semibold">Development fallback.</span> This server has no console login
        configured and runs with --insecure-dev, so it accepts a pasted token or a principal ID. Both are
        kept in this tab's sessionStorage, where any script on the page can read them.
      </p>
      <div>
        <label htmlFor="principal" className="mb-1.5 block text-sm font-medium text-ink">
          Principal ID
        </label>
        <input
          id="principal"
          value={principal}
          onChange={(event) => setPrincipalInput(event.target.value)}
          placeholder="operator-1"
          autoComplete="off"
          className={inputClass}
        />
      </div>
      <div>
        <label htmlFor="token" className="mb-1.5 block text-sm font-medium text-ink">
          Access token (OIDC)
        </label>
        <input
          id="token"
          type="password"
          value={token}
          onChange={(event) => setTokenInput(event.target.value)}
          placeholder="eyJ…"
          autoComplete="off"
          className={inputClass}
        />
      </div>
      <p className="text-xs leading-relaxed text-muted">
        The token is sent as{" "}
        <code className="rounded bg-stone-100 px-1 text-ink">Authorization: Bearer</code>. Without one, the
        principal ID is sent as <code className="rounded bg-stone-100 px-1 text-ink">X-Kavach-Principal</code>.
        Example principals from{" "}
        <code className="rounded bg-stone-100 px-1 text-ink">crates/kavach-auth/policies/entities.example.json</code>:{" "}
        <span className="font-medium text-ink">operator-1</span>,{" "}
        <span className="font-medium text-ink">viewer-1</span>,{" "}
        <span className="font-medium text-ink">admin-1</span> (proposes),{" "}
        <span className="font-medium text-ink">admin-2</span> or{" "}
        <span className="font-medium text-ink">approver-1</span> (approves).
      </p>
      <div className="flex items-center gap-3">
        <Button type="submit">Save principal</Button>
        <span role="status" className="text-sm font-medium text-decision-pass">
          {saved && (
            <span className="inline-flex items-center gap-1">
              <CheckCircle2 className="h-4 w-4" aria-hidden />
              Saved
            </span>
          )}
        </span>
      </div>
    </form>
  );
}
