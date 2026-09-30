import { useState } from "react";
import { CheckCircle2, KeyRound } from "lucide-react";
import { Button } from "../components/ui/Button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import {
  getAccessToken,
  getPrincipal,
  setAccessToken,
  setPrincipal,
} from "../lib/api";

export default function SettingsPage() {
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
      window.location.reload();
    }, 800);
  }

  return (
    <section>
      <PageHeader
        title="Settings"
        hindi="सेटिंग्स"
        subtitle="Paste an OIDC access token from your identity provider. The principal header is accepted only when the API runs with --insecure-dev (development)."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg bg-saffron-100 text-saffron-600">
              <KeyRound className="h-5 w-5" aria-hidden />
            </div>
            <CardTitle>Access credentials</CardTitle>
            <CardDescription>
              The access token is sent as{" "}
              <code className="rounded bg-stone-100 px-1 text-xs">Authorization: Bearer</code>. Without
              a token, the principal ID is sent as{" "}
              <code className="rounded bg-stone-100 px-1 text-xs">X-Kavach-Principal</code>, which the
              API refuses unless it runs with --insecure-dev.
            </CardDescription>
          </CardHeader>

          <form onSubmit={onSave} className="space-y-4">
            <div>
              <label
                htmlFor="principal"
                className="mb-1.5 block text-sm font-medium text-ink"
              >
                Principal ID
              </label>
              <input
                id="principal"
                value={principal}
                onChange={(event) => setPrincipalInput(event.target.value)}
                placeholder="operator-1"
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink placeholder:text-stone-400 focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
              />
            </div>
            <div>
              <label
                htmlFor="token"
                className="mb-1.5 block text-sm font-medium text-ink"
              >
                Access token (OIDC)
              </label>
              <input
                id="token"
                type="password"
                value={token}
                onChange={(event) => setTokenInput(event.target.value)}
                placeholder="eyJ…"
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-ink placeholder:text-stone-400 focus:border-saffron-500 focus:ring-2 focus:ring-saffron-500/20"
              />
            </div>
            <p className="text-xs leading-relaxed text-muted">
              Example principals from{" "}
              <code className="rounded bg-stone-100 px-1">
                crates/kavach-auth/policies/entities.example.json
              </code>
              : <span className="font-medium text-ink">operator-1</span>,{" "}
              <span className="font-medium text-ink">viewer-1</span>,{" "}
              <span className="font-medium text-ink">admin-1</span> (proposes),{" "}
              <span className="font-medium text-ink">admin-2</span> or{" "}
              <span className="font-medium text-ink">approver-1</span> (approves).
            </p>
            <div className="flex items-center gap-3">
              <Button type="submit">Save principal</Button>
              {saved && (
                <span className="inline-flex items-center gap-1 text-sm font-medium text-decision-pass">
                  <CheckCircle2 className="h-4 w-4" aria-hidden />
                  Saved
                </span>
              )}
            </div>
          </form>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Production deployment</CardTitle>
            <CardDescription>Recommended auth posture for bank VPCs</CardDescription>
          </CardHeader>
          <ul className="space-y-3 text-sm text-muted">
            <li>
              Terminate TLS at your ingress; enable mTLS between services where required.
            </li>
            <li>
              Issue OIDC access tokens for the Kavach audience; map IdP groups to Cedar groups
              (the token's groups claim) — do not rely on manual principal entry.
            </li>
            <li>
              Add HMAC v2 signing (timestamp + nonce) on machine-to-machine evaluate calls for
              replay protection.
            </li>
            <li>
              See <span className="font-medium text-ink">docs/INSTALL.md</span> for full environment reference.
            </li>
          </ul>
        </Card>
      </div>
    </section>
  );
}
