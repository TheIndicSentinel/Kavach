# Local system review — step-by-step commands

Copy and run **one block at a time** in your terminal.  
Repo root: `KavachX/` (or wherever you cloned the repo).

> **Cursor Cloud Agent?** The app runs on the agent VM. After starting, open the **Ports** panel in Cursor, forward port **8080**, and click the forwarded URL — `localhost` on your laptop will not work by itself.

---

## Step 1 — Go to the repo

```bash
cd /workspace
```

*(On your own machine, use your clone path instead, e.g. `cd ~/Kavach`.)*

---

## Step 2 — Start the pilot stack (one command)

```bash
chmod +x scripts/start-local-review.sh && ./scripts/start-local-review.sh
```

Wait until you see `Kavach pilot stack is running`.

---

## Step 3 — Open the console

**If running locally on your machine:**

```bash
xdg-open http://localhost:8080/overview
```

*(Mac: `open http://localhost:8080/overview` · Windows: start `http://localhost:8080/overview` in your browser.)*

**If using Cursor Cloud Agent:**

1. Open **Ports** in Cursor  
2. Forward **8080**  
3. Open the forwarded URL + `/overview`  
   (e.g. `https://xxxx-8080.app.github.dev/overview`)

---

## Step 4 — Configure console Settings

In the browser:

1. Go to **Settings** (`/settings`)
2. Set **Principal** to `admin-1`
3. Set **Approver** to `admin-2` (for dual-control pages)

---

## Step 5 — Quick API health check (terminal)

```bash
curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/health
```

Expected: `{"status":"ok"}`

---

## Step 6 — Walk every console page

Open each URL (replace host if using port forwarding):

| Page | URL |
|---|---|
| Overview | http://localhost:8080/overview |
| Evaluate | http://localhost:8080/evaluate |
| Policies | http://localhost:8080/policies |
| Models | http://localhost:8080/models |
| Batch jobs | http://localhost:8080/batch |
| Fairness | http://localhost:8080/fairness |
| Audit | http://localhost:8080/audit |
| Incidents | http://localhost:8080/incidents |
| Retention | http://localhost:8080/retention |
| Settings | http://localhost:8080/settings |

On **Fairness**, click **Disparity sample** and **Inclusion sample**.

---

## Step 7 — Run automated system review

```bash
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
```

```bash
export PILOT_API_URL=http://localhost:8080
```

```bash
SKIP_VERIFY=1 ./scripts/system-review.sh
```

Expected end: `SYSTEM REVIEW — automated gates passed`

---

## Optional — Dev server with hot reload

Only if you are editing the console UI. **Terminal 2** (leave API running):

```bash
cd /workspace/console && npm run dev
```

Then open http://localhost:5173 (forward port **5173** in Cloud Agent).

---

## Troubleshooting

### Blank page / site not opening

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/
```

- `200` → API is up; use port forwarding (Cloud Agent) or correct URL  
- `000` or connection refused → run Step 2 again

### Check if API is running

```bash
curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/health
```

### View API logs

```bash
tmux -f /exec-daemon/tmux.portal.conf capture-pane -t kavach-pilot-api:0.0 -p | tail -30
```

### Restart from scratch

```bash
tmux -f /exec-daemon/tmux.portal.conf kill-session -t kavach-pilot-api 2>/dev/null || true
./scripts/start-local-review.sh
```

### Postgres not running

```bash
sudo pg_ctlcluster 16 main start
```

Or with Docker:

```bash
cp deploy/pilot.env.example deploy/.env
docker compose -f deploy/docker-compose.pilot.yml up -d postgres
```

---

## Full checklist

See [SYSTEM_REVIEW_CHECKPOINT.md](SYSTEM_REVIEW_CHECKPOINT.md) for the complete sign-off checklist.
