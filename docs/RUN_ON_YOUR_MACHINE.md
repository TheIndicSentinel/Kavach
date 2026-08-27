# See the complete flow on your machine

Two ways to experience Kavach end-to-end: **on your laptop** (recommended) or **via this Cloud Agent** (preview link).

---

## What “complete flow” means

```mermaid
flowchart LR
  A[Partner LOS export] --> B[Batch worker]
  B --> C[Postgres evidence]
  D[Live scoring API] --> C
  C --> E[Governance console]
  E --> F[Batch jobs / Audit / Fairness]
```

1. **Overnight batch** — partner NDJSON file ingested  
2. **Sync scoring** — real-time evaluate API per application  
3. **Governance** — policies, models, audit, retention  
4. **Fairness** — model risk report from batch results  

---

## Option A — On your laptop (best experience)

`localhost` works normally. No port forwarding issues.

### What you need

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running  
- Git  

### Steps

1. **Clone the repo**
   ```bash
   git clone https://github.com/TheIndicSentinel/Kavach.git
   cd Kavach
   ```

2. **Start everything (Postgres + API + console)**
   ```bash
   cp deploy/pilot.env.example deploy/.env
   docker compose -f deploy/docker-compose.pilot.yml up --build
   ```
   Wait until you see `kavach-api listening` in the logs (first run takes a few minutes to build).

3. **Open the console in your browser**
   ```
   http://localhost:8080/overview
   ```

4. **Configure access** (one time)  
   - Go to **Settings**  
   - Principal: `admin-1`  
   - Approver: `admin-2`  
   - Save  

5. **Run the automated real-world simulation** (second terminal)
   ```bash
   cd Kavach
   export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
   export PILOT_API_URL=http://localhost:8080
   ./scripts/simulate-partner-day.sh
   ```
   Wait for: `SIMULATION: 13/13 steps passed`

6. **See the results in the console** (refresh the browser)

   | Click this | What you'll see |
   |---|---|
   | **Batch jobs** | New job from the simulation |
   | **Audit** | Enforce promotion entries |
   | **Evaluate** | Try **Reset sample** → **Run evaluate** |
   | **Fairness** | **Disparity sample** button |
   | **Policies** | Finance pack rules |
   | **Models** | `credit-underwriting-v1` in shadow mode |

7. **Stop when done**  
   `Ctrl+C` in the docker terminal, or:
   ```bash
   docker compose -f deploy/docker-compose.pilot.yml down
   ```

---

## Option B — Cloud Agent (this session)

Port forwarding (`+` on 8080) often shows **Cancelled** in Cloud Agent. Use a **preview link** instead.

Ask the agent: **“refresh my preview link”** — you'll get a URL like:

```
https://xxxx.trycloudflare.com/overview
```

Click it in your normal browser (Chrome/Safari). Same console, no `localhost` needed.

Then ask: **“run the simulation”** — the agent runs `simulate-partner-day.sh` and you refresh **Batch jobs** / **Audit** in the browser.

---

## Option C — No Docker (developers)

Requires Rust, Node, and Postgres installed locally.

```bash
git clone https://github.com/TheIndicSentinel/Kavach.git
cd Kavach
./scripts/start-local-review.sh          # terminal 1 — starts API
./scripts/simulate-partner-day.sh        # terminal 2 — runs full flow
```

Open: `http://localhost:8080/overview`

See [INSTALL.md](INSTALL.md) for Postgres setup details.

---

## Quick visual checklist

After simulation passes, confirm in the browser:

- [ ] **Overview** — API health green  
- [ ] **Batch jobs** — at least one completed job  
- [ ] **Evaluate** — decision badges after Run evaluate  
- [ ] **Fairness** — disparity table after sample load  
- [ ] **Audit** — recent admin actions  
- [ ] **Policies** — `finance-v0` rules listed  

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `localhost` blank on Cloud Agent | Use preview link (Option B), not localhost |
| Port `+` says Cancelled | Normal in Cloud Agent — use preview link |
| Docker build slow | First build ~5–10 min; later starts are fast |
| Evaluate unauthorized | Settings → Principal `admin-1` → Save |
| Simulation fails | Ensure API is up (`docker compose` or `start-local-review.sh`) |

---

## Related docs

- [SIMULATE_PARTNER_DAY.md](SIMULATE_PARTNER_DAY.md) — what the simulation tests  
- [SYSTEM_REVIEW_CHECKPOINT.md](SYSTEM_REVIEW_CHECKPOINT.md) — full sign-off gate  
- [PARTNER_PILOT.md](PARTNER_PILOT.md) — partner pilot playbook  
