# Odin Public Demo — Deployment

A rate-limited, no-auth instance of Odin so visitors can try a review without installing. Deployed separately from the production backend.

## Endpoints

| Path | Purpose |
|---|---|
| `POST /api/demo/review` | Streaming review. Size-capped (500 LOC), rate-limited (5/hr/IP). |
| `GET /api/demo/limits` | Remaining quota + limits for the caller's IP. Does not consume quota. |

## Deploy on fly.io (free tier)

```bash
flyctl launch --copy-config --config infra/demo/fly.toml --name odin-demo --no-deploy
flyctl redis create --name odin-demo-cache --plan free && flyctl redis attach odin-demo-cache
flyctl secrets set ODIN_LLM_API_KEY=sk-... ODIN_DEMO_ENABLED=true
flyctl deploy
```

The `auto_stop_machines = true` + `min_machines_running = 0` settings scale the instance to zero between visitors — important for staying inside the free tier when the launch blog post hits front-page traffic.

## Deploy on Render.com

Create a new web service pointing at this repo, set the start command to `uvicorn app.main:app --host 0.0.0.0 --port 8000`, and set these environment variables:

- `ODIN_DEMO_ENABLED=true`
- `ODIN_LLM_API_KEY=sk-...`
- `ODIN_REDIS_URL=...` (use Render's managed Redis)
- `ODIN_MAX_FINDINGS=10`
- `ODIN_ENVIRONMENT=production`

Attach a free Render Redis instance — demo rate limiting is best-effort without Redis (see `app/api/demo.py`).

## What the demo deliberately does NOT expose

- GitHub App install flow (`/api/github/*`)
- Review history (`/api/reviews`)
- Feedback endpoints (`/api/feedback*`)
- `/metrics` (Prometheus) and `/mcp`

Everything else — `/api/review`, `/api/settings` — will be accessible if the demo is deployed without a reverse-proxy deny list. Put one in front (Cloudflare rule or nginx `location` block) that only allows `/api/demo/*` and `/api/health`.

## Cost math

- fly.io free tier: 3 shared-cpu-1x VMs (we use 1), 3 GB outbound/month.
- Upstash Redis free tier: 10 000 commands/day (limit is `incr` + `expire` + `ttl` = 3 per review, so ~3 000 reviews/day headroom).
- LLM spend: worst case 5 reviews × 500 LOC per IP per hour. Plug a hard spend cap into the LLM provider dashboard.
