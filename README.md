# GhostLeaks Enterprise

Credential-breach monitoring SaaS. See `docs/ARCHITECTURE.md` for how it
works and `README_CHANGES.md` for what changed in the latest rebuild.

## Deploy with Docker (recommended)

This is the fastest way to run GhostLeaks Enterprise for real use. It
starts the app **and** a Postgres database, wires them together, and
persists data across restarts — no separate database setup needed.

### 1. Configure your environment

```bash
cp .env.example .env
```

Open `.env` and fill in:

- `SECRET_KEY`, `ALERT_SECRET` — any long random strings
- `POSTGRES_PASSWORD` — a strong password for the bundled database
- `BREVO_API_KEY`, `MAIL_USERNAME` — for sending emails
- `RAPIDAPI_KEY` — for breach lookups
- `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` — for payments
- `APP_PUBLIC_URL` — the URL customers will actually reach this at

Leave `DATABASE_URL` commented out — docker-compose builds it
automatically from the `POSTGRES_*` values so the app talks to the
bundled database container. Only uncomment and set it yourself if you
want to point at an external database (e.g. Supabase) instead.

### 2. Start everything

```bash
docker compose up -d
```

That's it. This single command:

- Builds the app image
- Starts Postgres and waits for it to be ready (healthcheck-gated)
- Starts the app, which waits for the database before booting, then
  creates all tables automatically on first run
- Persists both the database and app data in named Docker volumes, so
  `docker compose down` / `up` again does **not** lose data
- Restarts either container automatically if it crashes or the host
  reboots (`restart: unless-stopped`)

The app is now running at `http://localhost:5000` (or whatever
`APP_PORT` you set in `.env`).

### Useful commands

```bash
docker compose logs -f web      # tail app logs
docker compose logs -f db       # tail database logs
docker compose down             # stop everything (keeps data)
docker compose down -v          # stop and WIPE all data — careful
docker compose up -d --build    # rebuild after pulling code changes
```

### Notes

- The app runs behind Gunicorn (see `gunicorn_config.py`), not Flask's
  dev server — this is the same production entrypoint whether you use
  Docker or deploy directly to a host like Render.
- Set `GUNICORN_WORKERS` / `GUNICORN_THREADS` / `GUNICORN_TIMEOUT` in
  `.env` if you need to tune for your server's CPU/RAM; sane defaults
  are used otherwise.
- Put GhostLeaks behind a reverse proxy (nginx, Caddy, Traefik, or your
  cloud provider's load balancer) for TLS/HTTPS in front of port 5000 —
  this compose setup does not terminate TLS itself.

## Deploy without Docker

Still supported — see `docs/DEPLOYMENT.md` for deploying directly on a
host (e.g. Render) with `pip install -r requirements.txt` and
`gunicorn -c gunicorn_config.py app:app`.
