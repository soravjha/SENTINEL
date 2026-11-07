# SENTINEL

Open-source threat intelligence engine. SENTINEL collects indicators (malicious URLs, domains and IPs) from public feeds, normalizes and deduplicates them, stores every sighting with its source and time, and exposes them through a REST API.

**Status: v0.1.0, Phase 1 (foundation and data collection).** Scoring, correlation, the dashboard and AI-assisted analysis come in later phases (see [Roadmap](#roadmap)).

## What works in v0.1.0

- URLhaus collector (abuse.ch "recent URLs" feed)
- Normalization: lowercase hosts, IDNA, default ports and fragments removed, defanged input (`hxxp://evil[.]com`) accepted, private/invalid IPs rejected
- Deduplication: one row per unique indicator, one observation per feed sighting; re-running a collector never creates duplicates
- PostgreSQL schema, FastAPI backend, Docker Compose, unit tests, CI

## Quick start

Requires Docker with Compose.

```bash
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, URLHAUS_AUTH_KEY (free, https://auth.abuse.ch/) and ADMIN_API_KEY
docker compose up --build -d
./scripts/collect.sh urlhaus          # one-off collection
curl localhost:8000/api/v1/stats
```

Interactive API docs: http://localhost:8000/docs. The API listens on localhost only by default, and the database port is not published.

The schema in `database/schema.sql` is loaded the first time the database volume is created. To apply schema changes during development, run `docker compose down -v` (this deletes data).

## API

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness and database check |
| GET | `/api/v1/indicators` | List/search. Params: `type`, `q`, `limit` (max 500), `offset` |
| GET | `/api/v1/indicators/lookup?type=&value=` | Find by value; input is normalized first |
| GET | `/api/v1/indicators/{id}` | Indicator with its most recent observations |
| GET | `/api/v1/sources` | Configured feeds |
| GET | `/api/v1/stats` | Counts by type, observations, sources |
| POST | `/api/v1/collectors/{name}/run` | Run a collector now. Requires `X-API-Key: $ADMIN_API_KEY` |

## Configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy URL (`postgresql+psycopg://...`) |
| `URLHAUS_AUTH_KEY` | abuse.ch Auth-Key, required by the URLhaus collector |
| `ADMIN_API_KEY` | Enables and protects the collector-trigger endpoint |
| `AUTO_CREATE_TABLES` | `true` to create tables from the ORM models (local dev without Docker) |
| `LOG_LEVEL` | Logging level |

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements-dev.txt
pytest
```

Tests use in-memory SQLite and mocked HTTP, so they need no database, key or network.

One concurrency test needs a real PostgreSQL and is skipped unless `TEST_DATABASE_URL` is set. It **drops and recreates all tables**, so point it only at a disposable database whose name contains `test`:

```bash
docker run --rm -d --name sentinel-test-db -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=sentinel_test -p 5433:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql+psycopg://postgres:pw@localhost:5433/sentinel_test pytest
```

Before a release, follow [docs/VERIFY_V0.1.0.md](docs/VERIFY_V0.1.0.md).

Run locally against your own PostgreSQL:

```bash
export DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/sentinel
psql "$DATABASE_URL" -f database/schema.sql
cd backend && uvicorn app.main:app --reload
python -m app.cli collect urlhaus
```

## Responsible use

- Respect each feed's terms, licensing and rate limits. For URLhaus, a few runs per day is plenty.
- Never commit API keys. `.env` is git-ignored.
- Indicators are intelligence, not verdicts. A "derived-from-url" host may be a legitimate shared service; Phase 2 scoring is designed to account for that.

## Roadmap

1. **Foundation and data collection** (this release)
2. Threat analysis: IP/domain reputation, scoring engine, correlation, source reliability, history
3. Dashboard: live overview, search and investigation, trends, reports
4. Advanced: AI-assisted explanations, automated correlation, alerts, integrations

More collectors planned: AbuseIPDB and AlienVault OTX (both need API keys and have their own rate limits and terms).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details.

## License

MIT. See [LICENSE](LICENSE).
