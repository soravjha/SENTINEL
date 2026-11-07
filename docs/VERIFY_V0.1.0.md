# Verifying v0.1.0 before the freeze

Work through this in order. Stop and fix at the first failure. Nothing here changes code.

## 1. Unit tests (SQLite, no network)

```bash
pip install -r backend/requirements-dev.txt
pytest -q
```
Expect: all pass, the four PostgreSQL tests reported as skipped.

## 2. PostgreSQL verification tests

These check what SQLite cannot: lock exclusion, lock release after rollback, rollback of a failed batch, idempotent re-ingestion with timezone-aware timestamps, and parallel ingestion.

```bash
docker run --rm -d --name sentinel-test-db -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=sentinel_test -p 5433:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql+psycopg://postgres:pw@localhost:5433/sentinel_test pytest -q tests/test_concurrency_postgres.py
docker stop sentinel-test-db
```
Expect: 4 passed, none skipped. Run it three times; concurrency bugs are intermittent.

## 3. Full stack smoke test

```bash
cp .env.example .env     # set POSTGRES_PASSWORD, URLHAUS_AUTH_KEY, ADMIN_API_KEY
docker compose up --build -d
curl -s localhost:8000/health
```
Expect `{"status":"ok",...}`. Check `docker compose ps`: the database shows no host port, the API shows `127.0.0.1:8000`.

## 4. Collector with your own URLhaus key

```bash
./scripts/collect.sh urlhaus
curl -s localhost:8000/api/v1/stats
```
Expect a JSON result with `new_indicators` > 0 and `rejected` small. A large `rejected` count means the normalizer is dropping real data: inspect before freezing.

## 5. Repeated collection

Run the collector again. Expect `duplicate_observations` > 0 and no new rows for records that were already stored (genuinely new feed entries may add some). Totals in `/api/v1/stats` must never fall.

## 6. Persistence

```bash
docker compose down          # without -v
docker compose up -d
curl -s localhost:8000/api/v1/stats
```
Expect the same totals as before the restart.

## 7. Failure paths

- Wrong `URLHAUS_AUTH_KEY`: collector fails with a clear error and the key does not appear in logs or output.
- `POST /api/v1/collectors/urlhaus/run` without `X-API-Key`: 401. With `ADMIN_API_KEY` empty: 503.
- Spot-check lookups: `GET /api/v1/indicators/lookup?type=url&value=hxxp://...` returns the stored indicator.

## 8. Repository hygiene

- `git status` shows no `.env`; `git grep -i "auth-key\|password"` finds only placeholders.
- CI is green on a clean clone.

## 9. Freeze

Tag `v0.1.0`. Record anything you chose to accept in the release notes under "Known limitations": no user authentication, manual collection only, one collector, global ingestion lock.
