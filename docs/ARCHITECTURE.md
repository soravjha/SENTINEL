# SENTINEL architecture (v0.1.0)

## Decision: modular monolith

One deployable backend with clear internal module boundaries. Microservices would add networking, deployment and observability overhead that Phase 1 does not need. The module boundaries below are the seams to split along later if scale ever demands it.

## Flow

```
Public feed --> Collector --> RawObservation --> Normalizer --> Ingestion --> PostgreSQL --> REST API
 (URLhaus)     (fetch+parse)  (unvalidated)     (canonical)   (dedup+store)  (indicators,
                                                                              observations)
```

## Modules (`backend/app/`)

| Module | Responsibility |
| --- | --- |
| `collectors/` | Fetch and parse one feed each. Return `RawObservation`s. Never touch the database. |
| `services/normalizer.py` | Canonicalize IPs, domains, URLs and hashes. Standard library only. |
| `services/ingestion.py` | Normalize, deduplicate and persist. Owns transaction handling. |
| `services/runner.py` | Builds collectors and wires them to ingestion (used by CLI and API). |
| `models/` | SQLAlchemy models for the Phase 1 tables. |
| `api/` | FastAPI routes, response schemas, admin-key dependency. |
| `analyzers/`, `scoring/` | Empty placeholders for Phase 2. |

## Data model

Phase 1 uses three tables; `database/schema.sql` also defines `threat_scores`, `analysis_results`, `alerts` and `users` so later relationships are fixed early.

- `threat_sources`: one row per feed, with a `reliability` placeholder (0..1).
- `indicators`: unique per `(indicator_type, sha256(normalized value))`. Hashing keeps the unique index small for very long URLs. Holds `first_seen`, `last_seen`, `observation_count`.
- `observations`: one row per feed sighting, unique per `(indicator, source, source_ref)`. `source_ref` is the feed's own id, which is what makes re-ingestion idempotent. Feeds without ids fall back to one observation per day.

Keeping sightings separate from indicators is what enables source reliability, correlation across feeds and historical tracking in Phase 2 without schema changes.

## Normalization rules

- Defanged input is refanged (`hxxp`, `[.]`, `[:]`).
- Domains: lowercase, trailing dot removed, IDNA (punycode) encoded, label/length checks, IP literals rejected.
- IPs: canonical text form, IPv4-mapped IPv6 unwrapped, non-public ranges rejected (private, loopback, link-local, reserved).
- URLs: http/https/ftp only; lowercase scheme and host; default port, fragment and userinfo dropped; empty path becomes `/`. Path and query are kept as-is, since they are case-sensitive and meaningful.

## Adding a collector

1. Subclass `BaseCollector` in `collectors/`, set `source_name`, `feed_url`, implement `collect()`.
2. Register it in `services/runner.py` (`SUPPORTED_COLLECTORS`, `build_collector`).
3. Add tests with a mocked HTTP transport (see `tests/test_urlhaus_collector.py`).

## Security notes

- Secrets come from environment variables only.
- The collector-trigger endpoint is disabled unless `ADMIN_API_KEY` is set and uses a constant-time key comparison. There is no user authentication yet; read endpoints are open, which is why Compose binds the API to localhost. Put real auth in front before exposing it.
- Feed data is untrusted input: it is validated by the normalizer, stored with parameterized queries, and never executed or fetched.

## Known limitations (v0.1.0)

- Only the URLhaus collector exists; AbuseIPDB and OTX are next.
- Collection is triggered manually (CLI or API); there is no scheduler yet. Use cron or a CI schedule in the meantime.
- Ingestion is serialized with a global PostgreSQL advisory lock, so concurrent collectors queue rather than race. This is simple and deadlock-free; revisit with per-source locking or `INSERT ... ON CONFLICT` only if ingestion volume ever makes queueing a bottleneck.
- No schema migration tool yet (Alembic is a good next step once the schema starts changing).
