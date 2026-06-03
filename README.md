# FastAPI Authentication and Authorization Service

Production-grade authentication microservice built with FastAPI, SQLAlchemy 2.0, PostgreSQL, Redis, Alembic, JWT access tokens, refresh token rotation, device sessions, RBAC, audit logging, and Docker.

## Architecture

The service uses clean backend layering:

- `app/api`: HTTP route handlers and OpenAPI-facing contracts.
- `app/schemas`: Pydantic request and response models.
- `app/services`: business workflows such as login, refresh rotation, replay response, logout, and session revocation.
- `app/repositories`: database access abstractions.
- `app/models`: SQLAlchemy ORM models.
- `app/dependencies`: FastAPI dependency injection for auth, RBAC, DB-backed services, and Redis.
- `app/core`: configuration, database, Redis, JWT, cookies, and password hashing.
- `app/middleware`: Redis-backed rate limiting.

Authorization is intentionally stateless for normal protected-route access. The JWT carries `sub`, `jti`, `role`, and `permissions`; protected routes validate signature, expiry, token type, and Redis blacklist status without querying PostgreSQL.

## Security Model

- Access tokens are JWTs with 15 minute expiry.
- Refresh tokens are cryptographically random opaque tokens with 30 day expiry.
- Refresh tokens are stored only as SHA-256 hashes in PostgreSQL.
- Refresh token rotation revokes the previous token and stores the new token hash.
- Rotated tokens remain as revoked tombstones so replay can be detected.
- Refresh token replay marks the account compromised, revokes all sessions, and revokes all refresh tokens.
- Logout and logout-all blacklist the current access token `jti` in Redis with a TTL equal to the remaining JWT lifetime.
- Cookies are HttpOnly, Secure, and SameSite configurable.
- Passwords are hashed with Argon2 via `pwdlib`.
- Rate limiting uses Redis counters per IP and path.
- Audit logs capture login, failed login, refresh, logout, logout all, replay, and session revocation events.

## API

OpenAPI is available at:

- `GET /docs`
- `GET /redoc`
- `GET /openapi.json`

Primary endpoints:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `GET /api/v1/auth/sessions`
- `DELETE /api/v1/auth/sessions/{session_id}`
- `GET /api/v1/auth/admin/ping`

RBAC is reusable:

```python
@router.get("/admin-only")
async def admin_only(_: CurrentUser = Depends(require_role("admin"))):
    return {"status": "ok"}
```

Permission checks are also reusable through `require_permission("sessions:read")`.

## Data Model

- `users`: identity, role, active/compromised flags, password hash.
- `sessions`: device-based sessions with device ID, IP, user agent, timestamps, and revocation.
- `refresh_tokens`: hashed refresh tokens, device metadata, expiry, revocation, replacement, and replay markers.
- `audit_logs`: user, IP address, action, and timestamp.

## Local Development

Create `.env`:

```bash
cp .env.example .env
```

Run with Docker:

```bash
docker compose up --build
```

Run migrations manually:

```bash
alembic upgrade head
```

Run the API locally without Docker:

```bash
pip install -e ".[test]"
uvicorn app.main:app --reload
```

## Testing

```bash
pytest
```

The tests use an in-memory SQLite database and a fake Redis implementation for endpoint-level coverage of login, refresh rotation, replay detection, logout blacklisting, and RBAC.

## Production Notes

- Replace `JWT_SECRET_KEY` with a long high-entropy secret from a secret manager.
- Keep `COOKIE_SECURE=true` in production.
- Put the service behind TLS and a trusted reverse proxy.
- Configure `x-forwarded-for` handling only from trusted infrastructure.
- Consider adding per-user and per-email rate limits for login in addition to the existing IP/path limiter.
- Keep access tokens short-lived and avoid database lookups during normal authorization.
- For breach response, `is_compromised=true` intentionally blocks future login until an administrative recovery flow clears the flag.

