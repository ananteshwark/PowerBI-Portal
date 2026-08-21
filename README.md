# Power BI Embedded Portal — App Owns Data with Row-Level Security

A custom web portal that embeds Power BI reports for users who have **no Power BI
licence and no account in your Power BI tenant**. A single service principal
authenticates to Power BI; the backend maps each portal user to an *effective
identity* and requests an embed token with that identity attached, so Power BI
applies the dataset's RLS filters per user.

**Stack:** Next.js 15 + `powerbi-client-react` · Node.js/Express + TypeScript ·
PostgreSQL · JWT auth (Entra ID OIDC pluggable) · Microsoft Entra ID service
principal.

## Documentation

| Document | Contents |
|---|---|
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Data flow, trust model, how RLS is enforced, caching strategy, stack rationale |
| **[docs/AZURE_SETUP.md](docs/AZURE_SETUP.md)** | Step-by-step Azure app registration, tenant settings, workspace access, capacity, RLS role definition, and a failure-symptom table |

## The one-paragraph version

The browser never sees a Power BI credential other than a short-lived embed
token scoped to one report, one dataset and one RLS identity. The service
principal secret, the Entra ID app token, and the RLS mapping logic all stay on
the server. Two checks guard every embed request, in this order: **is this user
granted this report** (403 if not), then **which RLS roles apply to them** — and
if a report is marked `rls_required` and no roles resolve, the request is
refused rather than falling back to a token that would return every row.

## Quick start

```bash
# 1. Dependencies
docker compose up -d postgres

# 2. Backend
cd backend
cp .env.example .env          # fill in AZURE_* from docs/AZURE_SETUP.md
npm install
npm run migrate
npm run seed                  # dev users + a sample report mapping
npm run verify:powerbi        # confirms your Azure setup end to end
npm run dev                   # http://localhost:4000

# 3. Frontend
cd ../frontend
cp .env.example .env.local
npm install
npm run dev                   # http://localhost:3000
```

Seeded logins (development only, password `Portal!Dev123`):

| Email | Portal role | What they see |
|---|---|---|
| `emea@contoso.com` | `sales_manager` | The sample report, filtered to EMEA |
| `apac@contoso.com` | `sales_manager` | The same report, filtered to APAC |
| `admin@contoso.com` | `portal_admin` | The report is listed, but embedding is **refused** — no RLS mapping exists for the admin role, and the portal fails closed rather than showing unfiltered data |

That third row is the fail-closed behaviour working as intended, not a bug. Add
an `rls_role_mappings` row for `portal_admin` if administrators should see the
report, or set `rls_required = false` if the dataset genuinely has no RLS roles.

## Layout

```
backend/
  src/
    config/env.ts             Zod-validated env; the process refuses to boot on bad config
    db/
      pool.ts                 pg pool, query helper, transaction wrapper
      migrations/001_init.sql Full schema (users, roles, reports, RLS mappings, audit)
    auth/
      jwt.ts                  Access-token sign/verify (HS256, algorithm-pinned)
      password.ts             Argon2id + constant-time-ish failure path
      refreshTokens.ts        Rotating refresh tokens with reuse detection
    powerbi/
      aadToken.ts             Service principal client_credentials via MSAL, single-flighted
      client.ts               Power BI REST: getReport, getDatasetRoles, GenerateToken
    services/
      embed.service.ts        ⭐ Authorization → identity resolution → fail-closed → mint
      rlsValidator.service.ts Detects RLS mapping drift (the silent failure mode)
      admin.service.ts        Admin mutations; invalidates caches on every access change
      identity.service.ts     Portal role → Power BI RLS role, per dataset
      reports.service.ts      Report catalogue and the access check
      tokenCache.ts           Embed-token cache, single-flight, identity-keyed
      audit.service.ts        Who saw what, under which identity
    routes/                   auth · reports · embed · admin · health
    middleware/               auth · rate limits · error handler
  scripts/
    migrate.ts  seed.ts  verify-powerbi.ts  validate-rls.ts
  test/                       Cache/single-flight units + refresh-rotation integration

frontend/
  app/
    login/page.tsx            Sign-in
    dashboard/page.tsx        Report catalogue, grouped by category
    reports/[slug]/page.tsx   Single report
  components/
    PowerBIReport.tsx         ⭐ The embed: silent token refresh, loading/error states
    AuthProvider.tsx          Session context, silent restore, route guard
  lib/api.ts                  Fetch wrapper, single-flighted 401 refresh + replay
  styles/globals.css          Responsive layout, light/dark
```

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/login` | — | Email + password → access token (body) + refresh token (HttpOnly cookie) |
| `POST` | `/api/auth/refresh` | cookie | Rotate the refresh token, issue a new access token |
| `POST` | `/api/auth/logout` | cookie | Revoke the token family and drop cached embed tokens |
| `GET` | `/api/auth/me` | Bearer | Current user and roles |
| `GET` | `/api/reports` | Bearer | Report catalogue for this user (metadata only) |
| `GET` | `/api/embed/:slugOrId` | Bearer | **Embed token + URL, RLS applied** |
| `GET` | `/api/health/live` `/ready` | — | Liveness / readiness (readiness checks DB + Entra ID) |

### Admin API

Every route requires an admin role, checked against the database rather than the
JWT. **Every mutation that changes access invalidates the affected users' cached
embed tokens and revokes their sessions** — without that, a demoted user keeps a
working Power BI credential for up to an hour.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/admin/users` | All users with their roles |
| `POST` | `/api/admin/users` | Create a user (optionally with roles) |
| `PATCH` | `/api/admin/users/:id` | Update name, department, effective username, active state |
| `PUT` | `/api/admin/users/:id/roles` | Replace a user's role set |
| `GET` | `/api/admin/roles` | Roles and how many users hold each |
| `GET` | `/api/admin/reports` | All reports, including inactive, with their grants |
| `PUT` | `/api/admin/reports/:id/access` | Replace which roles may see a report |
| `GET` `POST` | `/api/admin/rls-mappings` | List / create portal-role → Power BI-role mappings |
| `DELETE` | `/api/admin/rls-mappings/:id` | Remove a mapping |
| `GET` | `/api/admin/rls-validation` | Run the drift check (same result as the CLI) |

Two self-lockout guards: an admin cannot deactivate their own account, and
cannot remove their own administrator role.

## Security properties

- The service principal secret and the Entra ID app token never leave the backend.
- The browser holds the access token **in memory only** — not `localStorage`,
  which any injected script can read. A page refresh silently re-obtains it from
  the HttpOnly refresh cookie.
- Refresh tokens are stored only as SHA-256 hashes, rotate on every use, and
  replaying a rotated token revokes the entire family (theft detection).
- Report authorization is checked **before** any Power BI call, and re-read from
  the database on every request rather than trusted from the JWT — so a revoked
  role takes effect immediately, not when the token expires.
- `rls_required` reports fail closed: no resolved roles means 403, never an
  unfiltered token.
- Embed-token cache keys include a hash of the effective identity, so a role
  change can never serve a stale, over-permissive token.
- Embed responses are `Cache-Control: no-store, private`.
- Every embed decision is written to `audit_log` with the asserted identity.

## Rate limits and caching

Power BI throttles `GenerateToken`. Two layers keep upstream calls proportional
to real demand:

- **Caching** — a token is reused until 5 minutes before expiry, so one user on
  one report costs one call per ~55 minutes, not one per page load.
- **Single-flight** — concurrent misses on the same key share one upstream call,
  which matters on first paint and under React strict mode's double effects.

The default cache is per-process. Set `REDIS_URL` before running more than one
backend instance, or each instance will maintain its own tokens and
user-invalidation will only reach one of them.

## Detecting RLS drift

Power BI role names are case-sensitive strings asserted at token time, and
nothing validates them when a mapping row is written. Get one wrong and there is
no error anywhere: users see an empty dashboard, or the fail-closed guard starts
denying people who should have access — usually days after someone else
republished the dataset.

```bash
cd backend
npm run validate:rls            # human-readable; exits 1 on any error
npm run validate:rls -- --json  # machine-readable, for alerting
```

Run it on a schedule. It reports five kinds of drift, of which two are errors
you are already suffering from and one is silent data exposure:

| Issue | Severity | What it means |
|---|---|---|
| `mapping_references_unknown_role` | error | Users relying on this mapping are being denied. Names the near-miss when only the casing differs. |
| `rls_required_but_dataset_has_no_roles` | error | Every embed fails closed; nobody can view the report. |
| `rls_not_required_but_dataset_has_roles` | error | **Tokens are minted with no effective identity — every row goes to every user.** |
| `dataset_role_unmapped` | warning | A dataset role nothing maps to; usually an unfinished onboarding. |
| `dataset_unreadable` | warning | Could not reach Power BI. Not drift — unknown. |

## Tests

```bash
cd backend
npm test                                          # unit tests (no DB needed)

createdb portal_test
TEST_DATABASE_URL=postgres://…/portal_test npm run migrate
TEST_DATABASE_URL=postgres://…/portal_test npm test   # + rotation integration tests
```

## Production checklist

- [ ] Service principal uses a **certificate** from Key Vault, not a secret in env
- [ ] Secret/certificate expiry monitored — expiry takes every dashboard down at once
- [ ] `REDIS_URL` set if running more than one backend instance
- [ ] `COOKIE_SECURE=true`, HTTPS everywhere, `CORS_ORIGINS` pinned to real hosts
- [ ] `JWT_SECRET` from a secret manager (`openssl rand -base64 48`), rotated on a schedule
- [ ] `audit_log` shipped to your SIEM and retained per policy
- [ ] Capacity (F2+ / A1+) assigned to the workspace and sized for concurrency
- [ ] `purgeExpiredTokens()` running (it is scheduled in-process; move to a cron if you scale to zero)
