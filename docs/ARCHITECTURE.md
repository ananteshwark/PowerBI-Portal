# Architecture & Data Flow

## 1. Chosen stack (and why)

| Layer | Choice | Rationale |
|---|---|---|
| Frontend | **Next.js 16 (App Router, React 19)** + `powerbi-client-react` | The official React wrapper for `powerbi-client` is maintained by Microsoft. Next.js gives us a server boundary for the login/session cookie without shipping a second server. The embed component must be client-side (`"use client"`) because the Power BI JS SDK manipulates a DOM iframe. |
| Backend | **Node.js + Express + TypeScript** | Same language as the frontend (one toolchain, shared types). `@azure/msal-node` is a first-party AAD client. .NET Core is equally valid and has the richest first-party samples; Python works but `msal` + raw REST is more manual. See "Alternatives" below. |
| AuthN | **Local JWT** and/or **Entra ID OIDC**, selected by `AUTH_PROVIDER` | The requirement is that portal users need *no* Power BI licence, so portal identity is fully decoupled from the Power BI tenant. Both providers converge on the same session (short access token + rotating refresh cookie) and neither touches the embed pipeline, which keys off `effective_username` rather than the authentication method. Entra sign-in uses a **separate app registration** from the Power BI service principal. |
| Database | **PostgreSQL** | The data is relational by nature (users ↔ roles ↔ reports ↔ RLS role mappings — three join tables). Constraints and `ON DELETE CASCADE` do real work here; a document store would push that integrity into application code. |

### Alternatives, briefly
- **.NET Core backend** — best choice if your shop is already Microsoft-centric: `Microsoft.PowerBI.Api` SDK removes the hand-rolled REST calls in `src/powerbi/`. Everything else in this design is unchanged.
- **Python/FastAPI** — fine, but you write the Power BI REST calls by hand exactly as we do here, so there is no advantage unless the rest of your platform is Python.
- **MongoDB** — workable, but you would embed `roleIds`/`reportIds` arrays in the user document and lose referential integrity on role deletion.

## 2. The "App Owns Data" trust model

The single most important idea: **Power BI never sees your end users.**

```
Portal identity (Postgres / Entra)          Power BI identity (one Service Principal)
        │                                                    │
        │  users have NO Power BI licence                    │  has Workspace "Member"/"Contributor"
        │  users have NO Power BI account                    │  is the ONLY principal that ever authenticates
        └────────────── the backend is the bridge ───────────┘
```

The backend is the only component that holds credentials capable of talking to Power BI. It maps a *portal* user to an *effective identity* (a username string + a list of RLS role names) which it hands to Power BI at token-generation time. Power BI applies the dataset's RLS filters as if that identity were the viewer, then mints a short-lived **embed token** scoped to exactly one report, one dataset and one identity.

**The security boundary is the embed token.** It is the only Power BI credential the browser ever receives; it is scoped, RLS-bound, and expires in ≤60 minutes.

## 3. Request flow

### 3.1 Login
```
Browser                     Backend                     Postgres
   │  POST /api/auth/login      │                           │
   │  {email, password}         │                           │
   │──────────────────────────► │  SELECT user, argon2.verify│
   │                            │──────────────────────────►│
   │                            │  load roles + rls attrs   │
   │  200 {accessToken (15m)}   │◄──────────────────────────│
   │  Set-Cookie: rt=… HttpOnly │                           │
   │◄────────────────────────── │                           │
```
- **Access token**: 15 min JWT, held in browser memory only (never `localStorage` — that is XSS-exfiltratable).
- **Refresh token**: opaque 256-bit random value, `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`. Only a SHA-256 hash is stored server-side. Rotated on every use; reuse of a rotated token revokes the whole family (theft detection).

### 3.2 Listing reports the user may see
```
GET /api/reports  (Bearer access token)
      │
      └─► SQL: reports the user can reach via (a) any of their roles, or (b) a direct grant
          Returns metadata ONLY — no embed URL, no token, no workspace secrets.
```

### 3.3 Embedding a report — the critical path
```
Browser            Backend                  Entra ID              Power BI REST API
   │ GET /api/embed/:reportId │                    │                       │
   │─────────────────────────►│                    │                       │
   │                          │ (1) AUTHORIZE: is this user granted this report?
   │                          │     └─ 403 if not. This check happens BEFORE any Power BI call.
   │                          │                    │                       │
   │                          │ (2) RESOLVE IDENTITY: effective username +
   │                          │     RLS role names from rls_role_mappings
   │                          │                    │                       │
   │                          │ (3) cache hit? ────┴─ yes ─► return cached token, done
   │                          │                                            │
   │                          │ (4) client_credentials grant               │
   │                          │───────────────────►│                       │
   │                          │  AAD token (~60m, cached in MSAL)          │
   │                          │◄───────────────────│                       │
   │                          │                                            │
   │                          │ (5) GET /groups/{ws}/reports/{id}          │
   │                          │───────────────────────────────────────────►│
   │                          │  embedUrl + datasetId                      │
   │                          │◄───────────────────────────────────────────│
   │                          │                                            │
   │                          │ (6) POST /GenerateToken                    │
   │                          │     { reports, datasets, targetWorkspaces, │
   │                          │       identities: [{username, roles,       │
   │                          │                     datasets}] }           │
   │                          │───────────────────────────────────────────►│
   │                          │  { token, expiration }   ◄── RLS is BAKED IN HERE
   │                          │◄───────────────────────────────────────────│
   │ 200 {embedToken,         │                                            │
   │      embedUrl, reportId, │ (7) cache under (userId, reportId, identity-hash)
   │      expiresAt}          │ (8) write audit_log row
   │◄─────────────────────────│                                            │
   │                                                                       │
   │ (9) powerbi.embed() ─── iframe loads app.powerbi.com ─────────────────►│
   │     Browser talks to Power BI directly from here on, using the embed token.
```

**Step 1 before step 6 is non-negotiable.** RLS filters *rows*; the authorization check gates *reports*. RLS alone would let any authenticated user open any report ID in the workspace and see whatever rows their identity permits — usually not nothing.

### 3.4 Token expiry, in the browser
The embed token lives ≤60 min. The `PowerBIReport` component schedules a silent refresh at `expiresAt − 5 min`, calls `GET /api/embed/:id` again, and pushes the new token into the live embed with `report.setAccessToken(newToken)`. **The iframe is never re-created**, so the user keeps their filters, cross-highlights and current page. If the refresh fails, we retry with backoff and only then surface an error.

## 4. How RLS is actually enforced

Three pieces must line up, or you get either an error or (worse) unfiltered data:

1. **In the dataset (Power BI Desktop)** — a *role* with a DAX filter, e.g. role `RegionalManager` on table `Sales`:
   ```dax
   [Region] = LOOKUPVALUE(UserRegion[Region], UserRegion[Email], USERPRINCIPALNAME())
   ```
2. **In our database** — `rls_role_mappings` maps a portal role (`sales_manager`) to the exact Power BI role name (`RegionalManager`) for a given dataset. Portal role names and Power BI role names drift; an explicit mapping table is the fix. `user_rls_attributes` carries extra values (region, department) for datasets whose DAX reads a username we synthesise.
3. **In the token request** — `identities: [{ username, roles, datasets }]`. `username` is what `USERPRINCIPALNAME()` returns inside the DAX above; `roles` selects which role's filters apply; `datasets` scopes the identity.

**Fail-closed rule** implemented in `src/services/embed.service.ts`: if a report is flagged `rls_required = true` and identity resolution produces **zero** roles, we return `403` rather than generating a token without `identities`. A token without identities on an RLS dataset returns *all* rows — silent data leakage. This is the single most common Power BI Embedded security bug.

## 5. Caching & rate limits

Power BI throttles `GenerateToken` (≈ 200 requests/hour/user-report pair territory; treat it as scarce). Two caches:

| Cache | Key | TTL | Where |
|---|---|---|---|
| AAD app token | service principal | ~60 min, MSAL-managed | `@azure/msal-node` in-memory, plus our own skew guard |
| Embed token | `userId : reportId : sha256(identity)` | `expiration − 5 min` | `src/services/tokenCache.ts` |

Both use **single-flight**: N concurrent requests for the same key trigger exactly one upstream call, and all N await the same promise. Without this, a dashboard with 6 tiles produces 6 identical `GenerateToken` calls on first paint.

The identity hash is part of the embed-token cache key deliberately: if a user's roles change, the key changes and the old token is never served. Cached tokens are also dropped on logout.

> **Multi-instance note:** the default cache is per-process. Behind more than one backend instance, set `REDIS_URL` — `tokenCache.ts` is written against a small `CacheStore` interface with both in-memory and Redis implementations, so this is a config change, not a code change.

## 6. What never leaves the backend

- `AZURE_CLIENT_SECRET` / certificate
- The AAD access token (it is a tenant-wide Power BI credential — leaking it is far worse than leaking an embed token)
- Any master-user credentials (we don't use any)
- The JWT signing secret

The browser receives only: the embed token, the embed URL, the report ID, and an expiry timestamp.
