# Azure & Power BI Prerequisites

Do these **in order**. Steps 1–6 are one-time tenant setup; steps 7–9 are per-dataset.

---

## 1. Register the application in Microsoft Entra ID

Azure Portal → **Microsoft Entra ID** → **App registrations** → **New registration**

| Field | Value |
|---|---|
| Name | `powerbi-portal-service` |
| Supported account types | **Accounts in this organizational directory only (Single tenant)** |
| Redirect URI | *leave empty* — client-credentials flow needs none |

Record from the **Overview** blade:
- **Application (client) ID** → `AZURE_CLIENT_ID`
- **Directory (tenant) ID** → `AZURE_TENANT_ID`

## 2. Create a client secret (or, better, a certificate)

**Certificates & secrets** → **New client secret** → expiry 6–12 months (24 months max; Azure policy may cap it lower).

Copy the **Value** immediately — it is shown exactly once → `AZURE_CLIENT_SECRET`.

> **Production:** prefer a certificate over a secret, and store it in **Azure Key Vault**, read at startup via managed identity. Secrets in env vars are acceptable for dev; certificates + Key Vault are the target state. Whichever you use, set a calendar reminder ~30 days before expiry — an expired secret takes every dashboard down at once, and the failure looks like a generic 401.

## 3. API permissions — the counter-intuitive part

For a **service principal** using App Owns Data, **do not add Power BI Service delegated permissions**. The service principal's access is granted inside Power BI itself (steps 4–6), not through Graph consent. Adding `Report.Read.All` etc. as *delegated* permissions does nothing for client-credentials and is a common source of confusion.

Leave API permissions empty. If your tenant's app-registration policy forbids zero-permission apps, add `User.Read` (delegated) — it is unused but harmless.

> If you plan to use the **admin** APIs (`/v1.0/myorg/admin/...`) for tenant-wide inventory, that *does* require **Application** permissions (`Tenant.Read.All`) plus admin consent. The embedding flow in this repo does not need them.

## 4. Create a security group for the service principal

Entra ID → **Groups** → **New group**
- Type: **Security**
- Name: `PowerBI-Embedding-ServicePrincipals`
- Members: add the **service principal** created in step 1 (search by the app name; you may need to switch the picker to include applications).

A group is required because the tenant setting in step 5 accepts groups, and you want to onboard future apps without re-touching tenant settings.

## 5. Enable service principal access — Power BI tenant settings

**Power BI Service** → gear icon → **Admin portal** → **Tenant settings** → *Developer settings*

Enable:

| Setting | Value |
|---|---|
| **Allow service principals to use Power BI APIs** | **Enabled**, applied to the group `PowerBI-Embedding-ServicePrincipals` |
| **Embed content in apps** | **Enabled** (whole org, or the same group) |
| **Allow service principals to use read-only Power BI admin APIs** | Only if you use admin APIs |

Requires the **Fabric Administrator** (formerly Power BI Administrator) role. Changes can take up to 15 minutes to propagate — if your first `GenerateToken` returns `401`/`PowerBINotAuthorizedException`, wait and retry before debugging code.

## 6. Grant the service principal access to the workspace

Power BI Service → your workspace → **Manage access** → **Add people or groups**

- Add the **service principal** (or the security group from step 4)
- Role: **Member** (Contributor is enough for read-only embedding; Member is required if you also want to rebind datasets or manage content)
- **Viewer is not sufficient** — `GenerateToken` fails with a permission error.

The workspace must be a **new-experience workspace** (`groups/{groupId}` — classic "My Workspace" cannot be used with service principals at all).

Record the workspace GUID from the URL: `app.powerbi.com/groups/**<workspace-id>**/list` → `POWERBI_WORKSPACE_ID`.

## 7. Capacity

Embed tokens for external users require dedicated capacity:

| SKU | Use |
|---|---|
| **F2+** (Microsoft Fabric) | Current recommendation. Pausable, billed per-hour. |
| **A1–A6** (Power BI Embedded, Azure) | Legacy but still valid; pausable, ideal for dev. |
| **P1+** (Premium) | Enterprise, annual. |
| **PPU** | **Does not work** for App Owns Data external embedding. |

Assign the workspace to the capacity: workspace → **Settings** → **Premium/Capacity** → select the capacity.

> **Dev shortcut:** without a capacity you can still embed, but you burn from a limited free monthly embed-token quota tied to a Power BI Pro-licensed workspace, and it is not licensed for production. Start an A1 for development and **pause it when not in use** — it bills by the hour.

## 8. Define RLS roles in the dataset (Power BI Desktop)

**Modeling** → **Manage roles** → **Create**.

**Static role** — one filter for everyone in the role:
```dax
// Role name: "EMEA_Sales"
[Region] = "EMEA"
```

**Dynamic role** — filters by the identity we pass at token time (this is what you usually want):
```dax
// Role name: "RegionalManager", table: Sales
[Region] = LOOKUPVALUE(
    UserRegion[Region],
    UserRegion[Email], USERPRINCIPALNAME()
)
```
`USERPRINCIPALNAME()` returns exactly the `username` string we send in `identities[0].username`. It does **not** have to be a real Entra account — with a service principal it is an arbitrary string you control. That is the whole mechanism: our backend asserts the identity, Power BI trusts it.

You need a mapping table (`UserRegion` above) in the model, loaded from your source system, keyed on the same value the portal sends. Keep it in sync with `user_rls_attributes` in Postgres — a user present in Postgres but missing from the mapping table sees **zero rows**, which reports as "the dashboard is empty" rather than an error.

Test before publishing: **Modeling** → **View as** → tick the role, enter a test username.

## 9. Publish and record IDs

Publish the `.pbix` to the workspace, then collect for each report:

- **Report ID** — `app.powerbi.com/groups/{ws}/reports/**<report-id>**/ReportSection`
- **Dataset ID** — workspace → dataset → **Settings**, or `GET /v1.0/myorg/groups/{ws}/reports/{reportId}` (this API returns `datasetId`, which is why our backend fetches it rather than requiring you to store it).

Then, in the dataset's **Settings → Security**, confirm the RLS roles you defined appear. If the role list is empty, RLS did not publish — re-check step 8.

Insert these into the `reports` table (see `backend/src/db/migrations/001_init.sql` and `backend/scripts/seed.ts`).

---

## 10. Verification checklist

Run `npm run verify:powerbi` in `backend/` — it exercises the whole chain and tells you which step failed:

```
✔ Entra ID token acquired            (steps 1–2 correct)
✔ Workspace visible to SP            (steps 5–6 correct)
✔ Report metadata readable           (step 9 correct)
✔ Dataset RLS roles present          (step 8 correct)
✔ Embed token generated with RLS     (everything correct)
```

## 11. Common failures

| Symptom | Cause |
|---|---|
| `401 PowerBINotAuthorizedException` on any call | Tenant setting (step 5) off, or not yet propagated, or SP not in the group |
| `401` only on `GenerateToken`, other calls fine | SP has **Viewer** on the workspace — needs **Member**/**Contributor** (step 6) |
| `400 InvalidRequest: Creating embed token for accessing dataset requires effective identity` | Dataset has RLS roles but you sent no `identities` |
| `400 ... effective identity is not allowed` | Dataset has **no** RLS roles but you sent `identities` — remove them, or add roles to the dataset |
| Report loads but shows **all** rows | `identities` omitted, or the role name string does not match the dataset role exactly (it is case-sensitive) |
| Report loads but shows **no** rows | `username` has no match in the model's mapping table (step 8) |
| `TokenExpired` after ~1 hour | Front-end refresh not wired — see `PowerBIReport.tsx` |
| Everything works for you, fails for colleagues | You are signed into Power BI in the same browser and are seeing your *user* permissions, not the SP's. Test in a private window. |
