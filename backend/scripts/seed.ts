/**
 * Development seed: two roles, three users, one report, and the RLS mapping
 * that ties a portal role to a Power BI role name.
 *
 * Idempotent — safe to re-run. Refuses to run against NODE_ENV=production,
 * because it creates accounts with known passwords.
 */
import { withTransaction, closePool } from '../src/db/pool.js';
import { hashPassword } from '../src/auth/password.js';
import { config } from '../src/config/env.js';

if (config.isProduction) {
  console.error('Refusing to seed a production database.');
  process.exit(1);
}

const WORKSPACE_ID = config.powerbi.defaultWorkspaceId ?? '00000000-0000-0000-0000-000000000000';
// Replace with the real IDs from docs/AZURE_SETUP.md step 9.
const REPORT_ID = process.env.SEED_REPORT_ID ?? '11111111-1111-1111-1111-111111111111';
const DATASET_ID = process.env.SEED_DATASET_ID ?? '22222222-2222-2222-2222-222222222222';

async function seed(): Promise<void> {
  const password = await hashPassword('Portal!Dev123');

  await withTransaction(async (client) => {
    // ---- roles ----------------------------------------------------------
    await client.query(
      `INSERT INTO roles (name, description, is_admin) VALUES
         ('portal_admin',  'Portal administrator',        TRUE),
         ('sales_manager', 'Regional sales manager',      FALSE),
         ('sales_rep',     'Individual sales contributor', FALSE)
       ON CONFLICT (name) DO NOTHING`,
    );

    // ---- users ----------------------------------------------------------
    // effective_username defaults to email via trigger — that is the string
    // USERPRINCIPALNAME() returns inside the dataset's DAX.
    await client.query(
      `INSERT INTO users (email, password_hash, display_name, department) VALUES
         ('admin@contoso.com', $1, 'Ada Admin',    'IT'),
         ('emea@contoso.com',  $1, 'Erik Manager', 'Sales'),
         ('apac@contoso.com',  $1, 'Aiko Manager', 'Sales')
       ON CONFLICT (email) DO NOTHING`,
      [password],
    );

    await client.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT u.id, r.id FROM users u, roles r
        WHERE (u.email = 'admin@contoso.com' AND r.name = 'portal_admin')
           OR (u.email = 'emea@contoso.com'  AND r.name = 'sales_manager')
           OR (u.email = 'apac@contoso.com'  AND r.name = 'sales_manager')
       ON CONFLICT DO NOTHING`,
    );

    // ---- RLS attributes -------------------------------------------------
    // These must match the model's mapping table, or the user sees zero rows.
    await client.query(
      `INSERT INTO user_rls_attributes (user_id, attr_key, attr_value)
       SELECT u.id, 'region', v.region
         FROM users u
         JOIN (VALUES ('emea@contoso.com', 'EMEA'), ('apac@contoso.com', 'APAC'))
              AS v(email, region) ON v.email = u.email::text
       ON CONFLICT (user_id, attr_key) DO UPDATE SET attr_value = EXCLUDED.attr_value`,
    );

    // ---- report ---------------------------------------------------------
    await client.query(
      `INSERT INTO reports (name, slug, description, category, workspace_id,
                            pbi_report_id, pbi_dataset_id, rls_required)
       VALUES ('Regional Sales Performance', 'regional-sales',
               'Revenue, pipeline and quota attainment, filtered to your region.',
               'Sales', $1, $2, $3, TRUE)
       ON CONFLICT (slug) DO UPDATE
         SET workspace_id   = EXCLUDED.workspace_id,
             pbi_report_id  = EXCLUDED.pbi_report_id,
             pbi_dataset_id = EXCLUDED.pbi_dataset_id`,
      [WORKSPACE_ID, REPORT_ID, DATASET_ID],
    );

    // ---- grants ---------------------------------------------------------
    await client.query(
      `INSERT INTO report_role_access (report_id, role_id)
       SELECT rep.id, r.id FROM reports rep, roles r
        WHERE rep.slug = 'regional-sales' AND r.name IN ('sales_manager', 'portal_admin')
       ON CONFLICT DO NOTHING`,
    );

    // ---- RLS role mapping ----------------------------------------------
    // 'RegionalManager' must match the role name in Power BI Desktop EXACTLY,
    // including case. This is the single most common source of silent RLS bugs.
    await client.query(
      `INSERT INTO rls_role_mappings (role_id, pbi_dataset_id, pbi_role_name)
       SELECT r.id, $1::uuid, 'RegionalManager'
         FROM roles r WHERE r.name = 'sales_manager'
       ON CONFLICT DO NOTHING`,
      [DATASET_ID],
    );
  });

  console.log(`Seeded. Login with admin@contoso.com / emea@contoso.com / apac@contoso.com
Password for all three: Portal!Dev123

Update the Power BI IDs before embedding actually works:
  workspace: ${WORKSPACE_ID}
  report:    ${REPORT_ID}
  dataset:   ${DATASET_ID}`);
}

seed()
  .then(() => closePool())
  .catch(async (err) => {
    console.error('Seed failed:', err.message);
    await closePool().catch(() => undefined);
    process.exit(1);
  });
