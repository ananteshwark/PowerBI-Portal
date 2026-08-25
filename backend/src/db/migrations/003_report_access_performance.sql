-- =============================================================================
-- Make the report catalogue scale with the user's grants instead of the whole
-- table.
--
-- The user_report_access VIEW leads with `JOIN reports r ON r.is_active`, which
-- forces `reports` to drive the plan. For the single-report authorization check
-- that is fine — the planner pushes both predicates into index scans (0.26 ms).
-- For the unfiltered catalogue query it is not: report_role_access gets fully
-- seq-scanned and hashed on every dashboard load.
--
-- Measured on 5 000 users / 5 000 reports / 40 000 grants, warm and repeated
-- (a single cold run overstates the gain; these are steady-state figures):
--
--   CATALOGUE, typical user (20 of 5 000 reports accessible)
--     view ................................  14.8 ms
--     function + covering index ...........   5.5 ms      2.7x
--
--   CATALOGUE, pathological user (2 460 accessible)
--     view ................................  27.0 ms
--     function + covering index ...........  21.8 ms      row volume dominates
--
--   POINT LOOKUP (the per-embed authorization check)
--     view ................................   0.31 ms     Index Only Scan on the new index
--     function ............................   4.81 ms     Function Scan, 2 459 rows discarded
--
-- The constant factor matters less than the shape. The view seq-scans the whole
-- of report_role_access, so the catalogue was O(TOTAL grants in the system) and
-- degraded as other teams onboarded reports this user has nothing to do with.
-- The function is O(this user's grants), so the gap widens as the system grows.
--
-- Each path therefore keeps the shape that suits it, which is why this
-- migration ADDS the function rather than replacing the view.
--
-- The view stays on the point lookup because there the user id and report id
-- are ordinary predicates the planner pushes into index scans. Wrapping that in
-- a function is strictly worse: PostgreSQL will not inline a RETURNS TABLE SRF
-- here, so it materialises every accessible report and filters afterwards
-- (2 459 rows built and thrown away to return 1). Adding the filter as a
-- DEFAULT NULL parameter does not help either — `(p IS NULL OR col = p)` cannot
-- use the index in a generic plan.
--
-- Two definitions of "can this user see this report" is a drift risk, so
-- test/reportAccess.integration.test.ts asserts the two agree for every
-- user/report pair over a matrix of grant shapes.
-- =============================================================================

-- The PK is (report_id, role_id), which is the wrong column order for "give me
-- everything granted to these roles". Adding report_id to the index makes the
-- lookup index-only.
CREATE INDEX report_role_access_role_report_idx
    ON report_role_access (role_id, report_id);

-- Superseded: (role_id) alone required a heap fetch per row for report_id.
DROP INDEX IF EXISTS report_role_access_role_idx;

CREATE OR REPLACE FUNCTION accessible_reports(p_user_id UUID)
RETURNS TABLE (
    report_id              UUID,
    slug                   TEXT,
    name                   TEXT,
    description            TEXT,
    category               TEXT,
    workspace_id           UUID,
    pbi_report_id          UUID,
    pbi_dataset_id         UUID,
    rls_required           BOOLEAN,
    token_lifetime_minutes INTEGER
)
LANGUAGE sql
STABLE
-- Runs as the caller; there is no SECURITY DEFINER privilege escalation here.
AS $$
    SELECT r.id, r.slug, r.name, r.description, r.category,
           r.workspace_id, r.pbi_report_id, r.pbi_dataset_id,
           r.rls_required, r.token_lifetime_minutes
      FROM reports r
     WHERE r.is_active
       AND EXISTS (SELECT 1 FROM users u WHERE u.id = p_user_id AND u.is_active)
       AND r.id IN (
           -- role-based grants
           SELECT ra.report_id
             FROM report_role_access ra
             JOIN user_roles ur ON ur.role_id = ra.role_id
            WHERE ur.user_id = p_user_id
           UNION
           -- direct grants, ignoring any that have lapsed
           SELECT ua.report_id
             FROM report_user_access ua
            WHERE ua.user_id = p_user_id
              AND (ua.expires_at IS NULL OR ua.expires_at > now())
       );
$$;

COMMENT ON FUNCTION accessible_reports(UUID) IS
    'Catalogue listing: every report a user may see. Must return exactly the '
    'same set as user_report_access filtered to that user — enforced by '
    'test/reportAccess.integration.test.ts.';

COMMENT ON VIEW user_report_access IS
    'Point lookup: is this user granted THIS report. Keeps the per-embed check '
    'sub-millisecond because the user id and report id are ordinary predicates '
    'the planner pushes into index scans. Do not use it unfiltered — that path '
    'is O(total grants); call accessible_reports() instead.';
