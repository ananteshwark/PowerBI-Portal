import { query } from '../db/pool.js';
import { logger } from '../utils/logger.js';

export type AuditAction =
  | 'login'
  | 'login_failed'
  | 'logout'
  | 'token_refresh'
  | 'embed_token_issued'
  | 'embed_token_served_from_cache'
  | 'access_denied'
  | 'rls_resolution_failed';

export interface AuditEntry {
  userId?: string | null;
  action: AuditAction;
  reportId?: string | null;
  effectiveUsername?: string | null;
  rlsRoles?: string[] | null;
  detail?: Record<string, unknown>;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Fire-and-forget audit write.
 *
 * Deliberately does not await the caller's request path and never rejects: a
 * failed audit insert must not turn a working dashboard into a 500. Failures
 * are logged loudly so a broken audit pipeline is still visible.
 *
 * For regulated environments where the audit record is a hard requirement,
 * make this awaited and part of the request transaction instead.
 */
export function recordAudit(entry: AuditEntry): void {
  void query(
    `INSERT INTO audit_log
        (user_id, action, report_id, effective_username, rls_roles, detail, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      entry.userId ?? null,
      entry.action,
      entry.reportId ?? null,
      entry.effectiveUsername ?? null,
      entry.rlsRoles ?? null,
      JSON.stringify(entry.detail ?? {}),
      entry.ipAddress ?? null,
      entry.userAgent ?? null,
    ],
  ).catch((err) => logger.error({ err, action: entry.action }, 'Audit write failed'));
}
