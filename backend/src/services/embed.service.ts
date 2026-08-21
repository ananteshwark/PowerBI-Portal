import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { forbidden } from '../utils/errors.js';
import { generateEmbedToken, getReport } from '../powerbi/client.js';
import type { AuthenticatedUser, EmbedConfigResponse } from '../types/domain.js';
import { findAccessibleReport, cacheDatasetId } from './reports.service.js';
import { resolveEffectiveIdentity } from './identity.service.js';
import { getOrCreateEmbedToken, identityFingerprint } from './tokenCache.js';
import { recordAudit } from './audit.service.js';

export interface EmbedRequestContext {
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Produce everything the browser needs to embed one report, for one user.
 *
 * Order of operations is load-bearing:
 *
 *   1. AUTHORIZE  — does this user have a grant for this report?
 *   2. RESOLVE    — which RLS roles apply, under which username?
 *   3. FAIL-CLOSED— refuse if RLS is required but resolved to nothing.
 *   4. MINT       — GenerateToken with identities (cached / single-flighted).
 *
 * Step 1 must precede everything: RLS filters *rows within* a report, it does
 * not decide *which reports* a user may open. Relying on RLS alone means any
 * authenticated user can open any report ID in the workspace.
 *
 * Step 3 is the one that prevents silent data leaks. A GenerateToken call
 * without `identities` against an RLS-enabled dataset does not fail — it
 * returns a token that sees EVERY row. So "no roles resolved" must be a 403,
 * never a token request with the identities omitted.
 */
export async function buildEmbedConfig(
  user: AuthenticatedUser,
  reportIdOrSlug: string,
  ctx: EmbedRequestContext = {},
): Promise<EmbedConfigResponse> {
  // ---- 1. Authorize ------------------------------------------------------
  const report = await findAccessibleReport(user.id, reportIdOrSlug);

  if (!report) {
    recordAudit({
      userId: user.id,
      action: 'access_denied',
      detail: { requested: reportIdOrSlug },
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    // 403 rather than 404: the caller is authenticated, and a 404 here would
    // let someone enumerate which report IDs exist by probing for the
    // difference. Both responses are identical for an unknown report.
    throw forbidden('You do not have access to this report');
  }

  // ---- 2. Resolve the Power BI coordinates -------------------------------
  // datasetId is needed both for the RLS mapping lookup and the token request.
  // Cached on the row after the first resolution.
  let datasetId = report.pbiDatasetId;
  let embedUrl: string | null = null;

  if (!datasetId) {
    const pbiReport = await getReport(report.workspaceId, report.pbiReportId);
    datasetId = pbiReport.datasetId;
    embedUrl = pbiReport.embedUrl;
    await cacheDatasetId(report.reportId, datasetId);
  }

  // ---- 3. Resolve the effective identity ---------------------------------
  const identity = await resolveEffectiveIdentity(user.id, datasetId);

  if (report.rlsRequired && identity.roles.length === 0) {
    // FAIL CLOSED. See the doc comment above — this is not a recoverable case.
    logger.warn(
      { userId: user.id, reportId: report.reportId, datasetId },
      'RLS required but no roles resolved — refusing to issue an unfiltered token',
    );
    recordAudit({
      userId: user.id,
      action: 'rls_resolution_failed',
      reportId: report.reportId,
      effectiveUsername: identity.username,
      detail: { datasetId, portalRoles: user.roles },
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    throw forbidden(
      'No row-level security context could be resolved for your account on this report. Contact your administrator.',
    );
  }

  const useIdentities = report.rlsRequired && identity.roles.length > 0;
  const fingerprint = identityFingerprint(
    useIdentities ? identity.username : null,
    useIdentities ? identity.roles : [],
  );

  // ---- 4. Mint (or reuse) the embed token --------------------------------
  const { value, cached } = await getOrCreateEmbedToken(
    { userId: user.id, reportId: report.reportId, fingerprint },
    async () => {
      // embedUrl may already be in hand from the datasetId lookup above.
      const resolvedEmbedUrl =
        embedUrl ?? (await getReport(report.workspaceId, report.pbiReportId)).embedUrl;

      const result = await generateEmbedToken({
        workspaceId: report.workspaceId,
        reportId: report.pbiReportId,
        datasetId: datasetId!,
        requestedLifetimeMinutes: report.tokenLifetimeMinutes,
        allowEdit: false,
        ...(useIdentities
          ? {
              identities: [
                {
                  username: identity.username,
                  roles: identity.roles,
                  datasets: [datasetId!],
                },
              ],
            }
          : {}),
      });

      return {
        token: result.token,
        embedUrl: resolvedEmbedUrl,
        reportId: report.pbiReportId,
        expiresAtMs: new Date(result.expiration).getTime(),
        rlsUsername: useIdentities ? identity.username : null,
        rlsRoles: useIdentities ? identity.roles : [],
      };
    },
  );

  recordAudit({
    userId: user.id,
    action: cached ? 'embed_token_served_from_cache' : 'embed_token_issued',
    reportId: report.reportId,
    effectiveUsername: value.rlsUsername,
    rlsRoles: value.rlsRoles,
    detail: { datasetId, workspaceId: report.workspaceId },
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  return {
    reportId: value.reportId,
    embedUrl: value.embedUrl,
    embedToken: value.token,
    expiresAt: new Date(value.expiresAtMs).toISOString(),
    tokenType: 'Embed',
    rls: value.rlsUsername ? { username: value.rlsUsername, roles: value.rlsRoles } : null,
  };
}

/**
 * Seconds until the client should refresh. Exported so the /api/embed route
 * and any future SSE/websocket push agree on one definition.
 */
export function secondsUntilRefresh(expiresAtIso: string): number {
  const ms = new Date(expiresAtIso).getTime() - Date.now();
  return Math.max(0, Math.floor(ms / 1000) - config.cache.refreshSkewSeconds);
}
