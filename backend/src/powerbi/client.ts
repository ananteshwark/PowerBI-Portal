import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { upstreamError, notFound } from '../utils/errors.js';
import { getAadToken, remainingMinutes, type AadToken } from './aadToken.js';

/**
 * Thin typed wrapper over the Power BI REST API.
 *
 * We call REST directly rather than pulling in the `powerbi-api` SDK: we need
 * three endpoints, and the SDK adds a large dependency plus its own auth
 * abstraction that we would only have to work around.
 */

export interface PbiReport {
  id: string;
  name: string;
  webUrl: string;
  embedUrl: string;
  datasetId: string;
}

export interface PbiDatasetRole {
  name: string;
}

export interface EmbedTokenResult {
  token: string;
  tokenId: string;
  expiration: string; // ISO-8601, UTC
}

/** identities[] entry, exactly as the GenerateToken API expects it. */
export interface PbiEffectiveIdentity {
  username: string;
  roles: string[];
  datasets: string[];
  /** DirectQuery-with-SSO only; not used for import models. */
  identityBlob?: { value: string };
  /** Only for datasets whose credentials are per-customer. */
  customData?: string;
}

const TIMEOUT_MS = 15_000;

async function pbiFetch<T>(
  path: string,
  init: { method: 'GET' | 'POST'; body?: unknown; token: AadToken },
): Promise<T> {
  const url = `${config.powerbi.apiBase}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      headers: {
        Authorization: `Bearer ${init.token.accessToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: init.body ? JSON.stringify(init.body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw upstreamError(`Power BI API timed out after ${TIMEOUT_MS}ms`, { path });
    }
    throw upstreamError('Could not reach the Power BI API', err);
  } finally {
    clearTimeout(timer);
  }

  if (res.ok) {
    // 204 has no body; every endpoint we use returns JSON otherwise.
    return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
  }

  const bodyText = await res.text().catch(() => '');
  // Power BI puts the actionable detail in this header far more often than in
  // the body — surface it in logs, it is the difference between a 5-minute and
  // a 5-hour debugging session.
  const errorDetail = res.headers.get('x-powerbi-error-info') ?? '';
  const requestId = res.headers.get('requestid') ?? '';

  logger.error(
    { status: res.status, path, errorDetail, requestId, body: bodyText.slice(0, 800) },
    'Power BI API error',
  );

  throw translatePbiError(res.status, path, bodyText, errorDetail);
}

/** Map raw Power BI failures onto messages that point at the actual fix. */
function translatePbiError(status: number, path: string, body: string, detail: string) {
  const blob = `${detail} ${body}`;

  if (status === 401) {
    return upstreamError(
      'Power BI rejected the service principal. Check that "Allow service principals to use Power BI APIs" is enabled for its security group (docs/AZURE_SETUP.md step 5) and that it has Member or Contributor on the workspace (step 6).',
      { status, path },
    );
  }
  if (status === 403) {
    return upstreamError(
      'The service principal is authenticated but not permitted for this workspace or report. Viewer access is not sufficient — grant Member or Contributor.',
      { status, path },
    );
  }
  if (status === 404) {
    return notFound('Report, dataset or workspace not found in Power BI. Verify the IDs stored in the reports table.');
  }
  if (status === 429) {
    return upstreamError('Power BI API rate limit reached. Requests are cached; this indicates unusually high traffic or a cache misconfiguration.', { status, path });
  }
  if (blob.includes('requires effective identity')) {
    return upstreamError(
      'This dataset has RLS roles defined, so an effective identity is mandatory. No RLS roles resolved for this user — check rls_role_mappings.',
      { status, path },
    );
  }
  if (blob.includes('effective identity is not allowed') || blob.includes('InvalidRequest')) {
    return upstreamError(
      'Power BI rejected the effective identity. Usual causes: the dataset has no RLS roles defined (set reports.rls_required = false), or a role name in rls_role_mappings does not exactly match a role in the dataset (names are case-sensitive).',
      { status, path },
    );
  }
  return upstreamError(`Power BI API returned ${status}`, { status, path, detail });
}

/** GET /groups/{workspaceId}/reports/{reportId} — gives embedUrl + datasetId. */
export async function getReport(workspaceId: string, reportId: string): Promise<PbiReport> {
  const token = await getAadToken();
  return pbiFetch<PbiReport>(`/groups/${workspaceId}/reports/${reportId}`, {
    method: 'GET',
    token,
  });
}

/** GET /groups/{workspaceId}/datasets/{datasetId}/roles — used by verify script. */
export async function getDatasetRoles(
  workspaceId: string,
  datasetId: string,
): Promise<string[]> {
  const token = await getAadToken();
  const res = await pbiFetch<{ value: PbiDatasetRole[] }>(
    `/groups/${workspaceId}/datasets/${datasetId}/roles`,
    { method: 'GET', token },
  );
  return (res.value ?? []).map((r) => r.name);
}

export interface GenerateTokenParams {
  workspaceId: string;
  reportId: string;
  datasetId: string;
  /** Omit for datasets without RLS roles; Power BI rejects identities then. */
  identities?: PbiEffectiveIdentity[];
  requestedLifetimeMinutes: number;
  allowEdit?: boolean;
}

/**
 * POST /GenerateToken — the multi-resource endpoint.
 *
 * We use this rather than the older per-report
 * /groups/{ws}/reports/{id}/GenerateToken because it is the only form that
 * supports multiple datasets/reports in one token and is what Microsoft
 * documents going forward.
 *
 * THIS IS WHERE RLS IS ENFORCED. The `identities` array is the assertion
 * "treat the viewer as this principal, with these roles". Power BI bakes the
 * resulting filters into the token; the browser cannot alter them.
 */
export async function generateEmbedToken(
  params: GenerateTokenParams,
): Promise<EmbedTokenResult> {
  const token = await getAadToken();

  // Power BI rejects a lifetime longer than the AAD token has left. Cap it,
  // and leave a 2-minute margin so we never lose a race with expiry.
  const aadMinutes = Math.max(0, remainingMinutes(token) - 2);
  const lifetimeInMinutes = Math.min(params.requestedLifetimeMinutes, aadMinutes);

  if (lifetimeInMinutes < 1) {
    // MSAL should have refreshed before this; treat as transient.
    throw upstreamError('Entra ID token is about to expire; retry in a moment');
  }

  const body: Record<string, unknown> = {
    datasets: [{ id: params.datasetId }],
    reports: [{ id: params.reportId, allowEdit: params.allowEdit ?? false }],
    targetWorkspaces: [{ id: params.workspaceId }],
    lifetimeInMinutes,
  };

  if (params.identities?.length) {
    body.identities = params.identities;
  }

  const result = await pbiFetch<EmbedTokenResult>('/GenerateToken', {
    method: 'POST',
    body,
    token,
  });

  logger.info(
    {
      reportId: params.reportId,
      datasetId: params.datasetId,
      lifetimeInMinutes,
      rlsRoles: params.identities?.[0]?.roles ?? [],
      // username is deliberately logged: it is the audit trail for what data
      // context was released. It is not a secret.
      rlsUsername: params.identities?.[0]?.username ?? null,
    },
    'Embed token generated',
  );

  return result;
}
