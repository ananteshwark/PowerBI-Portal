/**
 * API client.
 *
 * The access token lives in a module-scoped variable — deliberately NOT in
 * localStorage or sessionStorage, both of which are readable by any injected
 * script. The cost is that a page refresh loses it; that is recovered silently
 * via the HttpOnly refresh cookie on mount (see AuthProvider).
 */

const API_ORIGIN = process.env.NEXT_PUBLIC_API_ORIGIN ?? 'http://localhost:4000';

let accessToken: string | null = null;
let onUnauthenticated: (() => void) | null = null;

export const setAccessToken = (token: string | null) => {
  accessToken = token;
};
export const getAccessToken = () => accessToken;
export const setUnauthenticatedHandler = (fn: (() => void) | null) => {
  onUnauthenticated = fn;
};

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Single-flight refresh. Without this, a page that fires several requests at
 * once on an expired token produces one refresh call per request — and because
 * refresh tokens rotate, the losers of that race present an already-rotated
 * token, which the backend treats as theft and responds to by revoking every
 * session. Sharing one in-flight promise is what prevents that.
 */
let refreshPromise: Promise<boolean> | null = null;

async function doRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${API_ORIGIN}/api/auth/refresh`, {
      method: 'POST',
      credentials: 'include', // sends the HttpOnly refresh cookie
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { accessToken: string };
    accessToken = data.accessToken;
    return true;
  } catch {
    return false;
  }
}

/**
 * The in-page promise above only dedupes within one document. Two tabs still
 * race, and the loser presents a cookie the winner has already rotated. The
 * server now tolerates that (see REUSE_LEEWAY_MS), but taking a cross-tab lock
 * means the second tab usually does not make the redundant call at all.
 *
 * Web Locks is unavailable on older Safari and in non-secure contexts, so this
 * is an optimisation layered on top of the server-side fix, never the fix
 * itself.
 */
async function withCrossTabLock<T>(fn: () => Promise<T>): Promise<T> {
  if (typeof navigator === 'undefined' || !navigator.locks) return fn();
  return navigator.locks.request('pbp-token-refresh', fn) as Promise<T>;
}

async function refreshAccessToken(): Promise<boolean> {
  refreshPromise ??= (async () => {
    try {
      return await withCrossTabLock(doRefresh);
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  /** Internal: prevents infinite retry loops. */
  _isRetry?: boolean;
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, _isRetry, headers, ...rest } = options;

  const res = await fetch(`${API_ORIGIN}${path}`, {
    ...rest,
    credentials: 'include',
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });

  // Expired access token: refresh once, then replay the original request.
  if (res.status === 401 && !_isRetry && !path.startsWith('/api/auth/')) {
    if (await refreshAccessToken()) {
      return apiFetch<T>(path, { ...options, _isRetry: true });
    }
    accessToken = null;
    onUnauthenticated?.();
    throw new ApiError(401, 'unauthorized', 'Your session has expired. Please sign in again.');
  }

  if (res.status === 204) return undefined as T;

  const payload = (await res.json().catch(() => null)) as
    | { error?: { code: string; message: string; details?: unknown } }
    | null;

  if (!res.ok) {
    const err = payload?.error;
    throw new ApiError(
      res.status,
      err?.code ?? 'unknown_error',
      err?.message ?? `Request failed with status ${res.status}`,
      err?.details,
    );
  }

  return payload as T;
}

// ------------------------------------------------------------------ types --
export interface SessionUser {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
  isAdmin: boolean;
}

export interface ReportSummary {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  category: string | null;
  rlsEnabled: boolean;
}

export interface EmbedConfig {
  reportId: string;
  embedUrl: string;
  embedToken: string;
  expiresAt: string;
  tokenType: 'Embed';
  refreshInSeconds: number;
  rls: { username: string; roles: string[] } | null;
}

// ------------------------------------------------------------- endpoints --
export const login = (email: string, password: string) =>
  apiFetch<{ accessToken: string; expiresIn: number; user: SessionUser }>('/api/auth/login', {
    method: 'POST',
    body: { email, password },
  });

export const logout = () => apiFetch<void>('/api/auth/logout', { method: 'POST' });

export const restoreSession = () =>
  apiFetch<{ accessToken: string; user: SessionUser }>('/api/auth/refresh', { method: 'POST' });

export const fetchReports = () => apiFetch<{ reports: ReportSummary[] }>('/api/reports');

/**
 * `bypassCache` is for one situation only: Power BI told us the token we hold
 * is bad. Without it the server returns the same cached token and the client
 * loops. Do not set it on the routine pre-expiry refresh.
 */
export const fetchEmbedConfig = (slugOrId: string, opts: { bypassCache?: boolean } = {}) =>
  apiFetch<EmbedConfig>(
    `/api/embed/${encodeURIComponent(slugOrId)}${opts.bypassCache ? '?bypassCache=1' : ''}`,
  );
