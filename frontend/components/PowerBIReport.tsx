'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { PowerBIEmbed } from 'powerbi-client-react';
import { models, type Report, type Embed, service } from 'powerbi-client';
import { fetchEmbedConfig, ApiError, type EmbedConfig } from '@/lib/api';

type Phase = 'loading' | 'embedding' | 'ready' | 'error';

/**
 * How many times we will re-fetch a token because Power BI rejected the last
 * one, before concluding the problem is not the token.
 */
const MAX_SDK_RECOVERIES = 2;

/**
 * ...counted only within this window. What needs bounding is a *loop* — the
 * same error recurring in seconds — not the session total. A dashboard left
 * open all day can legitimately hit the expiry backstop several times hours
 * apart, and a lifetime counter would eventually refuse to recover it.
 */
const SDK_RECOVERY_WINDOW_MS = 2 * 60_000;

interface Props {
  /** Portal report slug or UUID — never the Power BI report id. */
  slug: string;
  /** Show the Power BI filter pane. Default false: RLS already scopes the data. */
  showFilterPane?: boolean;
  /** Page navigation tabs along the bottom. */
  showPageNav?: boolean;
  className?: string;
}

/**
 * Embeds one Power BI report.
 *
 * The two things this component exists to get right:
 *
 * 1. TOKEN REFRESH WITHOUT RE-EMBEDDING. Embed tokens expire in <=60 minutes.
 *    Re-creating the iframe would work but throws away the user's filters,
 *    cross-highlights and current page — on a dashboard someone leaves open all
 *    day, that is a visible, infuriating reset every hour. Instead we call
 *    `report.setAccessToken()` on the live embed, which the user never notices.
 *    That is why `embedConfig` below is memoised on the report identity only:
 *    if the token were part of it, every refresh would re-mount the iframe.
 *
 * 2. HONEST STATES. "loading" (fetching our token), "embedding" (Power BI is
 *    rendering), "ready", "error". Collapsing these makes a 6-second embed look
 *    like a hang.
 */
export default function PowerBIReport({
  slug,
  showFilterPane = false,
  showPageNav = true,
  className,
}: Props) {
  const [phase, setPhase] = useState<Phase>('loading');
  const [error, setError] = useState<{ message: string; canRetry: boolean } | null>(null);
  const [config, setConfig] = useState<EmbedConfig | null>(null);

  // The live embed instance. Held in a ref because mutating it must not
  // re-render (and re-rendering must not recreate it).
  const reportRef = useRef<Report | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryCount = useRef(0);
  // Recoveries triggered by Power BI itself rejecting the token, as opposed to
  // our own scheduled refresh. Counted within a sliding window, see below.
  const sdkRecoveries = useRef(0);
  const lastSdkRecoveryAt = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    };
  }, []);

  // ---------------------------------------------------------------- fetch --
  const loadToken = useCallback(
    async (isRefresh: boolean, opts: { bypassCache?: boolean } = {}) => {
      try {
        const next = await fetchEmbedConfig(slug, opts);
        if (!mounted.current) return;

        retryCount.current = 0;

        if (isRefresh && reportRef.current) {
          // The whole point: swap the token in place, keep the iframe.
          await reportRef.current.setAccessToken(next.embedToken);
          setConfig((prev) => (prev ? { ...prev, ...next } : next));
        } else {
          setConfig(next);
          setPhase('embedding');
        }

        scheduleRefresh(next.refreshInSeconds);
      } catch (err) {
        if (!mounted.current) return;

        // A failed *refresh* is recoverable — the current token is still valid
        // for a few more minutes, so retry with backoff instead of tearing the
        // report down in front of the user.
        if (isRefresh && retryCount.current < 3) {
          retryCount.current += 1;
          scheduleRefresh(Math.min(30 * 2 ** retryCount.current, 120));
          return;
        }

        const apiErr = err instanceof ApiError ? err : null;
        setError({
          message:
            apiErr?.status === 403
              ? apiErr.message
              : apiErr?.status === 401
                ? 'Your session has expired. Please sign in again.'
                : 'The report could not be loaded. Please try again.',
          // 403 is a permissions decision — retrying will not change it.
          canRetry: apiErr?.status !== 403 && apiErr?.status !== 401,
        });
        setPhase('error');
      }
    },
    // scheduleRefresh is stable (defined below via useCallback on loadToken-free deps)
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [slug],
  );

  const scheduleRefresh = useCallback(
    (seconds: number) => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      // Never schedule further out than ~55 min, and never tighter than 30s.
      const delay = Math.min(Math.max(seconds, 30), 55 * 60) * 1000;
      refreshTimer.current = setTimeout(() => void loadToken(true), delay);
    },
    [loadToken],
  );

  useEffect(() => {
    setPhase('loading');
    setError(null);
    setConfig(null);
    reportRef.current = null;
    void loadToken(false);
  }, [loadToken]);

  // ------------------------------------------------------- embed settings --
  /**
   * Memoised on the report identity, NOT the token — see note (1) above.
   * `config?.embedToken` is read at first embed only; refreshes go through
   * setAccessToken.
   */
  const embedConfig = useMemo(() => {
    if (!config) return null;
    return {
      type: 'report' as const,
      id: config.reportId,
      embedUrl: config.embedUrl,
      accessToken: config.embedToken,
      tokenType: models.TokenType.Embed, // Embed, not Aad — App Owns Data
      settings: {
        panes: {
          filters: { expanded: false, visible: showFilterPane },
          pageNavigation: { visible: showPageNav },
        },
        // Scale to the container instead of a fixed canvas size — this is what
        // makes the report usable on a laptop and a 4K monitor alike.
        layoutType: models.LayoutType.Custom,
        customLayout: { displayOption: models.DisplayOption.FitToWidth },
        background: models.BackgroundType.Transparent,
        bars: { statusBar: { visible: false } },
      },
    };
    // Token intentionally excluded from deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config?.reportId, config?.embedUrl, showFilterPane, showPageNav]);

  // ---------------------------------------------------------- SDK events --
  const eventHandlers = useMemo(
    () =>
      new Map<string, (event?: service.ICustomEvent<unknown>) => void>([
        [
          'loaded',
          () => {
            // 'loaded' = metadata in; visuals may still be rendering.
            sdkRecoveries.current = 0;
            if (mounted.current) setPhase('ready');
          },
        ],
        ['rendered', () => undefined],
        [
          'error',
          (event) => {
            const detail = event?.detail as
              | { message?: string; detailedMessage?: string; errorCode?: string }
              | undefined;

            // Backstop for the case where our proactive refresh did not land in
            // time (laptop asleep, tab throttled by the browser).
            //
            // Bounded, because a 403 here does not always mean "stale token" —
            // a paused capacity or a deleted report reports the same way, and
            // an unbounded recover-and-retry loop would hammer the API at
            // network speed until the server-side limiter cut it off.
            if (detail?.message === 'TokenExpired' || detail?.errorCode === '403') {
              const now = Date.now();
              // Outside the window this is a fresh incident, not a loop.
              if (now - lastSdkRecoveryAt.current > SDK_RECOVERY_WINDOW_MS) {
                sdkRecoveries.current = 0;
              }
              if (sdkRecoveries.current < MAX_SDK_RECOVERIES) {
                sdkRecoveries.current += 1;
                lastSdkRecoveryAt.current = now;
                void loadToken(true, { bypassCache: true });
                return;
              }
              // Still failing after repeated fresh tokens, so the token is not
              // the problem — a paused capacity or a deleted report looks like
              // this. Fall through and surface it.
            }

            if (mounted.current) {
              setError({
                message: detail?.detailedMessage ?? detail?.message ?? 'Power BI reported an error.',
                canRetry: true,
              });
              setPhase('error');
            }
          },
        ],
      ]),
    [loadToken],
  );

  const handleEmbedded = useCallback((embed: Embed) => {
    reportRef.current = embed as Report;
  }, []);

  const retry = () => {
    setPhase('loading');
    setError(null);
    retryCount.current = 0;
    sdkRecoveries.current = 0;
    lastSdkRecoveryAt.current = 0;
    // Clear the config first. The token is deliberately excluded from the
    // embedConfig memo deps (see note 1), so without this the deps are
    // unchanged, useMemo hands back its cached object, and we re-embed with the
    // very token that just failed.
    setConfig(null);
    reportRef.current = null;
    // Power BI rejected what we had, so ask for a genuinely new token rather
    // than whatever is sitting in the server-side cache.
    void loadToken(false, { bypassCache: true });
  };

  // ------------------------------------------------------------- rendering --
  return (
    <div className={`pbi-shell ${className ?? ''}`}>
      {phase === 'error' && error ? (
        <div className="pbi-state" role="alert">
          <svg viewBox="0 0 24 24" width="40" height="40" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v5M12 16.5h.01" strokeLinecap="round" />
          </svg>
          <p className="pbi-state__title">Unable to display this report</p>
          <p className="pbi-state__detail">{error.message}</p>
          {error.canRetry && (
            <button type="button" className="btn btn--primary" onClick={retry}>
              Try again
            </button>
          )}
        </div>
      ) : (
        <>
          {phase !== 'ready' && (
            <div className="pbi-state pbi-state--overlay" aria-live="polite">
              <span className="spinner" aria-hidden="true" />
              <p className="pbi-state__detail">
                {phase === 'loading' ? 'Preparing your secure report…' : 'Loading report…'}
              </p>
            </div>
          )}

          {embedConfig && (
            <PowerBIEmbed
              embedConfig={embedConfig}
              eventHandlers={eventHandlers}
              getEmbeddedComponent={handleEmbedded}
              // The SDK injects an iframe into this element; the class carries
              // the sizing rules (see globals.css).
              cssClassName={`pbi-frame ${phase === 'ready' ? 'pbi-frame--visible' : ''}`}
            />
          )}
        </>
      )}

      {config?.rls && phase === 'ready' && (
        <p className="pbi-rls-note">
          Row-level security active — viewing as <strong>{config.rls.username}</strong>
          {config.rls.roles.length > 0 && <> ({config.rls.roles.join(', ')})</>}
        </p>
      )}
    </div>
  );
}
