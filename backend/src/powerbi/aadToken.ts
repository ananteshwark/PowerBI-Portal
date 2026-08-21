import { ConfidentialClientApplication, type AuthenticationResult } from '@azure/msal-node';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { upstreamError } from '../utils/errors.js';

/**
 * Acquires the Microsoft Entra ID access token for the service principal
 * (OAuth2 client_credentials).
 *
 * This token is a TENANT-WIDE Power BI credential. It must never reach the
 * browser, never be logged, and never be returned by any endpoint. Everything
 * the browser gets is derived from it (short-lived, report-scoped embed
 * tokens).
 *
 * MSAL keeps its own in-memory token cache and serves from it until ~5 minutes
 * before expiry, so calling this per request is cheap — it is a cache lookup,
 * not a network round-trip. We add single-flight on top so a cold start with N
 * concurrent requests produces exactly one token request instead of N.
 */

const msalClient = new ConfidentialClientApplication({
  auth: {
    clientId: config.azure.clientId,
    authority: config.azure.authority,
    clientSecret: config.azure.clientSecret,
    // Production alternative — certificate credential:
    // clientCertificate: { thumbprint: '...', privateKey: fs.readFileSync('...', 'utf8') },
  },
  system: {
    loggerOptions: {
      // MSAL's own logger can emit token material at Verbose. Keep it off.
      loggerCallback: (_level, message, containsPii) => {
        if (!containsPii) logger.debug({ msal: message }, 'msal');
      },
      piiLoggingEnabled: false,
    },
  },
});

export interface AadToken {
  accessToken: string;
  expiresOn: Date;
}

let inFlight: Promise<AadToken> | null = null;

export async function getAadToken(): Promise<AadToken> {
  if (inFlight) return inFlight;

  inFlight = (async (): Promise<AadToken> => {
    let result: AuthenticationResult | null;
    try {
      result = await msalClient.acquireTokenByClientCredential({
        scopes: [config.azure.scope],
      });
    } catch (err) {
      logger.error({ err }, 'Entra ID token acquisition failed');
      // Distinguish the two failures people actually hit, without echoing the
      // raw AADSTS text (it contains tenant identifiers) to the client.
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('AADSTS7000215')) {
        throw upstreamError('Entra ID rejected the client secret (invalid or expired)', err);
      }
      if (msg.includes('AADSTS700016') || msg.includes('AADSTS90002')) {
        throw upstreamError('Entra ID application or tenant not found — check AZURE_CLIENT_ID / AZURE_TENANT_ID', err);
      }
      throw upstreamError('Could not authenticate with Entra ID', err);
    }

    if (!result?.accessToken) {
      throw upstreamError('Entra ID returned no access token');
    }

    // expiresOn can be null in edge cases; assume the standard 60 min.
    const expiresOn = result.expiresOn ?? new Date(Date.now() + 60 * 60 * 1000);

    logger.debug(
      { expiresOn, fromCache: result.fromCache },
      'Entra ID token acquired',
    );

    return { accessToken: result.accessToken, expiresOn };
  })();

  try {
    return await inFlight;
  } finally {
    // Clear so a later expiry triggers a fresh acquisition. MSAL's cache means
    // that call is still nearly free while the token remains valid.
    inFlight = null;
  }
}

/**
 * Minutes of life left on the app token, floored at 0.
 *
 * Needed because Power BI rejects a GenerateToken request whose
 * lifetimeInMinutes exceeds the remaining lifetime of the AAD token used to
 * make it. Callers cap their requested lifetime with this.
 */
export function remainingMinutes(token: AadToken): number {
  return Math.max(0, Math.floor((token.expiresOn.getTime() - Date.now()) / 60_000));
}
