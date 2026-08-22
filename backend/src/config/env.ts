import 'dotenv/config';
import { z } from 'zod';

/**
 * Fail fast, at startup, on bad configuration. A missing AZURE_CLIENT_SECRET
 * discovered at 3am on the first embed request is a much worse outcome than a
 * process that refuses to boot.
 */
const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // ---- Database -----------------------------------------------------------
  DATABASE_URL: z.string().url(),
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
  DATABASE_SSL: z.enum(['true', 'false']).default('false'),

  // ---- Identity provider --------------------------------------------------
  // 'local'  — email + password against the users table
  // 'entra'  — Microsoft Entra ID via OIDC authorization code + PKCE
  // 'both'   — either; useful while migrating, and for break-glass admin access
  //            if the IdP is unreachable.
  AUTH_PROVIDER: z.enum(['local', 'entra', 'both']).default('local'),

  // ---- Entra ID OIDC (only required when AUTH_PROVIDER includes entra) ----
  // A SEPARATE app registration from the Power BI service principal. That one
  // is a confidential client acting as itself; this one signs users in. Sharing
  // one registration would give the sign-in app the service principal's Power BI
  // access.
  ENTRA_OIDC_TENANT_ID: z.string().min(1).optional(),
  ENTRA_OIDC_CLIENT_ID: z.string().uuid().optional(),
  ENTRA_OIDC_CLIENT_SECRET: z.string().min(1).optional(),
  ENTRA_OIDC_REDIRECT_URI: z.string().url().optional(),
  // Where to send the browser after a successful sign-in.
  ENTRA_POST_LOGIN_REDIRECT: z.string().url().default('http://localhost:3000/dashboard'),
  // Override the discovery document. Exists so tests can point at a stub
  // issuer; in production leave it unset and it is derived from the tenant.
  ENTRA_OIDC_DISCOVERY_URL: z.string().url().optional(),
  // Create a portal user on first successful sign-in. Off by default: with it
  // on, anyone in the tenant gets an account (with no roles, so no reports).
  ENTRA_AUTO_PROVISION: z.enum(['true', 'false']).default('false'),
  // Link an Entra identity to an EXISTING local account matching on email.
  // Off by default and deliberately so — see entraUsers.service.ts.
  ENTRA_LINK_BY_EMAIL: z.enum(['true', 'false']).default('false'),

  // ---- Portal auth (JWT) --------------------------------------------------
  // Must be >=32 bytes of entropy. Generate: openssl rand -base64 48
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_ISSUER: z.string().default('powerbi-portal'),
  JWT_AUDIENCE: z.string().default('powerbi-portal-api'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),        // 15 min
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 14),

  // ---- Microsoft Entra ID service principal -------------------------------
  AZURE_TENANT_ID: z.string().uuid('AZURE_TENANT_ID must be a GUID'),
  AZURE_CLIENT_ID: z.string().uuid('AZURE_CLIENT_ID must be a GUID'),
  AZURE_CLIENT_SECRET: z.string().min(1),
  AZURE_AUTHORITY_HOST: z.string().url().default('https://login.microsoftonline.com'),

  // ---- Power BI -----------------------------------------------------------
  POWERBI_API_BASE: z.string().url().default('https://api.powerbi.com/v1.0/myorg'),
  POWERBI_SCOPE: z.string().default('https://analysis.windows.net/powerbi/api/.default'),
  // Default workspace; individual reports carry their own workspace_id.
  POWERBI_WORKSPACE_ID: z.string().uuid().optional(),

  // ---- Caching ------------------------------------------------------------
  // Refresh this many seconds before actual expiry, both server- and client-side.
  TOKEN_REFRESH_SKEW_SECONDS: z.coerce.number().int().nonnegative().default(300),
  REDIS_URL: z.string().url().optional(),

  // ---- CORS / cookies -----------------------------------------------------
  // How many proxy hops to trust for req.ip, which both rate limiters and the
  // audit log depend on. 'false' (the default) is the only safe value when the
  // app is reachable directly: any other setting lets a client forge
  // X-Forwarded-For. Set to the hop count ('1' behind a single ALB/nginx), a
  // CIDR, or 'true' only when something upstream always overwrites the header.
  TRUST_PROXY: z.string().default('false'),

  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: z.enum(['true', 'false']).default('false'),
});

/**
 * Entra settings are conditionally required: demanding them when AUTH_PROVIDER
 * is 'local' would force every deployment to carry OIDC config it never uses,
 * while accepting a half-configured 'entra' deployment would fail at the first
 * sign-in attempt instead of at boot.
 */
const withEntraChecks = schema.superRefine((cfg, ctx) => {
  if (cfg.AUTH_PROVIDER === 'local') return;

  for (const key of [
    'ENTRA_OIDC_TENANT_ID',
    'ENTRA_OIDC_CLIENT_ID',
    'ENTRA_OIDC_CLIENT_SECRET',
    'ENTRA_OIDC_REDIRECT_URI',
  ] as const) {
    if (!cfg[key]) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [key],
        message: `required when AUTH_PROVIDER is "${cfg.AUTH_PROVIDER}"`,
      });
    }
  }
});

const parsed = withEntraChecks.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues
    .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('\n');
  // eslint-disable-next-line no-console
  console.error(`Invalid environment configuration:\n${issues}\n\nSee .env.example.`);
  process.exit(1);
}

const raw = parsed.data;

export const config = {
  env: raw.NODE_ENV,
  isProduction: raw.NODE_ENV === 'production',
  port: raw.PORT,
  logLevel: raw.LOG_LEVEL,

  db: {
    url: raw.DATABASE_URL,
    poolMax: raw.DATABASE_POOL_MAX,
    ssl: raw.DATABASE_SSL === 'true',
  },

  jwt: {
    secret: raw.JWT_SECRET,
    issuer: raw.JWT_ISSUER,
    audience: raw.JWT_AUDIENCE,
    accessTtlSeconds: raw.ACCESS_TOKEN_TTL_SECONDS,
    refreshTtlSeconds: raw.REFRESH_TOKEN_TTL_SECONDS,
  },

  auth: {
    provider: raw.AUTH_PROVIDER,
    localEnabled: raw.AUTH_PROVIDER !== 'entra',
    entraEnabled: raw.AUTH_PROVIDER !== 'local',
  },

  entra: {
    tenantId: raw.ENTRA_OIDC_TENANT_ID ?? '',
    clientId: raw.ENTRA_OIDC_CLIENT_ID ?? '',
    clientSecret: raw.ENTRA_OIDC_CLIENT_SECRET ?? '',
    redirectUri: raw.ENTRA_OIDC_REDIRECT_URI ?? '',
    postLoginRedirect: raw.ENTRA_POST_LOGIN_REDIRECT,
    discoveryUrl:
      raw.ENTRA_OIDC_DISCOVERY_URL ??
      `https://login.microsoftonline.com/${raw.ENTRA_OIDC_TENANT_ID}/v2.0/.well-known/openid-configuration`,
    autoProvision: raw.ENTRA_AUTO_PROVISION === 'true',
    linkByEmail: raw.ENTRA_LINK_BY_EMAIL === 'true',
  },

  azure: {
    tenantId: raw.AZURE_TENANT_ID,
    clientId: raw.AZURE_CLIENT_ID,
    clientSecret: raw.AZURE_CLIENT_SECRET,
    authority: `${raw.AZURE_AUTHORITY_HOST.replace(/\/$/, '')}/${raw.AZURE_TENANT_ID}`,
    scope: raw.POWERBI_SCOPE,
  },

  powerbi: {
    apiBase: raw.POWERBI_API_BASE.replace(/\/$/, ''),
    defaultWorkspaceId: raw.POWERBI_WORKSPACE_ID,
  },

  cache: {
    refreshSkewSeconds: raw.TOKEN_REFRESH_SKEW_SECONDS,
    redisUrl: raw.REDIS_URL,
  },

  http: {
    trustProxy: raw.TRUST_PROXY,
    corsOrigins: raw.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    cookieDomain: raw.COOKIE_DOMAIN,
    cookieSecure: raw.COOKIE_SECURE === 'true',
  },
} as const;

export type AppConfig = typeof config;
