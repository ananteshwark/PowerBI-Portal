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
  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: z.enum(['true', 'false']).default('false'),
});

const parsed = schema.safeParse(process.env);

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
    corsOrigins: raw.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    cookieDomain: raw.COOKIE_DOMAIN,
    cookieSecure: raw.COOKIE_SECURE === 'true',
  },
} as const;

export type AppConfig = typeof config;
