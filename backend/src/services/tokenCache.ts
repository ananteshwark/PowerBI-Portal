import crypto from 'node:crypto';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';

/**
 * Embed-token cache.
 *
 * Power BI throttles GenerateToken, and a dashboard page can easily fire
 * several embed requests on first paint (multiple visuals, React strict-mode
 * double effects, a user hammering refresh). Two mechanisms keep upstream
 * calls proportional to real demand:
 *
 *   1. CACHING     — a token is reused until `refreshSkewSeconds` before it
 *                    expires, so one user viewing one report costs one
 *                    GenerateToken call per ~55 minutes, not per page load.
 *   2. SINGLE-FLIGHT — concurrent misses on the same key await one shared
 *                    promise instead of each issuing their own request.
 *
 * The cache key includes a hash of the effective identity. If a user's RLS
 * roles change, the key changes, and the stale (over-permissive) token can
 * never be served. That property is why the identity is hashed into the key
 * rather than merely stored alongside it.
 */

export interface CachedEmbedToken {
  token: string;
  embedUrl: string;
  reportId: string;
  /** Epoch ms — real Power BI expiry, not the skewed one. */
  expiresAtMs: number;
  rlsUsername: string | null;
  rlsRoles: string[];
}

interface CacheStore {
  get(key: string): Promise<CachedEmbedToken | null>;
  set(key: string, value: CachedEmbedToken, ttlSeconds: number): Promise<void>;
  deleteByPrefix(prefix: string): Promise<void>;
}

// ---------------------------------------------------------------- in-memory
class MemoryStore implements CacheStore {
  #map = new Map<string, { value: CachedEmbedToken; expiresAtMs: number }>();

  async get(key: string): Promise<CachedEmbedToken | null> {
    const hit = this.#map.get(key);
    if (!hit) return null;
    if (hit.expiresAtMs <= Date.now()) {
      this.#map.delete(key);
      return null;
    }
    return hit.value;
  }

  async set(key: string, value: CachedEmbedToken, ttlSeconds: number): Promise<void> {
    this.#map.set(key, { value, expiresAtMs: Date.now() + ttlSeconds * 1000 });
  }

  async deleteByPrefix(prefix: string): Promise<void> {
    for (const key of this.#map.keys()) {
      if (key.startsWith(prefix)) this.#map.delete(key);
    }
  }

  /** Drop expired entries so an idle process does not grow without bound. */
  sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.#map) {
      if (entry.expiresAtMs <= now) this.#map.delete(key);
    }
  }
}

// -------------------------------------------------------------------- redis
/**
 * Enable by setting REDIS_URL. Required as soon as you run more than one
 * backend instance: with the memory store, N instances means N× the
 * GenerateToken calls and no way to invalidate a user's tokens fleet-wide.
 */
class RedisStore implements CacheStore {
  #client: import('ioredis').Redis;

  constructor(client: import('ioredis').Redis) {
    this.#client = client;
  }

  async get(key: string): Promise<CachedEmbedToken | null> {
    const raw = await this.#client.get(key);
    return raw ? (JSON.parse(raw) as CachedEmbedToken) : null;
  }

  async set(key: string, value: CachedEmbedToken, ttlSeconds: number): Promise<void> {
    await this.#client.set(key, JSON.stringify(value), 'EX', Math.max(1, ttlSeconds));
  }

  async deleteByPrefix(prefix: string): Promise<void> {
    // SCAN, not KEYS — KEYS blocks the Redis event loop.
    let cursor = '0';
    do {
      const [next, keys] = await this.#client.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 200);
      cursor = next;
      if (keys.length) await this.#client.del(...keys);
    } while (cursor !== '0');
  }
}

let store: CacheStore = new MemoryStore();

export async function initTokenCache(): Promise<void> {
  if (!config.cache.redisUrl) {
    // Sweep every 5 minutes; cheap, and bounds memory on long-running processes.
    setInterval(() => (store as MemoryStore).sweep?.(), 5 * 60_000).unref();
    logger.info('Embed token cache: in-memory (single instance only)');
    return;
  }
  try {
    const { default: Redis } = await import('ioredis');
    const client = new Redis(config.cache.redisUrl, { maxRetriesPerRequest: 2 });
    client.on('error', (err) => logger.error({ err }, 'Redis error'));
    store = new RedisStore(client);
    logger.info('Embed token cache: Redis');
  } catch (err) {
    logger.error({ err }, 'REDIS_URL set but ioredis unavailable — falling back to in-memory cache');
  }
}

// ------------------------------------------------------------- key helpers
export function identityFingerprint(username: string | null, roles: string[]): string {
  // Sorted so role ordering does not fragment the cache.
  const canonical = JSON.stringify({ u: username, r: [...roles].sort() });
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

const keyFor = (userId: string, reportId: string, fingerprint: string) =>
  `embed:${userId}:${reportId}:${fingerprint}`;

const userPrefix = (userId: string) => `embed:${userId}:`;

// ----------------------------------------------------------- single-flight
const inFlight = new Map<string, Promise<CachedEmbedToken>>();

export async function getOrCreateEmbedToken(
  args: { userId: string; reportId: string; fingerprint: string; bypassCache?: boolean },
  factory: () => Promise<CachedEmbedToken>,
): Promise<{ value: CachedEmbedToken; cached: boolean }> {
  const key = keyFor(args.userId, args.reportId, args.fingerprint);

  if (args.bypassCache) {
    // The caller is telling us the cached token was rejected downstream, so
    // drop it before minting — otherwise a concurrent reader keeps serving the
    // bad value until it expires.
    await store.deleteByPrefix(key);
  } else {
    const hit = await store.get(key);
    if (hit) return { value: hit, cached: true };

    const pending = inFlight.get(key);
    if (pending) return { value: await pending, cached: true };
  }

  const promise = (async () => {
    const value = await factory();
    // Expire the cache entry `skew` seconds early so a served token always has
    // enough life left for the client to use and then refresh it.
    const ttl = Math.floor((value.expiresAtMs - Date.now()) / 1000) - config.cache.refreshSkewSeconds;
    if (ttl > 0) await store.set(key, value, ttl);
    return value;
  })();

  inFlight.set(key, promise);
  try {
    return { value: await promise, cached: false };
  } finally {
    inFlight.delete(key);
  }
}

/**
 * Drop every cached token for a user. Call on logout, on role change, and on
 * deactivation — otherwise a revoked user keeps a working embed token for up
 * to an hour.
 */
export async function invalidateUser(userId: string): Promise<void> {
  await store.deleteByPrefix(userPrefix(userId));
  for (const key of inFlight.keys()) {
    if (key.startsWith(userPrefix(userId))) inFlight.delete(key);
  }
}
