/**
 * Normalise a client address into a rate-limiting key.
 *
 * IPv4 addresses are used as-is. IPv6 is collapsed to its /64 prefix, because
 * a single subscriber is routinely handed a whole /64 (often a /48) — keying on
 * the full address would let one attacker draw a fresh budget from every one of
 * 2^64 addresses, which makes an IPv6 rate limit decorative.
 *
 * express-rate-limit grew its own `ipKeyGenerator` helper in v8; this project is
 * on v7, so the logic lives here rather than being imported.
 */
export function ipKey(ip: string | undefined): string {
  if (!ip) return 'unknown';

  // Express may hand back an IPv4-mapped IPv6 address (::ffff:203.0.113.4).
  // Treat those as the IPv4 address they represent.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return mapped[1]!;

  if (!ip.includes(':')) return ip; // plain IPv4

  // Strip a zone index (fe80::1%eth0) before parsing.
  const bare = ip.split('%')[0]!;
  const hextets = expandIpv6(bare);
  if (!hextets) return ip; // unparseable — key on the raw value rather than merge buckets

  return `${hextets.slice(0, 4).join(':')}::/64`;
}

/** Expand an IPv6 address to its 8 hextets, resolving `::`. Null if malformed. */
function expandIpv6(address: string): string[] | null {
  const halves = address.split('::');
  if (halves.length > 2) return null;

  const toParts = (s: string) => (s === '' ? [] : s.split(':'));

  if (halves.length === 2) {
    const head = toParts(halves[0]!);
    const tail = toParts(halves[1]!);
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    return [...head, ...Array<string>(missing).fill('0'), ...tail];
  }

  const parts = toParts(halves[0]!);
  return parts.length === 8 ? parts : null;
}
