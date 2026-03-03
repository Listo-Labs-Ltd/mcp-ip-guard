/** A pre-parsed CIDR range for fast bitwise matching. */
export interface ParsedRange {
  base: number;
  mask: number;
}

/**
 * Parse a CIDR string (e.g. "52.173.123.0/28") into a base IP
 * (as a 32-bit unsigned number) and subnet mask.
 *
 * Returns `null` for invalid CIDR strings.
 */
export function parseCidr(cidr: string): ParsedRange | null {
  const [ipStr, prefixStr] = cidr.split('/');
  if (!ipStr || !prefixStr) return null;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

  const parts = ipStr.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }

  const ip =
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { base: (ip & mask) >>> 0, mask };
}

/**
 * Parse an IPv4 address string into a 32-bit unsigned number.
 * Returns `null` for invalid addresses.
 */
export function parseIpv4(ip: string): number | null {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return (
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  );
}

/**
 * Check if a 32-bit IP number falls within a parsed CIDR range.
 */
export function ipMatchesRange(ipNum: number, range: ParsedRange): boolean {
  return (ipNum & range.mask) >>> 0 === range.base;
}
