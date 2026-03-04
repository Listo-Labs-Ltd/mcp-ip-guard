import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseCidr, parseIpv4, ipMatchesRange } from './cidr.js';
import type { ParsedRange } from './cidr.js';
import { OPENAI_IP_RANGES } from './ranges.js';
import { AZURE_IP_RANGES } from './azure-ranges.js';
import { FASTLY_IP_RANGES } from './fastly-ranges.js';
import { ANTHROPIC_IP_RANGES } from './anthropic-ranges.js';

// ── Types ────────────────────────────────────────────────────────────────────

/** Configuration for creating an IP guard. */
export interface IpGuardOptions {
  /**
   * Include OpenAI/ChatGPT egress IP ranges in the allowlist.
   * @default true
   */
  includeOpenAiRanges?: boolean;

  /**
   * Include Microsoft Azure public cloud IP ranges in the allowlist.
   * Enable this when your MCP server is connected to ChatGPT in
   * developer mode, where requests route through Azure infrastructure
   * rather than the dedicated OpenAI egress IPs.
   * @default false
   */
  includeAzureRanges?: boolean;

  /**
   * Include Fastly CDN public IP ranges in the allowlist.
   * OpenAI uses Fastly as their edge CDN. In ChatGPT developer mode,
   * requests may arrive from Fastly edge IPs (e.g. 140.248.x.x) rather
   * than the dedicated OpenAI egress ranges.
   * @default false
   */
  includeFastlyRanges?: boolean;

  /**
   * Include Anthropic (Claude) outbound IP ranges in the allowlist.
   * Enable this when your MCP server receives tool calls from Claude.
   * @default false
   */
  includeAnthropicRanges?: boolean;

  /**
   * Additional CIDR ranges or single IPs to allow.
   * Accepts any valid CIDR notation (e.g. "10.0.0.0/8", "192.168.1.1/32").
   * Single IPs without a prefix are treated as /32.
   */
  additionalRanges?: string[];

  /**
   * Allow localhost (127.0.0.1, ::ffff:127.0.0.1, ::1) when NODE_ENV !== "production".
   * @default true
   */
  allowLocalhostInDev?: boolean;

  /**
   * Log blocked IPs to stdout.
   * @default false
   */
  debug?: boolean;

  /**
   * Optional callback invoked when a request is blocked.
   * Useful for recording telemetry or custom logging.
   */
  onBlocked?: (clientIp: string, path: string) => void;
}

/** Result of checking a request against the guard. */
export interface GuardResult {
  allowed: boolean;
  clientIp: string;
}

/** The IP guard instance returned by `createIpGuard`. */
export interface IpGuard {
  /** Check if a raw IP address string is in the allowlist. */
  isAllowed: (ip: string) => boolean;

  /**
   * Extract the client IP from an HTTP request.
   * Respects X-Forwarded-For (rightmost entry, set by trusted proxy).
   */
  getClientIp: (req: IncomingMessage) => string;

  /**
   * Full request gate: extracts IP, checks the allowlist, and if blocked
   * writes a 403 response and returns `{ allowed: false }`.
   * If allowed, does nothing to the response and returns `{ allowed: true }`.
   */
  handleRequest: (req: IncomingMessage, res: ServerResponse) => GuardResult;

  /** The total number of parsed CIDR ranges in the allowlist. */
  rangeCount: number;
}

// ── Implementation ───────────────────────────────────────────────────────────

/**
 * Normalise a CIDR string: if it has no `/prefix`, treat it as /32.
 */
function normaliseCidr(cidr: string): string {
  return cidr.includes('/') ? cidr : `${cidr}/32`;
}

/**
 * Extract the client IP from an incoming HTTP request.
 *
 * Uses the **rightmost** IP in the `X-Forwarded-For` header because that is
 * the entry added by the trusted edge proxy (e.g. Railway, Cloudflare) and
 * cannot be spoofed by the client.
 */
function getClientIp(req: IncomingMessage): string {
  const rawForwarded = req.headers['x-forwarded-for'];
  const forwarded = Array.isArray(rawForwarded)
    ? rawForwarded.join(', ')
    : rawForwarded;

  if (forwarded) {
    const ips = forwarded
      .split(',')
      .map((ip) => ip.trim())
      .filter(Boolean);
    const clientIp = ips[ips.length - 1];
    if (clientIp) return clientIp;
  }

  return req.socket.remoteAddress ?? 'unknown';
}

/**
 * Create an IP allowlist guard for protecting MCP server endpoints.
 *
 * By default the guard includes all known OpenAI/ChatGPT egress IPs.
 * You can extend the allowlist with `additionalRanges`.
 *
 * @example
 * ```ts
 * import { createIpGuard } from '@listo-ai/mcp-ip-guard';
 *
 * const guard = createIpGuard();
 *
 * // In your HTTP handler:
 * const { allowed, clientIp } = guard.handleRequest(req, res);
 * if (!allowed) return; // 403 already sent
 * ```
 *
 * @example
 * ```ts
 * // With custom ranges and telemetry hook
 * const guard = createIpGuard({
 *   additionalRanges: ['10.0.0.0/8', '192.168.1.100'],
 *   onBlocked: (ip, path) => {
 *     observability.recordBusinessEvent('ip_blocked', {
 *       properties: { ip, path },
 *       status: 'error',
 *       category: 'system',
 *     });
 *   },
 * });
 * ```
 */
export function createIpGuard(options: IpGuardOptions = {}): IpGuard {
  const {
    includeOpenAiRanges = true,
    includeAzureRanges = false,
    includeFastlyRanges = false,
    includeAnthropicRanges = false,
    additionalRanges = [],
    allowLocalhostInDev = true,
    debug = false,
    onBlocked,
  } = options;

  // Build the full list of CIDR strings
  const allRanges: string[] = [];
  if (includeOpenAiRanges) {
    allRanges.push(...OPENAI_IP_RANGES);
  }
  if (includeAzureRanges) {
    allRanges.push(...AZURE_IP_RANGES);
  }
  if (includeFastlyRanges) {
    allRanges.push(...FASTLY_IP_RANGES);
  }
  if (includeAnthropicRanges) {
    allRanges.push(...ANTHROPIC_IP_RANGES);
  }
  for (const r of additionalRanges) {
    allRanges.push(normaliseCidr(r));
  }

  // Pre-parse all ranges for fast bitwise lookup
  const parsedRanges: ParsedRange[] = allRanges
    .map(parseCidr)
    .filter((r): r is ParsedRange => r !== null);

  function isAllowed(ip: string): boolean {
    // Handle IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1, ::ffff:52.173.123.5)
    let ipv4 = ip;
    if (ip.startsWith('::ffff:')) {
      ipv4 = ip.slice(7);
    }

    // Localhost bypass for development (checked after ::ffff: stripping so
    // that both 127.0.0.1 and ::ffff:127.0.0.1 are handled correctly)
    if (allowLocalhostInDev && process.env.NODE_ENV !== 'production') {
      if (ipv4 === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
        return true;
      }
    }

    const ipNum = parseIpv4(ipv4);
    if (ipNum === null) {
      return false; // Invalid IPv4 → deny
    }

    for (const range of parsedRanges) {
      if (ipMatchesRange(ipNum, range)) {
        return true;
      }
    }
    return false;
  }

  function handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
  ): GuardResult {
    const clientIp = getClientIp(req);

    if (!isAllowed(clientIp)) {
      const path = req.url ?? 'unknown';

      if (debug) {
        console.log(`[mcp-ip-guard] Blocked IP: ${clientIp} on ${path}`);
      }

      try {
        onBlocked?.(clientIp, path);
      } catch {
        // Never let a callback error suppress the 403 response
      }

      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Access denied',
          message: 'This endpoint only accepts requests from allowed IPs',
        }),
      );

      return { allowed: false, clientIp };
    }

    return { allowed: true, clientIp };
  }

  return {
    isAllowed,
    getClientIp,
    handleRequest,
    rangeCount: parsedRanges.length,
  };
}
