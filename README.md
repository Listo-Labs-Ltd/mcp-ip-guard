# @listo-ai/mcp-ip-guard

IP allowlist guard for MCP servers. Ships with OpenAI/ChatGPT egress IP ranges and Microsoft Azure public cloud ranges for ChatGPT developer mode. Supports custom CIDR ranges. Zero production dependencies.

## Install

```bash
npm install @listo-ai/mcp-ip-guard
```

## Quick Start

```typescript
import { createIpGuard } from '@listo-ai/mcp-ip-guard';

// Creates a guard with all OpenAI/ChatGPT IPs pre-loaded
const guard = createIpGuard();

// In your HTTP handler:
const { allowed, clientIp } = guard.handleRequest(req, res);
if (!allowed) return; // 403 already sent
```

## Options

```typescript
const guard = createIpGuard({
  // Include OpenAI/ChatGPT egress IPs (default: true)
  includeOpenAiRanges: true,

  // Include Azure public cloud IPs for ChatGPT developer mode (default: false)
  includeAzureRanges: false,

  // Add your own IPs/CIDR ranges
  additionalRanges: [
    '10.0.0.0/8',        // CIDR range
    '192.168.1.100',     // Single IP (treated as /32)
  ],

  // Allow localhost in non-production (default: true)
  allowLocalhostInDev: true,

  // Log blocked IPs to stdout (default: false)
  debug: false,

  // Hook for telemetry / custom logging
  onBlocked: (clientIp, path) => {
    console.log(`Blocked ${clientIp} on ${path}`);
  },
});
```

## API

### `createIpGuard(options?): IpGuard`

Creates a new guard instance.

### `guard.isAllowed(ip: string): boolean`

Check if a raw IP address string is in the allowlist.

### `guard.getClientIp(req: IncomingMessage): string`

Extract the client IP from an HTTP request. Uses the rightmost `X-Forwarded-For` entry (trusted proxy IP, cannot be spoofed).

### `guard.handleRequest(req, res): GuardResult`

Full request gate. Extracts IP, checks allowlist. If blocked, sends a `403` JSON response automatically. Returns `{ allowed: boolean, clientIp: string }`.

### `guard.rangeCount: number`

Total number of parsed CIDR ranges in the allowlist.

### `OPENAI_IP_RANGES: readonly string[]`

The raw list of OpenAI/ChatGPT egress IP ranges in CIDR notation. Useful if you need to inspect or use them directly.

### `AZURE_IP_RANGES: readonly string[]`

Microsoft Azure public cloud IPv4 ranges (10,360 CIDRs). Used when ChatGPT developer mode routes requests through Azure infrastructure instead of dedicated OpenAI egress IPs.

### Low-level utilities

```typescript
import { parseCidr, parseIpv4, ipMatchesRange } from '@listo-ai/mcp-ip-guard';
```

## Usage with MCP Server

```typescript
import http from 'node:http';
import { createIpGuard } from '@listo-ai/mcp-ip-guard';

const guard = createIpGuard({
  debug: process.env.TELEMETRY_DEBUG === 'true',
  onBlocked: (ip, path) => {
    observability.recordBusinessEvent('ip_blocked', {
      properties: { ip, path },
      status: 'error',
      category: 'system',
    });
  },
});

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host}`);

  // Only guard MCP endpoints
  if (url.pathname === '/mcp' || url.pathname === '/mcp/messages') {
    const { allowed } = guard.handleRequest(req, res);
    if (!allowed) return;
  }

  // ... handle request
});
```

## ChatGPT Developer Mode

When connecting an MCP server directly to ChatGPT in developer mode, requests may come from Azure infrastructure IPs rather than the dedicated OpenAI egress IPs. Enable `includeAzureRanges` to allow these:

```typescript
const guard = createIpGuard({
  includeAzureRanges: true,
});
```

This adds ~10,360 Azure IPv4 CIDR ranges to the allowlist. Only enable this when you need developer-mode compatibility — in production with ChatGPT's public integration, the default OpenAI ranges are sufficient.

## Environment

- `NODE_ENV` — When set to `"production"`, localhost is blocked (unless `allowLocalhostInDev` is `false`).

## IP Ranges Sources

- **OpenAI** — Published egress IPs (2026-02-21). Includes /28, /26, and /32 entries covering all ChatGPT outbound traffic to MCP servers.
- **Azure** — Microsoft Azure Service Tags – Public Cloud (2026-03-02). The `AzureCloud` service tag with 10,360 IPv4 CIDR ranges covering all Azure datacenter egress.

## License

MIT
