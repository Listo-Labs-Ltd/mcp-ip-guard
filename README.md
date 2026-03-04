# @listo-ai/mcp-ip-guard

IP allowlist guard for MCP servers. Ships with OpenAI/ChatGPT egress IP ranges, Anthropic/Claude outbound IPs, Fastly CDN ranges, and Microsoft Azure public cloud ranges for ChatGPT developer mode. Supports custom CIDR ranges. Zero production dependencies.

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

  // Include Fastly CDN IPs — OpenAI's edge CDN (default: false)
  includeFastlyRanges: false,

  // Include Anthropic/Claude outbound IPs (default: false)
  includeAnthropicRanges: false,

  // Add your own IPs/CIDR ranges
  additionalRanges: [
    '10.0.0.0/8',        // CIDR range
    '192.168.1.100',     // Single IP (treated as /32)
  ],

  // Allow localhost in non-production (default: true)
  allowLocalhostInDev: true,

  // Number of trusted reverse proxies (default: 1)
  // See "Reverse Proxy Configuration" section below
  trustedProxyDepth: 1,

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

Extract the client IP from an HTTP request. Uses `X-Forwarded-For[-trustedProxyDepth]` to select the IP added by the outermost trusted proxy.

### `guard.handleRequest(req, res): GuardResult`

Full request gate. Extracts IP, checks allowlist. If blocked, sends a `403` JSON response automatically. Returns `{ allowed: boolean, clientIp: string }`.

### `guard.rangeCount: number`

Total number of parsed CIDR ranges in the allowlist.

### `OPENAI_IP_RANGES: readonly string[]`

The raw list of OpenAI/ChatGPT egress IP ranges in CIDR notation. Useful if you need to inspect or use them directly.

### `AZURE_IP_RANGES: readonly string[]`

Microsoft Azure public cloud IPv4 ranges (10,360 CIDRs). Used when ChatGPT developer mode routes requests through Azure infrastructure instead of dedicated OpenAI egress IPs.

### `FASTLY_IP_RANGES: readonly string[]`

Fastly CDN public IPv4 ranges (19 CIDRs). OpenAI uses Fastly as their edge CDN.

### `ANTHROPIC_IP_RANGES: readonly string[]`

Anthropic (Claude) outbound IPv4 ranges. Used when Claude makes MCP tool calls to your server.

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

## Reverse Proxy Configuration

The guard extracts the client IP from the `X-Forwarded-For` header using `trustedProxyDepth` to select the correct entry. **Getting this value wrong means the guard checks the wrong IP** — either a proxy's IP (too shallow) or a spoofable client-supplied IP (too deep).

### How `trustedProxyDepth` works

Each reverse proxy in the chain appends the connecting IP to `X-Forwarded-For`. The guard reads from the **right** side of the header, skipping `trustedProxyDepth` entries from the end:

```
X-Forwarded-For: <client_ip>, <proxy1_ip>, <proxy2_ip>
                  depth=3 ──┘    depth=2 ──┘    depth=1 ──┘
```

### Common deployments

| Platform | Proxy chain | Depth | XFF example |
|---|---|---|---|
| **Railway** | Client → Fastly CDN → Railway proxy → App | **3** | `52.173.123.5, 140.248.67.158, 167.82.233.39` |
| **Cloudflare only** | Client → Cloudflare → App | **2** | `52.173.123.5, 172.70.x.x` |
| **Single LB** | Client → Load Balancer → App | **2** | `52.173.123.5, 10.0.0.1` |
| **Direct** | Client → App | **1** | `52.173.123.5` |

### Railway example

Railway routes all traffic through Fastly CDN and its own internal proxy, producing **3 hops**. With the default `trustedProxyDepth: 1`, the guard would see Railway's proxy IP — not the actual caller:

```typescript
// WRONG — checks Railway's internal proxy IP
const guard = createIpGuard();

// CORRECT — skips Railway proxy + Fastly CDN to reach the real caller
const guard = createIpGuard({ trustedProxyDepth: 3 });
```

### How to find the right depth

Add a temporary debug endpoint to inspect the raw headers:

```typescript
app.get('/debug/ip', (req, res) => {
  res.json({
    xff: req.headers['x-forwarded-for'],
    remote: req.socket.remoteAddress,
    clientIp: guard.getClientIp(req),
  });
});
```

Then `curl https://your-app.example.com/debug/ip` and count the entries in `xff`. The real client IP is the leftmost entry; set `trustedProxyDepth` to the total number of entries to reach it. **Remove this endpoint before going to production.**

## ChatGPT Developer Mode

When connecting an MCP server directly to ChatGPT in developer mode, requests may come from Azure infrastructure IPs or Fastly CDN IPs rather than the dedicated OpenAI egress IPs:

```typescript
const guard = createIpGuard({
  includeAzureRanges: true,   // Azure infrastructure IPs (~10,360 ranges)
  includeFastlyRanges: true,  // Fastly CDN edge IPs (19 ranges)
});
```

Only enable these when you need developer-mode compatibility — in production with ChatGPT's public integration, the default OpenAI ranges are sufficient.

## Claude (Anthropic) MCP Tool Calls

When Claude makes MCP tool calls to your server, requests come from Anthropic's outbound IP range:

```typescript
const guard = createIpGuard({
  includeAnthropicRanges: true,  // Anthropic outbound IPs (160.79.104.0/21)
});
```

To allow both ChatGPT and Claude:

```typescript
const guard = createIpGuard({
  includeOpenAiRanges: true,      // ChatGPT (default)
  includeAnthropicRanges: true,   // Claude
  trustedProxyDepth: 3,           // Railway deployment
});
```

## Environment

- `NODE_ENV` — When set to `"production"`, localhost is blocked (unless `allowLocalhostInDev` is `false`).

## IP Ranges Sources

- **OpenAI** — Published egress IPs (2026-03-03). Includes /28, /26, and /32 entries covering all ChatGPT outbound traffic to MCP servers.
- **Azure** — Microsoft Azure Service Tags – Public Cloud (2026-03-02). The `AzureCloud` service tag with 10,360 IPv4 CIDR ranges covering all Azure datacenter egress.
- **Fastly** — Fastly CDN public IP list (2026-03-04). 19 IPv4 ranges covering all Fastly edge nodes.
- **Anthropic** — Published outbound IPs (2026-03-04). The `160.79.104.0/21` range used for Claude MCP tool calls.

## License

MIT
