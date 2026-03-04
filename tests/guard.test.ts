import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createIpGuard } from '../src/guard.js';
import type { IncomingMessage, ServerResponse } from 'node:http';

function mockReq(
  remoteAddress: string,
  xForwardedFor?: string | string[],
): IncomingMessage {
  return {
    headers: xForwardedFor ? { 'x-forwarded-for': xForwardedFor } : {},
    socket: { remoteAddress },
    url: '/mcp',
  } as unknown as IncomingMessage;
}

function mockRes() {
  const res = {
    writeHead: vi.fn(),
    end: vi.fn(),
  };
  return res as unknown as ServerResponse & {
    writeHead: ReturnType<typeof vi.fn>;
    end: ReturnType<typeof vi.fn>;
  };
}

describe('createIpGuard', () => {
  describe('isAllowed', () => {
    it('allows an IP within an OpenAI /28 range', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      // 52.173.123.0/28 → .0 through .15
      expect(guard.isAllowed('52.173.123.5')).toBe(true);
      expect(guard.isAllowed('52.173.123.15')).toBe(true);
    });

    it('blocks an IP outside OpenAI ranges', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('8.8.8.8')).toBe(false);
    });

    it('allows an OpenAI /32 single IP', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('130.33.24.99')).toBe(true);
    });

    it('rejects an IP one off from a /32', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('130.33.24.100')).toBe(false);
    });

    it('allows an IP within a /26 range', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      // 12.129.184.64/26 → .64 through .127
      expect(guard.isAllowed('12.129.184.100')).toBe(true);
    });

    it('handles IPv6-mapped IPv4', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('::ffff:52.173.123.5')).toBe(true);
      expect(guard.isAllowed('::ffff:8.8.8.8')).toBe(false);
    });

    it('denies invalid IP formats', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('not-an-ip')).toBe(false);
      expect(guard.isAllowed('')).toBe(false);
    });

    it('allows additional custom ranges', () => {
      const guard = createIpGuard({
        additionalRanges: ['10.0.0.0/8'],
        allowLocalhostInDev: false,
      });
      expect(guard.isAllowed('10.1.2.3')).toBe(true);
      expect(guard.isAllowed('10.255.255.255')).toBe(true);
    });

    it('allows single IPs without /prefix in additionalRanges', () => {
      const guard = createIpGuard({
        additionalRanges: ['192.168.1.100'],
        allowLocalhostInDev: false,
      });
      expect(guard.isAllowed('192.168.1.100')).toBe(true);
      expect(guard.isAllowed('192.168.1.101')).toBe(false);
    });

    it('can disable OpenAI ranges', () => {
      const guard = createIpGuard({
        includeOpenAiRanges: false,
        additionalRanges: ['10.0.0.0/8'],
        allowLocalhostInDev: false,
      });
      // OpenAI IP should be blocked
      expect(guard.isAllowed('52.173.123.5')).toBe(false);
      // Custom range should still work
      expect(guard.isAllowed('10.1.2.3')).toBe(true);
    });
  });

  describe('Azure ranges', () => {
    it('does not include Azure ranges by default', () => {
      const guard = createIpGuard({
        includeOpenAiRanges: false,
        allowLocalhostInDev: false,
      });
      // 4.144.0.0/17 is an Azure range — should be blocked without the flag
      expect(guard.isAllowed('4.144.0.1')).toBe(false);
    });

    it('allows Azure IPs when includeAzureRanges is true', () => {
      const guard = createIpGuard({
        includeAzureRanges: true,
        allowLocalhostInDev: false,
      });
      // 4.144.0.0/17 covers 4.144.0.0 – 4.144.127.255
      expect(guard.isAllowed('4.144.0.1')).toBe(true);
      expect(guard.isAllowed('4.144.64.10')).toBe(true);
    });

    it('adds Azure ranges on top of OpenAI ranges', () => {
      const guard = createIpGuard({
        includeAzureRanges: true,
        allowLocalhostInDev: false,
      });
      // OpenAI IP still works
      expect(guard.isAllowed('52.173.123.5')).toBe(true);
      // Azure IP also works
      expect(guard.isAllowed('4.144.0.1')).toBe(true);
    });

    it('increases rangeCount when Azure ranges are included', () => {
      const base = createIpGuard();
      const withAzure = createIpGuard({ includeAzureRanges: true });
      // Azure adds ~10,000 ranges
      expect(withAzure.rangeCount).toBeGreaterThan(base.rangeCount + 5000);
    });
  });

  describe('Anthropic ranges', () => {
    it('does not include Anthropic ranges by default', () => {
      const guard = createIpGuard({
        includeOpenAiRanges: false,
        allowLocalhostInDev: false,
      });
      // 160.79.104.0/21 covers 160.79.104.0 – 160.79.111.255
      expect(guard.isAllowed('160.79.106.42')).toBe(false);
    });

    it('allows Anthropic IPs when includeAnthropicRanges is true', () => {
      const guard = createIpGuard({
        includeAnthropicRanges: true,
        allowLocalhostInDev: false,
      });
      expect(guard.isAllowed('160.79.104.1')).toBe(true);
      expect(guard.isAllowed('160.79.111.254')).toBe(true);
    });

    it('adds Anthropic ranges on top of OpenAI ranges', () => {
      const guard = createIpGuard({
        includeAnthropicRanges: true,
        allowLocalhostInDev: false,
      });
      expect(guard.isAllowed('52.173.123.5')).toBe(true); // OpenAI
      expect(guard.isAllowed('160.79.106.42')).toBe(true); // Anthropic
    });

    it('increases rangeCount when Anthropic ranges are included', () => {
      const base = createIpGuard();
      const withAnthropic = createIpGuard({ includeAnthropicRanges: true });
      expect(withAnthropic.rangeCount).toBe(base.rangeCount + 1);
    });
  });

  describe('Fastly ranges', () => {
    it('does not include Fastly ranges by default', () => {
      const guard = createIpGuard({
        includeOpenAiRanges: false,
        allowLocalhostInDev: false,
      });
      // 140.248.67.158 is a Fastly IP — should be blocked without the flag
      expect(guard.isAllowed('140.248.67.158')).toBe(false);
    });

    it('allows Fastly IPs when includeFastlyRanges is true', () => {
      const guard = createIpGuard({
        includeFastlyRanges: true,
        allowLocalhostInDev: false,
      });
      // 140.248.64.0/18 covers 140.248.64.0 – 140.248.127.255
      expect(guard.isAllowed('140.248.67.158')).toBe(true);
      expect(guard.isAllowed('140.248.67.124')).toBe(true);
    });

    it('adds Fastly ranges on top of OpenAI ranges', () => {
      const guard = createIpGuard({
        includeFastlyRanges: true,
        allowLocalhostInDev: false,
      });
      // OpenAI IP still works
      expect(guard.isAllowed('52.173.123.5')).toBe(true);
      // Fastly IP also works
      expect(guard.isAllowed('140.248.67.158')).toBe(true);
    });

    it('increases rangeCount when Fastly ranges are included', () => {
      const base = createIpGuard();
      const withFastly = createIpGuard({ includeFastlyRanges: true });
      expect(withFastly.rangeCount).toBe(base.rangeCount + 19);
    });
  });

  describe('localhost handling', () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('allows localhost in non-production by default', () => {
      process.env.NODE_ENV = 'development';
      const guard = createIpGuard();
      expect(guard.isAllowed('127.0.0.1')).toBe(true);
      expect(guard.isAllowed('::1')).toBe(true);
      expect(guard.isAllowed('localhost')).toBe(true);
    });

    it('blocks localhost in production', () => {
      process.env.NODE_ENV = 'production';
      const guard = createIpGuard();
      expect(guard.isAllowed('127.0.0.1')).toBe(false);
      expect(guard.isAllowed('::1')).toBe(false);
    });

    it('allows IPv6-mapped localhost (::ffff:127.0.0.1) in non-production', () => {
      process.env.NODE_ENV = 'development';
      const guard = createIpGuard();
      expect(guard.isAllowed('::ffff:127.0.0.1')).toBe(true);
    });

    it('blocks localhost when allowLocalhostInDev is false', () => {
      process.env.NODE_ENV = 'development';
      const guard = createIpGuard({ allowLocalhostInDev: false });
      expect(guard.isAllowed('127.0.0.1')).toBe(false);
      expect(guard.isAllowed('::ffff:127.0.0.1')).toBe(false);
    });
  });

  describe('getClientIp', () => {
    it('uses rightmost X-Forwarded-For entry', () => {
      const guard = createIpGuard();
      const req = mockReq('10.0.0.1', '1.1.1.1, 2.2.2.2, 3.3.3.3');
      expect(guard.getClientIp(req)).toBe('3.3.3.3');
    });

    it('joins array X-Forwarded-For headers', () => {
      const guard = createIpGuard();
      const req = mockReq('10.0.0.1', ['1.1.1.1', '2.2.2.2']);
      expect(guard.getClientIp(req)).toBe('2.2.2.2');
    });

    it('falls back to remoteAddress', () => {
      const guard = createIpGuard();
      const req = mockReq('10.0.0.1');
      expect(guard.getClientIp(req)).toBe('10.0.0.1');
    });

    it('uses trustedProxyDepth=2 to skip CDN entry (Railway behind Fastly)', () => {
      // XFF: "openai_ip, fastly_ip" — depth=2 picks openai_ip
      const guard = createIpGuard({ trustedProxyDepth: 2 });
      const req = mockReq('10.0.0.1', '52.173.123.5, 140.248.67.158');
      expect(guard.getClientIp(req)).toBe('52.173.123.5');
    });

    it('uses trustedProxyDepth=1 (default) to get rightmost entry', () => {
      const guard = createIpGuard();
      const req = mockReq('10.0.0.1', '52.173.123.5, 140.248.67.158');
      expect(guard.getClientIp(req)).toBe('140.248.67.158');
    });

    it('clamps trustedProxyDepth to XFF list length', () => {
      const guard = createIpGuard({ trustedProxyDepth: 10 });
      const req = mockReq('10.0.0.1', 'only_one_ip');
      expect(guard.getClientIp(req)).toBe('only_one_ip');
    });
  });

  describe('handleRequest', () => {
    it('returns allowed: true for OpenAI IPs', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      const req = mockReq('', '52.173.123.5');
      const res = mockRes();
      const result = guard.handleRequest(req, res);
      expect(result.allowed).toBe(true);
      expect(result.clientIp).toBe('52.173.123.5');
      expect(res.writeHead).not.toHaveBeenCalled();
    });

    it('sends 403 for blocked IPs', () => {
      const guard = createIpGuard({ allowLocalhostInDev: false });
      const req = mockReq('', '8.8.8.8');
      const res = mockRes();
      const result = guard.handleRequest(req, res);
      expect(result.allowed).toBe(false);
      expect(res.writeHead).toHaveBeenCalledWith(403, {
        'content-type': 'application/json',
      });
    });

    it('calls onBlocked callback for blocked IPs', () => {
      const onBlocked = vi.fn();
      const guard = createIpGuard({
        allowLocalhostInDev: false,
        onBlocked,
      });
      const req = mockReq('', '8.8.8.8');
      const res = mockRes();
      guard.handleRequest(req, res);
      expect(onBlocked).toHaveBeenCalledWith('8.8.8.8', '/mcp');
    });
  });

  describe('rangeCount', () => {
    it('reports correct range count with defaults', () => {
      const guard = createIpGuard();
      // All OpenAI ranges should be parsed
      expect(guard.rangeCount).toBeGreaterThan(100);
    });

    it('includes additional ranges in count', () => {
      const base = createIpGuard();
      const extended = createIpGuard({
        additionalRanges: ['10.0.0.0/8', '172.16.0.0/12'],
      });
      expect(extended.rangeCount).toBe(base.rangeCount + 2);
    });
  });
});
