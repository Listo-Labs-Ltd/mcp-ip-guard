import { describe, it, expect } from 'vitest';
import { parseCidr, parseIpv4, ipMatchesRange } from '../src/cidr.js';

describe('parseCidr', () => {
  it('parses a /28 range', () => {
    const result = parseCidr('52.173.123.0/28');
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0xfffffff0 >>> 0);
  });

  it('parses a /32 single IP', () => {
    const result = parseCidr('130.33.24.99/32');
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0xffffffff >>> 0);
  });

  it('parses a /26 range', () => {
    const result = parseCidr('12.129.184.64/26');
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0xffffffc0 >>> 0);
  });

  it('parses a /0 range', () => {
    const result = parseCidr('0.0.0.0/0');
    expect(result).not.toBeNull();
    expect(result!.mask).toBe(0);
    expect(result!.base).toBe(0);
  });

  it('returns null for missing prefix', () => {
    expect(parseCidr('1.2.3.4')).toBeNull();
  });

  it('returns null for invalid prefix', () => {
    expect(parseCidr('1.2.3.4/33')).toBeNull();
    expect(parseCidr('1.2.3.4/-1')).toBeNull();
    expect(parseCidr('1.2.3.4/abc')).toBeNull();
  });

  it('returns null for invalid octets', () => {
    expect(parseCidr('256.0.0.0/24')).toBeNull();
    expect(parseCidr('1.2.3/24')).toBeNull();
  });
});

describe('parseIpv4', () => {
  it('parses a valid IPv4 address', () => {
    expect(parseIpv4('192.168.1.1')).toBe(
      ((192 << 24) | (168 << 16) | (1 << 8) | 1) >>> 0,
    );
  });

  it('returns null for invalid addresses', () => {
    expect(parseIpv4('not-an-ip')).toBeNull();
    expect(parseIpv4('256.1.1.1')).toBeNull();
    expect(parseIpv4('1.2.3')).toBeNull();
    expect(parseIpv4('')).toBeNull();
  });
});

describe('ipMatchesRange', () => {
  it('matches an IP within a /28 range', () => {
    const range = parseCidr('52.173.123.0/28')!;
    const ip = parseIpv4('52.173.123.5')!;
    expect(ipMatchesRange(ip, range)).toBe(true);
  });

  it('rejects an IP outside a /28 range', () => {
    const range = parseCidr('52.173.123.0/28')!;
    const ip = parseIpv4('52.173.123.16')!;
    expect(ipMatchesRange(ip, range)).toBe(false);
  });

  it('matches a /32 exact IP', () => {
    const range = parseCidr('130.33.24.99/32')!;
    const ip = parseIpv4('130.33.24.99')!;
    expect(ipMatchesRange(ip, range)).toBe(true);
  });

  it('rejects a /32 mismatch', () => {
    const range = parseCidr('130.33.24.99/32')!;
    const ip = parseIpv4('130.33.24.100')!;
    expect(ipMatchesRange(ip, range)).toBe(false);
  });
});
