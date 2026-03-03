export { createIpGuard } from './guard.js';
export type {
  IpGuardOptions,
  IpGuard,
  GuardResult,
} from './guard.js';

export { OPENAI_IP_RANGES } from './ranges.js';
export { AZURE_IP_RANGES } from './azure-ranges.js';

export { parseCidr, parseIpv4, ipMatchesRange } from './cidr.js';
export type { ParsedRange } from './cidr.js';
