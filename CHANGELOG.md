# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

### [0.1.1](https://github.com/Listo-Labs-Ltd/mcp-ip-guard/compare/v0.1.0...v0.1.1) 2026-03-04

- Fixed CI publish workflow to use correct npm auth secret
- Hardened `onBlocked` callback with try/catch to prevent suppressing 403 responses

### [0.1.0](https://github.com/Listo-Labs-Ltd/mcp-ip-guard/releases/tag/v0.1.0) 2026-03-04

- Initial public release to npm registry
- IP allowlist guard with `createIpGuard()` factory, `isAllowed()`, `getClientIp()`, and `handleRequest()` APIs
- Ships with 170+ OpenAI/ChatGPT egress IP ranges (sourced 2026-02-21)
- Optional Microsoft Azure public cloud IP ranges (~10,360 CIDRs) for ChatGPT developer mode
- Custom CIDR range support via `additionalRanges`
- Localhost bypass in non-production environments (configurable)
- `onBlocked` callback for telemetry/logging (wrapped in try/catch to prevent suppressing 403 responses)
- Zero production dependencies
