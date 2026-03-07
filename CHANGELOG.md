# Changelog — legionforge-guardian

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [semantic versioning](https://semver.org/).

---

## [Unreleased]

### Fixed
- Uvicorn now binds to `0.0.0.0` by default (was `127.0.0.1`) — required for Docker port
  mapping to work from the host. Configurable via `GUARDIAN_HOST` env var.
- `GUARDIAN_PORT` env var now controls both the listening port and the Docker port mapping.
  Default remains `9766`. Override: `GUARDIAN_PORT=9767 docker compose up -d`.
- Docker healthcheck reads `GUARDIAN_PORT` from environment.

---

## [0.1.0] — 2026-03-06

Initial public release, extracted from [LegionForge](https://github.com/LegionForge/LegionForge).

### Added

**Seven-check enforcement pipeline (`/check` endpoint):**
- Check 0: JWT task token ACL — per-tool scope enforcement
- Check 1: Tool registry — unregistered and revoked tools are halted (10s revocation propagation)
- Check 2: Capability boundary — forbidden action/tool denylist (7 blocked capabilities)
- Check 3: Destructive pattern detection — 9 regex families covering credential probing,
  shell injection, bulk exfiltration, data staging, reconnaissance, privilege escalation,
  system path probing, SSRF targeting, and self-probe attacks
- Check 4: Sequence contracts — novel tool call sequences are sandboxed
- Check 5: Hash integrity — description and schema hash verification against registration baseline
- Check 6: Adaptive rules — hot-reloaded CAPABILITY_BLOCK, INJECTION_PATTERN, SEQUENCE_BLOCK
  rules from the `threat_rules` database table (10s cache TTL)

**Audit log:**
- SHA-256 hash chain on every check result — tamper-evident, verifiable offline
- Genesis sentinel anchoring for chain initialization

**Threat event logging:**
- Async `_write_threat_event_direct()` on Check 3 HALT (confidence=1.0) and LOG (confidence=0.6) tiers
- `POST /report` endpoint for application-driven threat event ingestion

**SDK (`legionforge_guardian.sdk.client`):**
- `GuardianClient` — async HTTP client for `/check`
- `guardian_check()` — convenience function
- Fail-safe: network error or timeout returns synthetic halt — never fail-open

**Standalone deployment:**
- `init.sql` — self-contained schema (`tool_registry`, `threat_rules`, `agent_profiles`,
  `threat_events`, `audit_log`) using `CREATE TABLE IF NOT EXISTS` — safe against existing databases
- `Dockerfile` — single-image container with canonical entry point
- `docker-compose.yml` — Guardian + PostgreSQL, ready to `docker compose up`
- Environment-variable-only config (no framework-specific dependencies)

**Authentication:**
- Bearer token auth on `/check` and `/rules` (`GUARDIAN_REQUIRE_AUTH=true` by default)
- Constant-time comparison (`hmac.compare_digest`) to prevent timing attacks
- Fail-closed when auth is required but secret is not configured (503, not 200)

**Validated against 24 adversarial attack functions — 0 bypasses.**

### Architecture notes

- No LLM calls on the hot path — all decisions are deterministic
- In-memory caches refreshed every 10s from PostgreSQL
- Decoupled from LegionForge internals via Phase G1 (zero `src.*` imports)
- Installs as `pip install legionforge-guardian` or as an editable local package
