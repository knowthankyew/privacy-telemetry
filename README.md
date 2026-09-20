# Privacy Telemetry (`@knowthankyew/privacy-telemetry` & `KnowThankYew.Privacy.Telemetry`)

Modular privacy telemetry libraries for the [knowthankyew](https://github.com/knowthankyew) portfolio.

Enforces the **Consumer-Safe, Zero-Fork Enterprise Overlay** standard across client-side web applications (TypeScript/React) and backend services (.NET 10).

---

## The 5 Core Privacy Invariants

1. **Volatile Memory-Only Default & True Burnability:** Runs with zero network egress (`deny`), in-memory telemetry buffer (`memory_only`), zero cloud retention, and complete memory wipe upon triggering "Burn Local Data".
2. **Compile-Time / Opt-In Enterprise Overlay:** External OTLP telemetry requires an explicit build-time or deployment endpoint. Public consumer builds eliminate network telemetry code paths.
3. **Strict Allowlist Invariant:** Attribute sanitizers operate on a strict allowlist (`SAFE_ALLOWLIST_KEYS`), not a denylist. All unrecognized keys are redacted fail-closed as `[REDACTED_BY_DEFAULT_ALLOWLIST]`.
4. **Single Source of Truth for Dynamic Claims (`getPrivacyClaims`):** User-facing UI claims are derived dynamically from active telemetry state. Enterprise builds mount non-dismissible amber banners and update audit affordances.
5. **Supply Chain Attestation & SBOM:** Machine-readable CycloneDX SBOM (`bom.json`) generated on every build with zero high/critical vulnerabilities.

---

## Packages

### 1. `@knowthankyew/privacy-telemetry` (npm)
TypeScript & React package for client-side web applications.
- In-memory circular buffer (`MemoryExporter`)
- Fail-closed attribute sanitization (`createAllowlistSanitizer`, `DEFAULT_SAFE_ALLOWLIST_KEYS`)
- Dynamic honest claims generator (`getPrivacyClaims`)
- Full lifecycle telemetry manager (`TelemetryManager`)
- React hook (`usePrivacyTelemetry`) and audit modal (`PrivacyAuditModal`)

### 2. `KnowThankYew.Privacy.Telemetry` (NuGet)
.NET 10 class library for backend services.
- `IPrivacyTelemetry` interface & `PrivacyTelemetryService`
- Thread-safe in-memory buffer (`ConcurrentQueue`) with burn routine
- Native BCL `ActivitySource` & `Activity` tag sanitization
- Configuration models adhering to [PRIVACY_TELEMETRY_SCHEMA.md](./PRIVACY_TELEMETRY_SCHEMA.md)
- ASP.NET Core dependency injection (`AddPrivacyTelemetry`) & endpoint mapping (`MapPrivacyTelemetryEndpoints`)

---

## License

MIT License. See [LICENSE](./LICENSE) and [NOTICE.md](./NOTICE.md).
