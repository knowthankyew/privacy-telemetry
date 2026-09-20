# Legal, Privacy, and Third-Party Attribution Notice

**KnowThankYew Privacy Telemetry**  
Copyright © 2026 knowthankyew / The KnowThankYew Contributors  
Repository: [https://github.com/knowthankyew/privacy-telemetry](https://github.com/knowthankyew/privacy-telemetry)

---

## 1. Specification Notice & Privacy Invariants

`@knowthankyew/privacy-telemetry` (TypeScript/React) and `KnowThankYew.Privacy.Telemetry` (.NET 10) provide modular implementations of the **Consumer-Safe, Zero-Fork Enterprise Overlay** standard:

1. **Consumer Default (Safe & Burnable):** Operates air-gapped in volatile memory with a burnable circular buffer. Zero remote network transmission by default.
2. **Compile-Time / Opt-In Enterprise Overlay:** Telemetry egress via OpenTelemetry (OTLP) is strictly opt-in and compile-time bound.
3. **Strict Allowlist Invariant:** Attribute sanitizers operate on a strict allowlist (`SAFE_ALLOWLIST_KEYS`), not a denylist. All unrecognized keys are fail-closed redacted to `[REDACTED_BY_DEFAULT_ALLOWLIST]`.
4. **Single Source of Truth for Privacy Claims:** Dynamic evaluation guarantees that user-facing claims derive from runtime telemetry state, mounting high-contrast banners when external exporters are attached.
5. **CycloneDX SBOM & Fail-Closed Auditing:** Every build generates a machine-readable Software Bill of Materials with zero high/critical vulnerabilities permitted in CI.

---

## 2. Software Bill of Materials (SBOM) & Third-Party Licensure

A complete, machine-readable **CycloneDX Software Bill of Materials** (`bom.json`) is automatically generated on every build in CI using OWASP `@cyclonedx/cdxgen` and attached to release artifacts.

For the root software license terms, refer to [LICENSE](./LICENSE).
