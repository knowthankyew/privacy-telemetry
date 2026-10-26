<!-- diagram-meta
  last-validated: 2026-10-26
  validated-commit: b284e67
  covers: [packages/**]
  generated-by: manual
-->

# Architecture & Invariants Specification: Privacy Telemetry Framework

> Cross-platform telemetry foundation (.NET 10 & TypeScript/React) enforcing the 5 Core Invariants across the `knowthankyew` portfolio.

---

## 1. Executive Summary

`privacy-telemetry` provides the universal telemetry abstraction used by every repository in the `knowthankyew` portfolio. Available as both an npm package (`@knowthankyew/privacy-telemetry`) and a .NET 10 NuGet package (`KnowThankYew.Privacy.Telemetry`), it guarantees that consumer applications operate with zero external telemetry egress by default, sanitizes all spans against fail-closed key allowlists, maintains dynamic runtime honesty for UI claims, and coordinates the portfolio's amnesiac "Hard Burn" state purge.

---

## 2. System Architecture & Component Interactions

### A. Telemetry Processing Pipeline & Trust Boundaries

```mermaid
flowchart TD
    subgraph ClientApplication["Application Context (Consumer Engine / Extension / Service)"]
        EmitSpan["📊 emitSpan(name, attributes)"]
        HandoffAction["🔗 Structured Handoff Protocol<br/><code>handoff.ts</code>"]
        BurnAction["🔥 hardBurnAllData()"]
    end

    subgraph SanitizationLayer["1. Allowlist & Sanitization Layer"]
        AllowlistValidator["🛡️ Allowlist Filter<br/><code>allowlist.ts</code>"]
        AllowlistKeys["📋 SAFE_ALLOWLIST_KEYS<br/><i>(rule_id, duration_ms, error_type)</i>"]
        Redactor["🔒 Fail-Closed Redactor<br/><i>Non-allowlisted &rarr; [REDACTED]</i>"]
    end

    subgraph StorageLayer["2. Buffer & Exporter Layer"]
        CircularBuffer["🧠 In-Memory Ring Buffer<br/><i>(Max 50-100 events, Volatile RAM)</i>"]
        OTLPShim["⚡ Compile-Time OTLP Shim<br/><code>exporter.ts</code>"]
    end

    subgraph ClaimsAndUI["3. Dynamic UI Honesty Layer"]
        ClaimsEngine["⚖️ getPrivacyClaims()<br/><code>claims.ts</code>"]
        GreenBadge["🟢 'Zero Egress' Consumer Badge"]
        AmberBanner["🟡 Persistent Enterprise OTLP Banner"]
        AuditModal["🔍 In-App Privacy Audit Modal"]
    end

    subgraph EnterpriseCollector["Optional Enterprise Destination"]
        OTLPEndpoint["🏢 Enterprise OTel Collector (:4317/:4318)<br/><i>(Disabled by default via dead-code elimination)</i>"]
    end

    %% Data flow
    EmitSpan --> AllowlistValidator
    AllowlistKeys -.-> AllowlistValidator
    AllowlistValidator --> Redactor
    Redactor -->|"Clean Sanitized Span"| CircularBuffer

    %% Build switch
    CircularBuffer -.->|"Enterprise Build Only"| OTLPShim
    OTLPShim -.->|"gRPC / HTTP Protobuf"| OTLPEndpoint

    %% Dynamic claims & UI
    CircularBuffer --> AuditModal
    ClaimsEngine -->|"If Consumer (Memory Only)"| GreenBadge
    ClaimsEngine -->|"If Enterprise (OTLP Active)"| AmberBanner

    %% Nuclear burn
    BurnAction -->|"Drain Buffer & Install Tombstone"| CircularBuffer

    classDef app fill:#0f172a,stroke:#64748b,stroke-width:1px,color:#f8fafc;
    classDef filter fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef buf fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef claims fill:#312e81,stroke:#818cf8,stroke-width:1px,color:#f8fafc;
    classDef ext fill:#78350f,stroke:#f59e0b,stroke-width:1px,stroke-dasharray: 5 5,color:#f8fafc;

    class EmitSpan,HandoffAction,BurnAction app;
    class AllowlistValidator,AllowlistKeys,Redactor filter;
    class CircularBuffer,OTLPShim buf;
    class ClaimsEngine,GreenBadge,AmberBanner,AuditModal claims;
    class OTLPEndpoint ext;
```

### B. Polyglot Architecture & Ecosystem Distribution

```mermaid
flowchart LR
    subgraph Monorepo["privacy-telemetry Repository"]
        CoreTS["packages/privacy-telemetry (TypeScript)"]
        CoreNET["packages/KnowThankYew.Privacy.Telemetry (.NET 10)"]
    end

    subgraph WebConsumers["Web Reality Engines & Extension"]
        Ext["knowthankyew-extension"]
        BoR["bill-of-rights-bot"]
        Care["careCheck"]
        Lease["lease-audit"]
        Paystub["paystub-check"]
        Warranty["warranty-watch"]
    end

    subgraph BackendConsumers[".NET & Service Implementations"]
        Grad["gradcast"]
        Mail["mailStripper"]
        ML["event-driven-ftaas (ml)"]
    end

    subgraph EnterpriseHarness["Enterprise Deployment"]
        SelfHost["enterprise-self-host"]
    end

    CoreTS --> Ext & BoR & Care & Lease & Paystub & Warranty
    CoreNET --> Grad & Mail & ML
    WebConsumers -.->|"Optional OTLP Export"| SelfHost
    BackendConsumers -.->|"Optional OTLP Export"| SelfHost

    classDef mono fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef web fill:#1e293b,stroke:#38bdf8,stroke-width:1px,color:#f8fafc;
    classDef net fill:#312e81,stroke:#818cf8,stroke-width:1px,color:#f8fafc;
    classDef infra fill:#78350f,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;

    class CoreTS,CoreNET mono;
    class Ext,BoR,Care,Lease,Paystub,Warranty web;
    class Grad,Mail,ML net;
    class SelfHost infra;
```

---

## 3. Core Architectural Invariants

| # | Invariant | Description & Enforcement |
|:--|:----------|:--------------------------|
| 1 | **Volatile Memory Default** | Spans are held strictly in an in-memory circular ring buffer; zero disk, database, or network transport in public consumer builds. |
| 2 | **Compile-Time Dead Code Over Runtime Flags** | OTLP network exporters are stripped at build time via bundler tree-shaking unless `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` is present. |
| 3 | **Strict Key Allowlists Beat Denylists** | Any attribute key not explicitly present in `SAFE_ALLOWLIST_KEYS` is redacted to `[REDACTED_BY_DEFAULT_ALLOWLIST]`. |
| 4 | **Single Source of Truth for Honest UI** | `getPrivacyClaims()` evaluates active runtime telemetry modes and dynamically forces UI badges (suppressing false "Zero Egress" claims in enterprise deployments). |
| 5 | **Nuclear Amnesia Purge** | A single invocation of `hardBurnAllData()` drains ring buffers, resets tombstone state, and broadcasts cleanup across active contexts. |

---

## 4. Directory Structure

```
privacy-telemetry/
├── PRIVACY_TELEMETRY_SCHEMA.md  # Portfolio-wide JSON/OTel schema contract
├── packages/
│   ├── privacy-telemetry/       # TypeScript / React npm package
│   │   ├── src/
│   │   │   ├── allowlist.ts     # SAFE_ALLOWLIST_KEYS & attribute redactor
│   │   │   ├── claims.ts        # getPrivacyClaims() dynamic truth engine
│   │   │   ├── exporter.ts      # Compile-time conditional OTLP exporter
│   │   │   ├── handoff.ts       # Structured Handoff protocol for deep links
│   │   │   ├── manager.ts       # TelemetryManager singleton & circular buffer
│   │   │   ├── react/           # React hooks, Context & PrivacyClaimsProvider
│   │   │   └── types.ts         # Telemetry span, claim, and audit types
│   │   ├── tests/               # Vitest unit & invariant suites
│   │   └── vite.config.ts       # Library build configuration
│   └── KnowThankYew.Privacy.Telemetry/ # .NET 10 NuGet package
│       ├── Abstractions/        # IPrivacyTelemetry, ITelemetrySanitizer
│       ├── Configuration/       # PrivacyOptions & OTLP endpoints
│       ├── Core/                # VolatileMemoryBuffer & sanitizer
│       ├── Extensions/         # IServiceCollection dependency injection
│       └── OpenTelemetry/       # ActivitySource & OTel SDK integration
└── tests/                       # Cross-ecosystem integration tests
```
