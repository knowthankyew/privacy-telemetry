# Shared Privacy & Telemetry Configuration Schema
> Standardized configuration schema across the `knowthankyew` application portfolio (`bill-of-rights-bot`, `careCheck`, `gradcast`, `lease-audit`, `mailStripper`, `ml` / FTaaS, `paystub-check`, `warranty-watch`).

---

## 1. Design Principles

Every application in the portfolio conforms to the **Consumer-Safe, Zero-Fork Enterprise Overlay** standard:
1. **Consumer Default (Safe & Burnable):** Runs with zero network egress (`deny`), in-memory telemetry (`memory_only`), zero cloud retention, and complete memory wipe upon triggering "Burn Local Data".
2. **Enterprise Overlay (Opt-In Observability):** An enterprise operator can attach standard OpenTelemetry collectors (`otlp`) and configure audit retention without modifying source code or maintaining a separate fork.
3. **Strict Allowlist Invariant:** To prevent short clause leaks or sensitive snippets from slipping through under unanticipated key names (e.g., `matchedText`, `snippet`, `excerpt`, `clause_text`), attribute sanitizers operate on a **strict allowlist**, not a denylist. Base runtime keys (`rule_id`, `rule_ids`, `clause_count`, `flagged_count`, `duration_ms`, `job_id`, `status`, `jurisdiction`, `device`, `adapter_size_bytes`, `dataset_hash`, plus core operational metadata registered in `@knowthankyew/privacy-telemetry` / `KnowThankYew.Privacy.Telemetry`) are permitted, and reviewed domain extensions are explicitly registered in Section 8. All unrecognized or arbitrary keys are automatically redacted as `[REDACTED_NOT_IN_ALLOWLIST]`.

---

## 2. Configuration Schema & Environment Mapping

| Configuration Key | Type | Default Value | Environment Variable | Description |
| :--- | :--- | :--- | :--- | :--- |
| `privacy.burn_enabled` | `boolean` | `true` | `KTY_PRIVACY_BURN_ENABLED` / `VITE_PRIVACY_BURN_ENABLED` | When `true`, burn purges all session buffers, memory, and telemetry. When `false`, UI resets but telemetry exporter pipeline remains attached. |
| `privacy.network_egress` | `string` | `"deny"` | `KTY_PRIVACY_NETWORK_EGRESS` | Network egress policy (`deny` \| `allow_otlp` \| `allow_all`). Consumer default is `"deny"`; in `.NET` backend services, when `telemetry.mode` is explicitly set to `"otlp"` with a non-empty `telemetry.otlp_endpoint` and no explicit `privacy.network_egress` override is configured, `network_egress` defaults to `"allow_otlp"`. Enforced via Content Security Policy (CSP) in web apps and network clients in backend services. |
| `telemetry.mode` | `string` | `"memory_only"` | `KTY_TELEMETRY_MODE` / `VITE_TELEMETRY_MODE` | Active telemetry strategy (`memory_only` \| `otlp` \| `disabled`). Browser/TypeScript builds escalate from `memory_only` to `otlp` when an endpoint is configured; `.NET` backend services require explicit `telemetry.mode = "otlp"` (`KTY_TELEMETRY_MODE=otlp` or `Telemetry:Mode=otlp`, which also defaults `privacy.network_egress` to `"allow_otlp"` when an endpoint is present and egress is not explicitly overridden) so ambient `OTEL_EXPORTER_OTLP_ENDPOINT` alone cannot enable consumer egress. |
| `telemetry.otlp_endpoint` | `string?` | `null` | `OTEL_EXPORTER_OTLP_ENDPOINT` / `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP gRPC/HTTP endpoint URL (e.g. `http://otel-collector:4318/v1/traces`). |
| `telemetry.allow_raw_payloads` | `boolean` | `false` | `KTY_TELEMETRY_ALLOW_RAW_PAYLOADS` | Security override permitting raw document bodies in telemetry. **Default `false` must never be bypassed in consumer builds.** |
| `audit.durable` | `boolean` | `false` | `KTY_AUDIT_DURABLE` | When `false`, audit events live solely in memory buffer and wipe upon burn. When `true`, enterprise persists to durable audit log. |

---

## 3. Configuration Formats

### YAML Format (`kty-config.yaml`)

```yaml
version: "1.0"
privacy:
  burn_enabled: true
  network_egress: "deny"

telemetry:
  mode: "memory_only" # "disabled" | "memory_only" | "otlp"
  otlp_endpoint: null
  allow_raw_payloads: false

audit:
  durable: false
```

### JSON Format (`kty-config.json`)

```json
{
  "$schema": "https://knowthankyew.org/schemas/privacy-telemetry-v1.json",
  "version": "1.0",
  "privacy": {
    "burn_enabled": true,
    "network_egress": "deny"
  },
  "telemetry": {
    "mode": "memory_only",
    "otlp_endpoint": null,
    "allow_raw_payloads": false
  },
  "audit": {
    "durable": false
  }
}
```

---

## 4. TypeScript Interface Definition

```typescript
export type TelemetryMode = 'disabled' | 'memory_only' | 'otlp';
export type EgressPolicy = 'deny' | 'allow_otlp' | 'allow_all';

export interface AppPrivacyConfig {
  privacy: {
    burnEnabled: boolean;
    networkEgress: EgressPolicy;
  };
  telemetry: {
    mode: TelemetryMode;
    otlpEndpoint?: string | null;
    allowRawPayloads: boolean;
  };
  audit: {
    durable: boolean;
  };
}

export const DEFAULT_PRIVACY_CONFIG: AppPrivacyConfig = {
  privacy: {
    burnEnabled: true,
    networkEgress: 'deny',
  },
  telemetry: {
    mode: 'memory_only',
    otlpEndpoint: null,
    allowRawPayloads: false,
  },
  audit: {
    durable: false,
  },
};
```

---

## 5. .NET Options Class Definition

```csharp
namespace KnowThankYew.Common.Configuration;

public sealed class PrivacyTelemetryOptions
{
    public const string SectionName = "PrivacyTelemetry";

    public PrivacyOptions Privacy { get; set; } = new();
    public TelemetryOptions Telemetry { get; set; } = new();
    public AuditOptions Audit { get; set; } = new();
}

public sealed class PrivacyOptions
{
    public bool BurnEnabled { get; set; } = true;
    public string NetworkEgress { get; set; } = "deny";
}

public sealed class TelemetryOptions
{
    public string Mode { get; set; } = "memory_only"; // "disabled" | "memory_only" | "otlp"
    public string? OtlpEndpoint { get; set; }
    public bool AllowRawPayloads { get; set; } = false;
}

public sealed class AuditOptions
{
    public bool Durable { get; set; } = false;
}
```

---

## 6. JSON Schema Specification

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "KnowThankYewPrivacyTelemetryConfig",
  "type": "object",
  "properties": {
    "version": { "type": "string", "enum": ["1.0"] },
    "privacy": {
      "type": "object",
      "properties": {
        "burn_enabled": { "type": "boolean", "default": true },
        "network_egress": { "type": "string", "enum": ["deny", "allow_otlp", "allow_all"], "default": "deny" }
      },
      "required": ["burn_enabled", "network_egress"]
    },
    "telemetry": {
      "type": "object",
      "properties": {
        "mode": { "type": "string", "enum": ["disabled", "memory_only", "otlp"], "default": "memory_only" },
        "otlp_endpoint": { "type": ["string", "null"], "format": "uri", "default": null },
        "allow_raw_payloads": { "type": "boolean", "default": false }
      },
      "required": ["mode", "allow_raw_payloads"]
    },
    "audit": {
      "type": "object",
      "properties": {
        "durable": { "type": "boolean", "default": false }
      },
      "required": ["durable"]
    }
  },
  "required": ["version", "privacy", "telemetry", "audit"]
}
```

---

## 7. Single Source of Truth for UI Privacy Claims & Honest Indicators

To prevent false privacy claims sitting adjacent to honest telemetry indicators:

1. **Unified Privacy Claims Function:**
   All client-side applications must derive user-facing claims from a single helper (`getPrivacyClaims(report)`).
   - **Consumer Mode (`isLocalOnlyHonest === true`):** Asserts `100% Client-Side Local Execution • Zero Network Transmission`.
   - **Enterprise Mode (`isLocalOnlyHonest === false`):** Must dynamically adjust all UI copy (dropzones, disclaimers, headers, footers) to reflect operational metadata export while emphasizing that document text is redacted via allowlist.
2. **Prominent Enterprise Differentiation:**
   When built with an external exporter (`otlp`), the UI must render an unmistakable persistent top banner (e.g. `enterprise-persistent-banner`) and an `[ENTERPRISE]` title badge so that non-default builds cannot be mistaken for default consumer builds at a glance.
3. **`NOTICE.md` Compliance:**
   Each repository must maintain a root `NOTICE.md` detailing statutory disclaimers, consumer privacy air-gap invariants, enterprise observability disclosures, and third-party software attribution aligned with the CycloneDX SBOM.

---

## 8. Canonical Telemetry Allowlist Registry & Collector Boundary

The centralized OpenTelemetry Collector (`enterprise-self-host/collector/otel-collector-config.yaml` and Helm `collector-configmap.yaml`) enforces `keep_keys(attributes, [...])` across:
- `trace_statements`: `context: resource` (enforcing `keep_keys` plus OTTL `IsMatch` value validation that redacts non-opaque `service.instance.id` values such as `"employee-alice"` via `set(attributes["service.instance.id"], "[REDACTED_SENSITIVE_VALUE]") where attributes["service.instance.id"] != nil and (not IsString(attributes["service.instance.id"]) or (attributes["service.instance.id"] != "" and attributes["service.instance.id"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["service.instance.id"], "^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{12,64}|(?:hmac|sha256):[0-9a-f]{16,64})$")))`), `context: scope` (stripping arbitrary scope attributes via `keep_keys(attributes, [])` and enforcing approved `instrumentation_scope.name` and semver `instrumentation_scope.version`), `context: span`, and `context: spanevent` (normalizing free-text `status.message`, non-registered `span.name`, and non-registered span event `name` before export), paired with `filter/drop_noncompliant_traces` (`error_mode: propagate`, dropping any span carrying `Len(links) > 0` before batching because Collector v0.118.0 lacks a `spanlink` transform context to strip arbitrary link attributes).
- `metric_statements`: `transform/metrics_preflight` + `filter/drop_noncompliant_metrics` (`error_mode: propagate`) + `transform` across `context: resource` (strips un-allowlisted resource attributes via `keep_keys` and marks non-opaque `service.instance.id` values such as `"employee-alice"` with `set(attributes["kty.resource_overflow"], "drop") where ... not IsMatch(...)` so `filter/drop_noncompliant_metrics` drops the metric before export), `context: scope` (strips arbitrary scope attributes and enforces safe scope `name`/`version`/`schema_url`), `context: metric` (enforces approved metric `name`, empty/unit-safe metadata, and clears free-text `description`), and `context: datapoint` (dropping metrics with non-empty instrumentation scope attributes, exemplar-carrying datapoints guarded via `metric.type != METRIC_DATA_TYPE_SUMMARY and metric.type != METRIC_DATA_TYPE_NONE and Len(exemplars) > 0`, or datapoints carrying unallowlisted attributes instead of collapsing or mutating cumulative/delta streams via stateful aggregation).
- `log_statements` (defense-in-depth): `context: resource`, `context: scope`, and `context: log` (including `body` redaction); only `traces` and `metrics` pipelines are enabled in `service.pipelines`.

Every key permitted at the collector boundary must trace directly to this registry. In addition, both `@knowthankyew/privacy-telemetry` and `KnowThankYew.Privacy.Telemetry` enforce:
- **Closed Registered Event / Span Names** (non-registered names replaced with `[REDACTED_SPAN_NAME]`);
- **Strict `ActivitySource` Allowlist** in .NET (exact default `"KnowThankYew.Privacy.Telemetry"` only, unless extra non-PII source names are explicitly injected via `SafeAllowlist(..., additionalActivitySourceNames)`);
- **Closed Identifier Domains**:
  - `rule_id` / `rule_ids` (up to 50 comma-separated tokens, aggregate `MAX_RULE_IDS_CSV_LENGTH = 3600` chars to accommodate full 71-char `sha256:<64hex>` digests) accept only the registered portfolio rule catalogs (`AR-*`, `ARB-*`, `UNI-*`, `SURV-*`, `US-*`, `EU-*`, `UK-*`, `CA-/FL-/IL-/NY-/TX-/FED-*`, `paystub-check` / `warranty-watch` rule IDs, `state_daily_overtime_<USPS>`, `state_implied_override_<USPS>`, canonical statutory IDs `CA_CIV_1950_5` / `FLSA_EXEMPT_541` / `implied_warranty_disclaimer`) or opaque `hmac:<16..64hex>` / `sha256:<64hex>` digests;
  - `base_model` accepts only the closed approved model catalog (`HuggingFaceTB/SmolLM2-135M`, `google/gemma-2-2b-it`, `microsoft/BitNet-b1.58-2B-4T`) or opaque `hmac:<16..64hex>` / `sha256:<64hex>` digests;
  - `job_id`, `status`, `risk_level`, `action`, `device`, `jurisdiction`, `state`, `product_type`, `product_category`, `warranty_type`, `hospital_id`, `cpt_code`, `error_code`, and `service.instance.id` enforce strict closed enums or constrained opaque patterns alongside value-level hygiene blocking multiline prose, control characters, emails, SSNs, payment cards, bearer/API tokens, local `/Users/` or `C:\Users\` paths, and free-text smuggling.

### 8.1 Collector Boundary Exclusions (Fail-Closed Policy)
Certain app-local keys that exist in client test fixtures or app-level allowlists are **intentionally excluded** at the enterprise collector boundary so neither free text nor quasi-identifying patient/household combinations can accumulate in shared Jaeger or Prometheus stores:
- **`agreement_title`**: Excluded (potential free-text document title from `bill-of-rights-bot`).
- **`hospital_id`, `household_size`, `fpl_percentage`**: Excluded (combined facility + household size + income ratio creates a patient quasi-identifier in shared telemetry).
- **Arbitrary Resource, Span-Event & Log Metadata**: Resource keys outside the approved service set (`host.name`, `os.description`, `process.command_line`, usernames, etc.) and any arbitrary span-event or log attributes are dropped, and log bodies are redacted.

### 8.2 Path-Valued Attribute Sanitization Invariant
Path-valued keys exported by backend ML services MUST NEVER emit absolute paths, directory trees, host usernames, or plain unsalted hashes of predictable paths:
- **`adapter_path`**: Must be emitted strictly as a **keyed HMAC-SHA256** digest prefix (`hmac:<16hex>`) using an application-local secret (`FTAAS_TELEMETRY_HMAC_KEY`, unavailable to the collector; falling back to an ephemeral per-process CSPRNG key when unset). Plain unsalted SHA-256 over predictable paths is prohibited.
- **`dataset_relative_path`**: Must be emitted strictly as a flat filename basename (`<job_id>.jsonl`), with zero directory components.
- **`service.instance.id`**: Must be an opaque UUID (`8-4-4-4-12`), 12–64 hex container/hash ID, or `hmac:`/`sha256:` digest; in both `otel-collector-config.yaml` and `collector-configmap.yaml`, OTTL `context: resource` `IsMatch` statements after `keep_keys` redact hostname/username slugs (e.g. `service.instance.id="employee-alice"` -> `"[REDACTED_SENSITIVE_VALUE]"`) before trace/spanmetrics ingestion and set `attributes["kty.resource_overflow"] = "drop"` in `transform/metrics_preflight` so `filter/drop_noncompliant_metrics` drops the metric.

### 8.3 Approved Collector Keys (Traces, Metrics & Resource Scope)

- **OTel Resource Attributes (`context: resource`)**: `deployment.environment`, `service.instance.id`, `service.name`, `service.namespace`, `service.version`, `telemetry.sdk.language`, `telemetry.sdk.name`, `telemetry.sdk.version`
- **Core Operations & Audit Tags**: `action`, `audit.allowlist_enforced`, `audit.collector_verified`, `audit_status`, `char_count`, `clause_count`, `duration_ms`, `duration_sec`, `error_code`, `error_type`, `flagged_count`, `is_compliant`, `jurisdiction`, `ocr_used`, `risk_level`, `rule_id`, `rule_ids`, `service`, `service.name`, `sidecar_active`, `span.kind`, `state`, `status`, `status.code`, `statute_code`
- **HTTP Transport Attributes (Method & Status Only)**: `http.method`, `http.status_code`
- **Housing (`lease-audit`)**: `flagged_clauses`, `line_count`, `total_clauses`, `unenforceable_count`, `watch_count`
- **Healthcare Billing (`careCheck` Non-Identifying Booleans & Counts)**: `charity_eligible`, `discount_percent`, `discrepancy_count`, `has_balance_due`, `has_income_verified`, `has_itemized_breakdown`, `parsed_line_count`, `standard_count`
- **Wage & Labor (`paystub-check`)**: `has_deductions`, `has_overtime`, `overtime_hours`, `redflag_count`, `regular_hours`, `unlawful_count`
- **Subscription Rights (`bill-of-rights-bot`)**: `matched_violations`, `score_percentage`, `unconditional_gift_triggered`
- **Warranty & Lemon Law (`warranty-watch`)**: `has_illegal_tie_in`, `has_implied_disclaimer`, `product_category`, `product_type`, `protection_score`, `violations_count`, `warranty_type`
- **FTaaS Control Plane & Training Worker (`ml`)**: `adapter_path` *(hash-only)*, `adapter_size_bytes`, `base_model`, `current_step`, `dataset_hash`, `dataset_relative_path` *(basename-only)*, `device`, `exchange`, `loss`, `progress_pct`, `routing_key`, `step`, `total_steps`
- **Surprisal / Preflight Data Arbiter (`surprisal-service` & Legacy Aliases)**: `surprisal.preflight.enabled`, `surprisal.preflight.status`, `surprisal.preflight.duration_ms`, `surprisal.cases.original_count`, `surprisal.cases.ablated_count`, `surprisal.cases.anomalous_count`, `howso.preflight.enabled`, `howso.preflight.status`, `howso.preflight.duration_ms`, `howso.cases.original_count`, `howso.cases.ablated_count`, `howso.cases.anomalous_count`


