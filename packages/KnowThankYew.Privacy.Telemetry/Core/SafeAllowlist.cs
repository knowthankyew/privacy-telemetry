using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KnowThankYew.Privacy.Telemetry.Core;

public sealed class SafeAllowlist
{
    public const string RedactedNotAllowlisted = "[REDACTED_NOT_IN_ALLOWLIST]";
    public const string RedactedSensitiveValue = "[REDACTED_SENSITIVE_VALUE]";
    private const string RedactedUnallowlistedKey = "[REDACTED_KEY]";

    internal const int MaxStringLength = 256;
    private const int MaxPatternCheckLength = 4096;
    internal const int MaxRuleIds = 50;
    // Up to 50 items, max 71 chars each (full sha256:<64hex>), separated by commas.
    internal const int MaxRuleIdsCsvLength = MaxRuleIds * 72;

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private static readonly Regex ControlOrMultilineRegex = new(@"[\r\n\x00-\x1f\x7f]", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex EmailRegex = new(@"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,24}", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex SsnRegex = new(@"(?<!\d)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex DelimitedCardRegex = new(@"(?<!\d)(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{1,4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})(?!\d)", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ContiguousCardIinRegex = new(@"(?<!\d)(?:4\d{12}(?:\d{3})?(?:\d{3})?|(?:5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))\d{12}|3[47]\d{13}|(?:6011|65\d{2}|64[4-9]\d)\d{12}(?:\d{3})?)(?!\d)", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex SecretTokenRegex = new(@"\bBearer\s+[A-Za-z0-9\-._~+/]{1,200}={0,4}|(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,128}\b|(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,128}\b|(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);
    private static readonly Regex LocalPathRegex = new(@"(?:^|[\s""'(=]|file:(?:\/\/(?:localhost)?)?)(?:\/(?:Users|home|tmp|var|private)\/[^\s""')]{1,200}|\/?[A-Za-z]:[\\/]Users[\\/][^\s""')]{1,200})", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);
    private static readonly Regex OpaqueUuidRegex = new(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex OpaqueHexIdRegex = new(@"^(?:[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex HmacPathRegexStatic = new(@"^hmac:[a-f0-9]{16}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex HospOrHmacHexRegex = new(@"^(?:hosp_|hmac:)[a-f0-9]{16,64}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex PrefixedHmacOrShaRegex = new(@"^(?:hmac|sha256):[a-f0-9]{16,64}$", RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex JobIdRegex = new(@"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|(?:job|test-job|run|task|j)[-_](?:[0-9]{1,8}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex OpaqueJobIdentifierRegex = new(@"^(?:(?:job|test-job|run|task|j)[-_])?(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex OpaqueDigestRegex = new(@"^(?:hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex KeyedHmacDigestRegex = new(@"^hmac:[a-f0-9]{16,64}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ServiceInstanceIdRegex = new(@"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{12,64}|(?:hmac|sha256):[a-f0-9]{16,64})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex HttpErrorCodeRegex = new(@"^(?:HTTP_)?[45]\d{2}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex CamelCaseBoundaryRegex1 = new(@"([a-z0-9])([A-Z])", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex CamelCaseBoundaryRegex2 = new(@"([A-Z]+)([A-Z][a-z])", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ProhibitedCustomDomainKeyRegex = new(
        @"(?:^|[._-])(?:tenant|ssn|social_security|email|phone|telephone|mobile|address|street|dob|birth|patient|diagnosis|prognosis|symptom|condition|disease|disorder|hiv|aids|pregnant|pregnancy|cancer|diabetes|medical|clinical|medication|prescription|treatment|mrn|phi|claimant|employee|employer|landlord|wage|salary|income|pay_rate|hourly_rate|annual_salary|gross_pay|net_pay|pay_amount|excerpt|snippet|prompt|raw_text|raw_payload|raw_content|clause_text|document_text|agreement_text|matched_text|matched_clause|matched_snippet|client|customer|victim|plaintiff|defendant|username|full_name|first_name|last_name|company|holdings|corp|corporation|llc|inc|ltd|vendor|merchant|creditor|organization|org|firm|business)(?:\d{0,6})?(?:$|[._-])|(?:^|[._-])name$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexTimeout);
    private static readonly Regex CustomDomainKeyRegex = new(@"^(?:[a-z][a-z0-9._-]{0,63}|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+){1,3})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex CustomDomainSchemaSuffixRegex = new(
        @"^(?:(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|dataset_relative|arbitrary|arbitrary_custom|matched|redflag|domain_custom|safe_custom|safe_registered|unkeyed_cleartext)[._-]?(?:count|cnt|pct|percent|percentage|ms|sec|bytes|score|status|level|tier|channel|path|code|type|key|field)|(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|matched|redflag)(?:Count|Cnt|Pct|Percent|Percentage|Ms|Sec|Bytes|Score|Status|Level|Tier|Channel|Path|Code|Type|Key|Field)|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$",
        RegexOptions.Compiled,
        RegexTimeout);
    // Section 8.1 Collector Boundary Exclusions: app-local keys permitted only in isolated in-memory
    // evaluation buffers (never exported over external OTLP/Activity pipelines when allowRawPayloads is false,
    // and never permitted as a combined hospital_id + household_size + fpl_percentage patient quasi-identifier triad).
    private static readonly HashSet<string> CollectorBoundaryExcludedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "agreement_title",
        "hospital_id",
        "household_size",
        "fpl_percentage"
    };

    public static bool IsCollectorBoundaryExcludedKey(string? key) =>
        !string.IsNullOrWhiteSpace(key) && CollectorBoundaryExcludedKeys.Contains(key);

    private static void RedactPatientQuasiIdentifierTriad(Dictionary<string, object> sanitized)
    {
        var hasHospital = false;
        var hasHousehold = false;
        var hasFpl = false;
        List<string>? matchedKeys = null;
        foreach (var k in sanitized.Keys)
        {
            if (k.Equals("hospital_id", StringComparison.OrdinalIgnoreCase))
            {
                hasHospital = true;
                matchedKeys ??= new List<string>();
                matchedKeys.Add(k);
            }
            else if (k.Equals("household_size", StringComparison.OrdinalIgnoreCase))
            {
                hasHousehold = true;
                matchedKeys ??= new List<string>();
                matchedKeys.Add(k);
            }
            else if (k.Equals("fpl_percentage", StringComparison.OrdinalIgnoreCase))
            {
                hasFpl = true;
                matchedKeys ??= new List<string>();
                matchedKeys.Add(k);
            }
        }
        if (hasHospital && hasHousehold && hasFpl && matchedKeys is not null)
        {
            foreach (var k in matchedKeys)
            {
                sanitized[k] = RedactedSensitiveValue;
            }
        }
    }

    private static readonly HashSet<string> ReviewedDomainExtensionKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "hospital_id", "cpt_code", "statute_code", "household_size", "fpl_percentage", "charity_eligible", "unconditional_gift_triggered",
        "line_count", "has_itemized_breakdown", "discrepancy_count", "discount_percent",
        "has_income_verified", "has_balance_due", "unlawful_count", "score_percentage",
        "sidecar_active", "agreement_title", "ocr_used", "state", "overtime_hours",
        "regular_hours", "redflag_count", "is_compliant", "parsed_line_count",
        "has_overtime", "has_deductions", "product_type", "product_category",
        "warranty_type", "protection_score", "violations_count", "findings_count",
        "risk_score", "has_illegal_tie_in", "has_implied_disclaimer",
        "extension.action", "extension.rule_category", "extension.rule_id", "extension.severity",
        "extension.scan_duration_ms", "extension.traps_found", "extension.critical_count", "extension.warning_count",
        "app.version", "app.environment", "service.instance.id", "base_model", "dataset_hash",
        "adapter_size_bytes", "current_step",
        "total_steps", "progress_pct", "loss", "device", "exchange", "routing_key",
        "surprisal.preflight.enabled", "surprisal.preflight.status", "surprisal.preflight.duration_ms",
        "surprisal.cases.original_count", "surprisal.cases.ablated_count", "surprisal.cases.anomalous_count",
        "howso.preflight.enabled", "howso.preflight.status", "howso.preflight.duration_ms",
        "howso.cases.original_count", "howso.cases.ablated_count", "howso.cases.anomalous_count",
        "audit.allowlist_enforced", "audit.collector_verified"
    };

    private static bool IsExplicitSafeSchemaKey(string key) =>
        DefaultKeysSet.Contains(key) ||
        RegisteredNumericKeys.Contains(key) ||
        BooleanOnlyKeys.Contains(key) ||
        StrictTokenKeys.Contains(key);

    private static bool IsProhibitedCustomDomainKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return true;
        }
        try
        {
            var normalized = CamelCaseBoundaryRegex1.Replace(key, "$1_$2");
            normalized = CamelCaseBoundaryRegex2.Replace(normalized, "$1_$2");
            return ProhibitedCustomDomainKeyRegex.IsMatch(normalized);
        }
        catch (RegexMatchTimeoutException)
        {
            return true;
        }
    }

    private static bool IsSafeAttributeKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }
        try
        {
            return CustomDomainKeyRegex.IsMatch(key) &&
                   !ContainsSensitivePattern(key);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static bool IsSafeCustomDomainKey(string? key)
    {
        if (!IsSafeAttributeKey(key) || IsProhibitedCustomDomainKey(key!))
        {
            return false;
        }
        try
        {
            return IsExplicitSafeSchemaKey(key!) ||
                   ReviewedDomainExtensionKeys.Contains(key!) ||
                   CustomDomainSchemaSuffixRegex.IsMatch(key!);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
    private static readonly HashSet<string> RegisteredErrorCodes = new(StringComparer.Ordinal)
    {
        "edge_inference_notice",
        "unknown_error",
        "internal_error",
        "validation_error",
        "invalid_request",
        "invalid_payload",
        "invalid_argument",
        "unauthorized",
        "forbidden",
        "not_found",
        "conflict",
        "rate_limited",
        "timeout",
        "gateway_timeout",
        "service_unavailable",
        "network_error",
        "network_denied",
        "parse_error",
        "parse_failed",
        "ocr_failed",
        "pdf_extract_failed",
        "model_load_failed",
        "inference_failed",
        "inference_timeout",
        "burn_activated",
        "telemetry_disabled",
        "handoff_rejected",
        "handoff_expired",
        "handoff_invalid",
        "worker_failed",
        "queue_timeout",
        "broker_unavailable",
        "storage_unavailable",
        "ERR_TIMEOUT",
        "ERR_NETWORK",
        "ERR_VALIDATION",
        "ERR_PARSE",
        "ERR_OCR",
        "ERR_PDF",
        "ERR_INFERENCE",
        "ERR_UNAUTHORIZED",
        "ERR_FORBIDDEN",
        "ERR_NOT_FOUND",
        "ERR_RATE_LIMITED",
        "ERR_INTERNAL",
        "ERR_UNAVAILABLE",
        "ERR_CONFLICT",
        "ECONNREFUSED",
        "ETIMEDOUT",
        "ENOTFOUND",
        "ECONNRESET",
        "EPIPE",
        "ENOENT",
        "TimeoutException",
        "TimeoutError",
        "ValidationException",
        "ValidationError",
        "ArgumentException",
        "ArgumentNullException",
        "InvalidOperationException",
        "HttpRequestException",
        "OperationCanceledException",
        "TaskCanceledException",
        "IOException",
        "JsonException",
        "FormatException",
        "KeyNotFoundException",
        "UnauthorizedAccessException",
        "TypeError",
        "ValueError",
        "RuntimeError",
        "KeyError",
        "OSError",
        "NetworkError",
        "AbortError",
        "SyntaxError"
    };
    private static readonly Regex ActivitySourceNameRegex = new(@"^(?:KnowThankYew|Kty|FtaaSService|knowthankyew)(?:\.[A-Za-z0-9_-]{1,36}){1,5}$", RegexOptions.Compiled, RegexTimeout);

    private static readonly string[] UsStateCodes =
    {
        "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL",
        "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME",
        "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH",
        "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI",
        "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    };

    private static readonly HashSet<string> RegisteredRuleIds = BuildRegisteredRuleIds();

    private static HashSet<string> BuildRegisteredRuleIds()
    {
        var ids = new HashSet<string>(StringComparer.Ordinal)
        {
            // Extension policy pack IDs
            "AR-001", "AR-002", "AR-003",
            "ARB-001", "ARB-002", "ARB-003",
            "UNI-001", "UNI-002",
            "SURV-001", "SURV-002",
            "US-CO-001", "US-IL-001", "US-OR-001",
            "EU-AR-001", "EU-AR-002", "EU-SURV-001",
            "UK-AR-001", "UK-AR-002", "UK-CONS-001",
            // Lease-audit statute pack IDs
            "CA-SEC-DEP-CAP-01", "CA-SEC-DEP-RET-02", "CA-ENTRY-NOT-03", "CA-EVICT-SLF-04", "CA-HABIT-REP-05", "CA-LATE-FEE-06",
            "FL-SEC-DEP-RET-01", "FL-ENTRY-NOT-02", "FL-PROHIB-PRAC-03", "FL-HABIT-REP-04",
            "IL-SEC-DEP-RET-01", "IL-EVICT-SLF-02", "IL-RETALIAT-03", "IL-DEP-INT-04",
            "NY-SEC-DEP-CAP-01", "NY-SEC-DEP-RET-02", "NY-ENTRY-NOT-06", "NY-LATE-FEE-03", "NY-EVICT-SLF-04", "NY-HABIT-WAR-05", "NY-OCCUP-ROOM-07",
            "TX-SEC-DEP-RET-01", "TX-LATE-FEE-02", "TX-LOCKOUT-SLF-03", "TX-UTIL-SHUT-04", "TX-HABIT-REP-05",
            "FED-FHA-FAM-01", "FED-FHA-DIS-02", "FED-SCRA-MIL-03", "FED-LEAD-DISC-04",
            // Paystub-check rule IDs
            "illegal_register_shortage_deduction",
            "illegal_uniform_equipment_deduction",
            "salaried_under_exemption_threshold",
            "missing_overtime_multiplier",
            "unexplained_mandatory_fee",
            "salaried_under_threshold",
            "fica_math_mismatch",
            // Warranty-watch rule & handoff IDs
            "KTY-WARRANTY-EXCL-001",
            "KTY-WARRANTY-DISCLAIM-001",
            "WARRANTY_VOID_IF_REMOVED",
            // Canonical statutory identifiers verified across compliance test suites
            "CA_CIV_1950_5",
            "FLSA_EXEMPT_541",
            "implied_warranty_disclaimer",
        };
        foreach (var abbr in UsStateCodes)
        {
            ids.Add($"state_daily_overtime_{abbr}");
            ids.Add($"state_implied_override_{abbr}");
        }
        return ids;
    }

    private static readonly HashSet<string> RegisteredBaseModels = new(StringComparer.Ordinal)
    {
        "HuggingFaceTB/SmolLM2-135M",
        "google/gemma-2-2b-it",
        "microsoft/BitNet-b1.58-2B-4T",
    };

    private static readonly HashSet<string> RegisteredActivitySourceNames = new(StringComparer.Ordinal)
    {
        "KnowThankYew.Privacy.Telemetry",
    };

    private static bool IsSafeRuleId(string value) =>
        RegisteredRuleIds.Contains(value) || OpaqueDigestRegex.IsMatch(value);

    private static bool IsSafeBaseModel(string value) =>
        RegisteredBaseModels.Contains(value) || OpaqueDigestRegex.IsMatch(value);

    private static readonly HashSet<string> RegisteredEventNames = new(StringComparer.Ordinal)
    {
        // Registered extension & consumer-app operational span/event names
        "extension.page_scan",
        "evaluate_subscription_agreement", "parse_agreement", "parse_contract",
        "evaluate_charity_care", "audit_medical_bill", "parse_bill",
        "evaluate_lease_rules", "evaluate_edge_semantic_lora", "segment_clauses", "audit_evaluation", "parse_document", "enterprise_job",
        "analyze_paystub", "parse_paystub", "parse_wage_statement",
        "analyze_warranty", "parse_warranty", "parse_warranty_card",
        // Registered ML FTaaS & OTel operational span/event names
        "job.accepted", "job.publish_failed", "job.published",
        "job.edge_export_requested", "job.edge_exported", "job.consumed",
        "job.registered", "job.completed", "job.failed",
        "job.training.started", "job.training.finished",
        "job.transition", "job.transition.pending", "job.transition.queued",
        "job.transition.training", "job.transition.succeeded", "job.transition.failed",
        "job.transition.cancelled", "job.transition.canceled",
        "surprisal.preflight", "howso.preflight", "rule.evaluated"
    };
    private static readonly Regex AppVersionRegex = new(@"^v?\d{1,4}\.\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:-(?:alpha|beta|rc|preview|nightly|dev|canary)(?:\.\d{1,4})?)?(?:\+(?:[0-9a-f]{7,40}|\d{1,12}))?$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex HospitalIdRegex = new(@"^(?:cleveland-clinic-main|mayo-clinic-rochester|ascension-health-national|kaiser-foundation-hospitals|HOSP-\d{1,6}|(?:hosp_|hmac:)[a-f0-9]{16,64})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex CptCodeRegex = new(@"^(?:\d{4}[A-Z0-9]|hmac:[a-f0-9]{16})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex DatasetHashRegex = new(@"^(?:sha256:)?(?:[0-9a-f]{12,64}|[0-9A-F]{12,64})$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex HmacPathRegex = new(@"^hmac:[a-f0-9]{16}$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex TruncatedHashRegex = new(@"^\[TRUNCATED_HASH_[a-f0-9]{8}\]$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex FederalStatuteRegex = new(@"^\d{1,3}\s+(?:U\.?S\.?C\.?|C\.?F\.?R\.?|Stat\.)\s+(?:(?:§§?|Part)\s*)?\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ChapterActStatuteRegex = new(@"^\d{1,4}\s+ILCS\s+\d{1,4}[A-Za-z]?(?:-(?:\d{1,4}|[A-Za-z]))?(?:\/|\/\d{1,4}(?:-\d{1,4})?[A-Za-z]?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex JurisdictionSectionStatuteRegex = new(@"^(?:Cal\.|N\.Y\.|Mass\.|Tex\.|Fla\.|Ill\.|Wash\.|Colo\.|Or\.|Pa\.|N\.J\.|Va\.|Md\.|Ga\.|N\.C\.|S\.C\.|Minn\.|Wis\.|Ariz\.|Nev\.|Mich\.|Conn\.|Ind\.|Ohio|Iowa|Utah|Tenn\.|Ky\.|La\.|Ala\.|Ark\.|Kan\.|Mo\.|Neb\.|Mont\.|Idaho|Wyo\.|Me\.|Vt\.|N\.H\.|R\.I\.|Del\.|Alaska|Hawaii|D\.C\.|UCC|FDCPA|FCRA|FLSA|TILA|SCRA|FHA|HIPAA|ROSCA|CCPA|CPRA|BIPA|FTC)(?:\s+(?:Rev\.|Gen\.|Bus\.|Prof\.|Civ\.|Lab\.|Prop\.|Penal|Ins\.|Health|Educ\.|Fin\.|Gov\.|Com\.|Code|Laws?|Stat\.|Act|Ann\.|ch\.|c\.|Part|Title|&|GBL|RPL|Art\.|\d{1,4}[A-Za-z]?)){0,5}(?:,\s*|\s*)(?:§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?|Ch\.\s*\d{1,4}(?:\s*§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?)?)$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex EuStatuteRegex = new(@"^(?:EU\s+)?(?:GDPR(?:\s+Art\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?|Directive\s+\d{4}/\d{1,4}/[A-Z]{2,4}(?:,?\s+Art(?:icle)?\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?)$", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex UkStatuteRegex = new(@"^UK\s+(?:Consumer\s+Rights|DMCC|Data\s+Protection|Employment\s+Rights)\s+Act\s+\d{4}(?:,?\s+(?:Part|Chapter|Section|Sec\.|§)\s*\d{1,4}(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3}){0,3}$", RegexOptions.Compiled, RegexTimeout);

    private static readonly HashSet<string> RegisteredNumericKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        // Default numeric schema keys
        "step", "current_step", "total_steps", "loss", "http.status_code",
        "duration_ms", "duration_sec", "progress_pct", "adapter_size_bytes",
        "clause_count", "total_clauses", "flagged_clauses", "flagged_count",
        "standard_count", "watch_count", "unenforceable_count", "char_count",
        "matched_violations",
        // Reviewed portfolio numeric schema keys
        "extension.scan_duration_ms", "extension.traps_found",
        "extension.critical_count", "extension.warning_count",
        "household_size", "fpl_percentage", "line_count", "discrepancy_count",
        "discount_percent", "parsed_line_count", "unlawful_count", "score_percentage",
        "overtime_hours", "regular_hours", "redflag_count", "protection_score",
        "violations_count", "findings_count", "risk_score",
        "surprisal.preflight.duration_ms", "surprisal.cases.original_count",
        "surprisal.cases.ablated_count", "surprisal.cases.anomalous_count",
        "howso.preflight.duration_ms", "howso.cases.original_count",
        "howso.cases.ablated_count", "howso.cases.anomalous_count"
    };

    private static readonly HashSet<string> BooleanOnlyKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "ocr_used", "sidecar_active", "charity_eligible", "unconditional_gift_triggered",
        "has_income_verified", "has_balance_due", "has_itemized_breakdown",
        "has_deductions", "has_overtime", "has_illegal_tie_in",
        "has_implied_disclaimer", "is_compliant", "surprisal.preflight.enabled",
        "howso.preflight.enabled", "audit.allowlist_enforced", "audit.collector_verified"
    };

    private static readonly HashSet<string> StrictTokenKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "rule_id", "error_code", "device", "http.method", "job_id", "service",
        "service.name", "action", "status", "audit_status", "risk_level",
        "exchange", "routing_key", "error_type", "extension.action",
        "extension.rule_category", "extension.rule_id", "extension.severity",
        "app.version", "app.environment", "howso.preflight.status", "surprisal.preflight.status"
    };

    private static readonly HashSet<string> StatusValues = new(StringComparer.Ordinal)
    {
        "OK", "ERROR", "UNSET", "Pending", "Queued", "Training", "TrainingFinished",
        "Succeeded", "Failed", "Completed", "Cancelled", "Canceled", "Timeout", "Unknown",
        "ok", "error", "unset", "pending", "queued", "training", "training_finished",
        "succeeded", "failed", "completed", "cancelled", "canceled", "timeout", "unknown",
        "degraded", "burned", "Standard", "Watch", "Flagged", "LikelyUnenforceable",
        "Unenforceable", "Compliant", "NonCompliant", "Disabled", "disabled",
        "Skipped", "skipped", "FellBack"
    };

    private static readonly HashSet<string> AuditStatusValues = new(StringComparer.Ordinal)
    {
        "Standard", "Watch", "Flagged", "LikelyUnenforceable", "Unenforceable",
        "Compliant", "NonCompliant", "Passed", "Failed", "Completed", "Pending",
        "OK", "ERROR", "Unknown", "standard", "watch", "flagged",
        "likely_unenforceable", "unenforceable", "compliant", "non_compliant",
        "passed", "failed", "completed", "pending", "ok", "error", "unknown"
    };

    private static readonly HashSet<string> RiskSeverityValues = new(StringComparer.Ordinal)
    {
        "Critical", "High", "Medium", "Moderate", "Low", "Info", "Warning", "None", "Minimal", "Elevated", "Severe",
        "CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "WARNING", "NONE",
        "critical", "high", "medium", "moderate", "low", "info", "warning", "none"
    };

    private static readonly HashSet<string> PreflightStatusValues = new(StringComparer.Ordinal)
    {
        "Disabled", "Skipped", "Completed", "FellBack", "Passed", "Failed", "Error", "OK",
        "disabled", "skipped", "completed", "fell_back", "passed", "failed", "error", "ok"
    };

    private static readonly HashSet<string> HttpMethodValues = new(StringComparer.Ordinal)
    {
        "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"
    };

    private static readonly HashSet<string> DeviceValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "cpu", "cuda", "cuda:0", "cuda:1", "cuda:2", "cuda:3", "cuda:4", "cuda:5", "cuda:6", "cuda:7",
        "mps", "webgpu", "wasm", "gpu", "npu", "ane", "xpu", "rocm", "directml", "auto", "none", "unknown", "x64", "arm64"
    };

    private static readonly HashSet<string> ActionValues = new(StringComparer.Ordinal)
    {
        "scan_started", "scan_complete", "scan_completed", "document_ingested",
        "rules_evaluated", "audit_performed", "handoff_sent", "handoff_received", "handoff_rejected",
        "edge_inference_started", "edge_inference_completed", "edge_inference_failed", "edge_export",
        "ocr_started", "ocr_completed", "pdf_extracted", "burn", "hard_burn", "export", "dispute_generated"
    };

    private static readonly HashSet<string> ExtensionRuleCategoryValues = new(StringComparer.Ordinal)
    {
        "AUTO_RENEWAL", "ARBITRATION", "UNILATERAL_CHANGE", "SURVEILLANCE",
        "WARRANTY_DISCLAIMER", "WAGE_THEFT", "TERMS", "BILLING", "PRIVACY", "DARK_PATTERN"
    };

    private static readonly HashSet<string> ServiceNameValues = new(StringComparer.Ordinal)
    {
        "knowthankyew-app", "privacy-telemetry", "knowthankyew-extension", "lease-audit", "care-check", "careCheck",
        "paystub-check", "bill-of-rights-bot", "warranty-watch", "ftaas-api", "ftaas-worker",
        "ftaas-inference", "surprisal-service", "howso-preflight", "mail-stripper",
        "mail-stripper-imap", "unsubscribe-shield-ext", "gradcast", "genesis",
        "mac-screen-record", "kty-ntfs", "enterprise-self-host", "test-svc", "unknown"
    };

    private static readonly HashSet<string> AppEnvironmentValues = new(StringComparer.Ordinal)
    {
        "development", "dev", "staging", "stage", "production", "prod",
        "test", "testing", "ci", "local", "sandbox", "preview",
        "Development", "Staging", "Production"
    };

    private static readonly HashSet<string> ExchangeValues = new(StringComparer.Ordinal)
    {
        "ftaas.direct", "ftaas.dlx", "ftaas.events", "ftaas.topic", "default", "direct"
    };

    private static readonly HashSet<string> RoutingKeyValues = new(StringComparer.Ordinal)
    {
        "job.requested", "job.updated", "job.status", "job.completed", "job.failed",
        "job.dlq", "job.cancelled", "job.canceled", "job.progress", "job.edge_export"
    };

    private static readonly Dictionary<string, HashSet<string>> ClosedTokenDomainMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["status"] = StatusValues,
        ["audit_status"] = AuditStatusValues,
        ["risk_level"] = RiskSeverityValues,
        ["extension.severity"] = RiskSeverityValues,
        ["howso.preflight.status"] = PreflightStatusValues,
        ["surprisal.preflight.status"] = PreflightStatusValues,
        ["http.method"] = HttpMethodValues,
        ["device"] = DeviceValues,
        ["action"] = ActionValues,
        ["extension.action"] = ActionValues,
        ["extension.rule_category"] = ExtensionRuleCategoryValues,
        ["service"] = ServiceNameValues,
        ["service.name"] = ServiceNameValues,
        ["app.environment"] = AppEnvironmentValues,
        ["exchange"] = ExchangeValues,
        ["routing_key"] = RoutingKeyValues
    };

    private static readonly HashSet<string> JurisdictionValues = new(StringComparer.Ordinal)
    {
        "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA",
        "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM",
        "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
        "WV", "WI", "WY", "AS", "GU", "MP", "PR", "VI",
        "FED", "FEDERAL", "FTC", "DEFAULT", "US", "UK", "EU", "EU_CRD", "UK_DMCC", "CA-ON",
        "Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware",
        "District of Columbia", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa",
        "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
        "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey",
        "New Mexico", "New York", "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon",
        "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah",
        "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming",
        "Puerto Rico", "American Samoa", "Virgin Islands", "Guam", "Northern Mariana Islands",
        "United States", "US Federal", "Federal", "United Kingdom", "European Union"
    };

    private static readonly HashSet<string> WarrantyTypeValues = new(StringComparer.Ordinal)
    {
        "Full", "Limited", "Disclaimed / As-Is", "Unspecified"
    };

    private static readonly HashSet<string> ProductTypeValues = new(StringComparer.Ordinal)
    {
        "Electronics & Laptops", "Electronics & Computers", "Automotive & EV Accessories",
        "Automotive / EV", "Home Appliances", "Tools & Hardware", "Tools & Equipment",
        "Smart Home Devices", "Furniture & Home Goods", "General Consumer Product",
        "Consumer Electronics", "Automotive Vehicle", "Home Appliance",
        "General", "Electronics", "Automotive", "Appliances", "Tools"
    };

    private enum KeySchemaKind
    {
        AdapterPath,
        DatasetJsonlPath,
        Path,
        RuleIds,
        Numeric,
        Boolean,
        BaseModel,
        DatasetHash,
        Jurisdiction,
        WarrantyType,
        ProductType,
        StatuteCode,
        HospitalId,
        CptCode,
        ServiceInstanceId,
        StrictToken,
        Custom
    }

    private readonly ConcurrentDictionary<string, byte> _allowedKeys;
    private readonly ConcurrentDictionary<string, byte> _allowedActivitySourceNames;
    private readonly ConcurrentDictionary<string, HashSet<string>> _customValueDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _registerSync = new();

    public static readonly IReadOnlyCollection<string> DefaultKeys = new[]
    {
        "job_id", "status", "duration_ms", "duration_sec", "base_model", "dataset_hash",
        "current_step", "total_steps", "progress_pct", "loss",
        "device", "adapter_size_bytes", "exchange", "routing_key",
        "rule_id", "rule_ids", "statute_code", "jurisdiction", "risk_level",
        "clause_count", "total_clauses", "flagged_clauses", "flagged_count",
        "standard_count", "watch_count", "unenforceable_count", "char_count",
        "matched_violations", "error_code", "service", "action", "step"
    };

    private static readonly HashSet<string> DefaultKeysSet = new(DefaultKeys, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Computes an 8-character lowercase hexadecimal SHA-256 digest marker for oversized attributes.
    /// Does not expose any source text.
    /// </summary>
    public static string FormatTruncatedDigest(string value)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        var digest = Convert.ToHexString(hashBytes)[..8].ToLowerInvariant();
        return $"[TRUNCATED_HASH_{digest}]";
    }

    public SafeAllowlist(IEnumerable<string>? additionalKeys = null)
        : this(additionalKeys, null, null)
    {
    }

    public SafeAllowlist(
        IEnumerable<string>? additionalKeys,
        IEnumerable<string>? additionalActivitySourceNames)
        : this(additionalKeys, additionalActivitySourceNames, null)
    {
    }

    public SafeAllowlist(
        IEnumerable<string>? additionalKeys,
        IEnumerable<string>? additionalActivitySourceNames,
        IReadOnlyDictionary<string, IEnumerable<string>>? customValueDomains)
    {
        _allowedKeys = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in DefaultKeys)
        {
            _allowedKeys[key] = 0;
        }
        if (additionalKeys != null)
        {
            foreach (var key in additionalKeys)
            {
                if (!string.IsNullOrWhiteSpace(key) &&
                    (IsExplicitSafeSchemaKey(key) || IsSafeCustomDomainKey(key)))
                {
                    _allowedKeys[key] = 0;
                }
            }
        }

        if (customValueDomains != null)
        {
            foreach (var kv in customValueDomains)
            {
                RegisterValueDomain(kv.Key, kv.Value);
            }
        }

        _allowedActivitySourceNames = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        foreach (var sourceName in RegisteredActivitySourceNames)
        {
            _allowedActivitySourceNames[sourceName] = 0;
        }
        if (additionalActivitySourceNames != null)
        {
            RegisterActivitySourceNames(additionalActivitySourceNames);
        }
    }

    /// <summary>
    /// Thread-safely registers additional <see cref="System.Diagnostics.ActivitySource"/> names
    /// that satisfy <see cref="HasValidActivitySourceStructure"/>.
    /// </summary>
    public void RegisterActivitySourceNames(IEnumerable<string> sourceNames)
    {
        if (sourceNames is null)
        {
            return;
        }
        foreach (var sourceName in sourceNames)
        {
            if (HasValidActivitySourceStructure(sourceName))
            {
                _allowedActivitySourceNames[sourceName] = 0;
            }
        }
    }

    /// <summary>
    /// Thread-safely registers an explicit closed digest domain for a custom attribute key.
    /// Uses copy-on-write sets so concurrent recording reads consistent immutable snapshots.
    /// </summary>
    public void RegisterValueDomain(string key, IEnumerable<string> allowedValues)
    {
        if (allowedValues is null || !IsSafeCustomDomainKey(key))
        {
            return;
        }
        lock (_registerSync)
        {
            var updated = _customValueDomains.TryGetValue(key, out var existing)
                ? new HashSet<string>(existing, StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in allowedValues)
            {
                // Custom domains cannot authorize arbitrary cleartext strings (e.g., tenant tokens under neutral keys)
                // when allowRawPayloads is false; only opaque cryptographic digests may pass without raw permission.
                if (item is not null && OpaqueDigestRegex.IsMatch(item))
                {
                    updated.Add(item);
                }
            }
            // Preserve explicit empty/cleartext-only domains so callers fail closed rather than falling back to digest-any,
            // while only auto-admitting keys that define at least one valid opaque digest token.
            _customValueDomains[key] = updated;
            if (updated.Count > 0)
            {
                _allowedKeys[key] = 0;
            }
        }
    }

    public bool IsAllowed(string key) => _allowedKeys.ContainsKey(key);

    /// <summary>
    /// Thread-safely registers additional allowlisted attribute keys.
    /// </summary>
    public void RegisterKeys(IEnumerable<string> keys)
    {
        if (keys is null) return;
        foreach (var key in keys)
        {
            if (!string.IsNullOrWhiteSpace(key) &&
                (IsExplicitSafeSchemaKey(key) || IsSafeCustomDomainKey(key)))
            {
                _allowedKeys[key] = 0;
            }
        }
    }

    private static bool PassesLuhn(string digits)
    {
        var sum = 0;
        var alternate = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var n = digits[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    private static KeySchemaKind ClassifyKeyKind(string key)
    {
        if (key.Equals("service.instance.id", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.ServiceInstanceId;
        var normalizedPathKey = CamelCaseBoundaryRegex2.Replace(CamelCaseBoundaryRegex1.Replace(key, "$1_$2"), "$1_$2");
        if (normalizedPathKey.EndsWith("_path", StringComparison.OrdinalIgnoreCase))
        {
            if (normalizedPathKey.StartsWith("adapter", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.AdapterPath;
            if (normalizedPathKey.StartsWith("dataset_", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.DatasetJsonlPath;
            return KeySchemaKind.Path;
        }
        if (key.Equals("rule_ids", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.RuleIds;
        if (key.Equals("base_model", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.BaseModel;
        if (key.Equals("dataset_hash", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.DatasetHash;
        if (key.Equals("jurisdiction", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("state", StringComparison.OrdinalIgnoreCase))
        {
            return KeySchemaKind.Jurisdiction;
        }
        if (key.Equals("warranty_type", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.WarrantyType;
        if (key.Equals("product_type", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("product_category", StringComparison.OrdinalIgnoreCase))
        {
            return KeySchemaKind.ProductType;
        }
        if (key.Equals("statute_code", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.StatuteCode;
        if (key.Equals("hospital_id", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.HospitalId;
        if (key.Equals("cpt_code", StringComparison.OrdinalIgnoreCase)) return KeySchemaKind.CptCode;
        if (RegisteredNumericKeys.Contains(key))
        {
            return KeySchemaKind.Numeric;
        }
        if (BooleanOnlyKeys.Contains(key) ||
            key.StartsWith("is_", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("has_", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith(".enabled", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("_enabled", StringComparison.OrdinalIgnoreCase))
        {
            return KeySchemaKind.Boolean;
        }
        if (StrictTokenKeys.Contains(key)) return KeySchemaKind.StrictToken;
        return KeySchemaKind.Custom;
    }

    internal static bool IsSafeEventName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 128 || ContainsSensitivePattern(name))
        {
            return false;
        }
        return ActionValues.Contains(name) || RegisteredEventNames.Contains(name);
    }

    private static bool HasValidActivitySourceStructure(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 128)
        {
            return false;
        }
        try
        {
            if (!ActivitySourceNameRegex.IsMatch(name))
            {
                return false;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }

        foreach (var segment in name.Split('.'))
        {
            var isOpaqueGuidSegment =
                OpaqueUuidRegex.IsMatch(segment) ||
                (OpaqueHexIdRegex.IsMatch(segment) && segment.Length >= 20 && !segment.All(char.IsDigit));
            if (!isOpaqueGuidSegment && ContainsSensitivePattern(segment))
            {
                return false;
            }
        }
        return true;
    }

    internal static bool IsSafeActivitySourceName(string? name) =>
        !string.IsNullOrEmpty(name) &&
        RegisteredActivitySourceNames.Contains(name) &&
        HasValidActivitySourceStructure(name);

    internal bool IsSafeActivitySource(string? name) =>
        !string.IsNullOrEmpty(name) &&
        _allowedActivitySourceNames.ContainsKey(name) &&
        HasValidActivitySourceStructure(name);

    internal static bool IsSafeAppVersion(string? version)
    {
        if (string.IsNullOrEmpty(version) || version.Length > 64 || ContainsSensitivePattern(version))
        {
            return false;
        }
        try
        {
            return AppVersionRegex.IsMatch(version);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    internal static bool IsSafeErrorCode(string value) =>
        RegisteredErrorCodes.Contains(value) ||
        HttpErrorCodeRegex.IsMatch(value) ||
        OpaqueDigestRegex.IsMatch(value);

    private static string SanitizeStatuteCode(string value)
    {
        if (value.Length <= 64 &&
            (FederalStatuteRegex.IsMatch(value) ||
             ChapterActStatuteRegex.IsMatch(value) ||
             JurisdictionSectionStatuteRegex.IsMatch(value) ||
             EuStatuteRegex.IsMatch(value) ||
             UkStatuteRegex.IsMatch(value)))
        {
            return value;
        }
        return RedactedSensitiveValue;
    }

    private static string SanitizePathValue(
        string key,
        KeySchemaKind kind,
        string value,
        bool allowRawPayloads,
        IReadOnlyDictionary<string, HashSet<string>>? customValueDomains = null)
    {
        if (value == RedactedSensitiveValue)
        {
            return value;
        }
        if (!allowRawPayloads &&
            customValueDomains != null &&
            customValueDomains.TryGetValue(key, out var registeredPathDomain) &&
            (IsProhibitedCustomDomainKey(key) || !registeredPathDomain.Contains(value)))
        {
            return RedactedSensitiveValue;
        }
        if (value.Length == 0)
        {
            return value;
        }
        // Enforce path schemas before any digest fallback or marker preservation (Section 8.2).
        if (kind == KeySchemaKind.AdapterPath)
        {
            return value.Length == 21 && HmacPathRegex.IsMatch(value)
                ? value
                : RedactedSensitiveValue;
        }
        if (kind == KeySchemaKind.DatasetJsonlPath)
        {
            if (value.Length > 128 || !value.EndsWith(".jsonl", StringComparison.Ordinal))
            {
                return RedactedSensitiveValue;
            }
            var stem = value[..^".jsonl".Length];
            var isOpaqueStem = OpaqueJobIdentifierRegex.IsMatch(stem);
            if (ContainsSensitivePattern(value, skipSsn: isOpaqueStem))
            {
                return RedactedSensitiveValue;
            }
            return JobIdRegex.IsMatch(stem) ? value : RedactedSensitiveValue;
        }
        var isKeyedHmacDigest = KeyedHmacDigestRegex.IsMatch(value);
        if (value.Length > 128 || ContainsSensitivePattern(value, skipSsn: isKeyedHmacDigest))
        {
            return RedactedSensitiveValue;
        }
        if (allowRawPayloads && !TruncatedHashRegex.IsMatch(value))
        {
            return value;
        }
        return isKeyedHmacDigest
            ? value
            : RedactedSensitiveValue;
    }

    private static string SanitizeRuleIdsCsv(string value)
    {
        if (value.Length == 0) return string.Empty;
        var parts = value.Split(',');
        if (parts.Length > MaxRuleIds) return RedactedSensitiveValue;
        foreach (var part in parts)
        {
            if (!IsSafeRuleId(part)) return RedactedSensitiveValue;
        }
        return value;
    }

    private static string SanitizeStrictToken(string key, string value)
    {
        if (ClosedTokenDomainMap.TryGetValue(key, out var allowedSet))
        {
            return allowedSet.Contains(value) ? value : RedactedSensitiveValue;
        }
        if (key.Equals("job_id", StringComparison.OrdinalIgnoreCase))
        {
            return JobIdRegex.IsMatch(value) ? value : RedactedSensitiveValue;
        }
        if (key.Equals("rule_id", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("extension.rule_id", StringComparison.OrdinalIgnoreCase))
        {
            return IsSafeRuleId(value) ? value : RedactedSensitiveValue;
        }
        if (key.Equals("error_code", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("error_type", StringComparison.OrdinalIgnoreCase))
        {
            return IsSafeErrorCode(value) ? value : RedactedSensitiveValue;
        }
        if (key.Equals("app.version", StringComparison.OrdinalIgnoreCase))
        {
            return AppVersionRegex.IsMatch(value) ? value : RedactedSensitiveValue;
        }
        return RedactedSensitiveValue;
    }

    private static object SanitizeRuleIdsSequence(
        System.Collections.IEnumerable items,
        bool allowRawPayloads,
        IReadOnlyDictionary<string, HashSet<string>>? customValueDomains = null)
    {
        HashSet<string>? registeredRuleDomain = null;
        var hasRegisteredRuleDomain =
            !allowRawPayloads &&
            customValueDomains != null &&
            customValueDomains.TryGetValue("rule_ids", out registeredRuleDomain);
        if (hasRegisteredRuleDomain && IsProhibitedCustomDomainKey("rule_ids"))
        {
            return RedactedSensitiveValue;
        }
        var cleaned = new List<string>();
        foreach (var item in items)
        {
            if (cleaned.Count >= MaxRuleIds || item is not string strItem)
            {
                return RedactedSensitiveValue;
            }
            if (hasRegisteredRuleDomain && !registeredRuleDomain!.Contains(strItem))
            {
                return RedactedSensitiveValue;
            }
            var sanitizedItem = allowRawPayloads
                ? (strItem.Length > MaxStringLength ? FormatTruncatedDigest(strItem) : strItem)
                : SanitizeAllowlistedStringValue("rule_id", strItem);
            if (!allowRawPayloads && sanitizedItem == RedactedSensitiveValue)
            {
                return RedactedSensitiveValue;
            }
            cleaned.Add(sanitizedItem);
        }
        if (hasRegisteredRuleDomain && cleaned.Count == 0)
        {
            return RedactedSensitiveValue;
        }
        return cleaned.ToArray();
    }

    private static bool IsFiniteNumeric(object value) => value switch
    {
        float f => float.IsFinite(f),
        double d => double.IsFinite(d),
        decimal or byte or sbyte or short or ushort or int or uint or long or ulong => true,
        _ => false,
    };

    private static string SanitizeStringForSchema(
        string key,
        string value,
        bool allowRawPayloads,
        IReadOnlyDictionary<string, HashSet<string>>? customValueDomains = null)
    {
        try
        {
            var kind = ClassifyKeyKind(key);
            if (kind is KeySchemaKind.AdapterPath or KeySchemaKind.DatasetJsonlPath or KeySchemaKind.Path)
            {
                return SanitizePathValue(key, kind, value, allowRawPayloads, customValueDomains);
            }
            if (value == RedactedSensitiveValue || TruncatedHashRegex.IsMatch(value))
            {
                return value;
            }
            if (!allowRawPayloads &&
                customValueDomains != null &&
                customValueDomains.TryGetValue(key, out var registeredDomain))
            {
                if (IsProhibitedCustomDomainKey(key))
                {
                    return RedactedSensitiveValue;
                }
                if (kind == KeySchemaKind.RuleIds)
                {
                    if (value.Length == 0)
                    {
                        return RedactedSensitiveValue;
                    }
                    if (value.Length > MaxRuleIdsCsvLength)
                    {
                        return FormatTruncatedDigest(value);
                    }
                    var domainParts = value.Split(',');
                    if (domainParts.Length > MaxRuleIds ||
                        !Array.TrueForAll(domainParts, part => registeredDomain.Contains(part)))
                    {
                        return RedactedSensitiveValue;
                    }
                }
                else if (!registeredDomain.Contains(value))
                {
                    return RedactedSensitiveValue;
                }
            }
            // Valid rule_ids CSV (<= 50 items, max 71 chars each) stays intact across repeated sanitization passes.
            if (kind == KeySchemaKind.RuleIds && value.Length <= MaxRuleIdsCsvLength)
            {
                if (allowRawPayloads)
                {
                    return value;
                }
                var csv = SanitizeRuleIdsCsv(value);
                if (csv != RedactedSensitiveValue)
                {
                    var parts = csv.Length == 0 ? Array.Empty<string>() : csv.Split(',');
                    var hasSensitive = Array.Exists(
                        parts,
                        part => ContainsSensitivePattern(part, skipSsn: OpaqueDigestRegex.IsMatch(part)));
                    if (!hasSensitive)
                    {
                        return csv;
                    }
                }
            }
            // Enforce length bound before any regex work to avoid ReDoS and oversized payloads.
            if (value.Length > MaxStringLength)
            {
                return FormatTruncatedDigest(value);
            }
            if (allowRawPayloads)
            {
                return value;
            }
            var isConstrainedOpaque =
                (kind == KeySchemaKind.DatasetHash && DatasetHashRegex.IsMatch(value)) ||
                (string.Equals(key, "job_id", StringComparison.OrdinalIgnoreCase) &&
                    OpaqueJobIdentifierRegex.IsMatch(value)) ||
                (kind == KeySchemaKind.ServiceInstanceId && ServiceInstanceIdRegex.IsMatch(value)) ||
                ((kind == KeySchemaKind.BaseModel ||
                  string.Equals(key, "rule_id", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(key, "extension.rule_id", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(key, "error_code", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(key, "error_type", StringComparison.OrdinalIgnoreCase)) &&
                    OpaqueDigestRegex.IsMatch(value)) ||
                (kind == KeySchemaKind.HospitalId && HospOrHmacHexRegex.IsMatch(value)) ||
                (kind == KeySchemaKind.CptCode && HmacPathRegexStatic.IsMatch(value)) ||
                (kind == KeySchemaKind.Custom && PrefixedHmacOrShaRegex.IsMatch(value));
            if (ContainsSensitivePattern(value, skipSsn: isConstrainedOpaque))
            {
                return RedactedSensitiveValue;
            }

            return kind switch
            {
                KeySchemaKind.Numeric or KeySchemaKind.Boolean => RedactedSensitiveValue,
                KeySchemaKind.BaseModel => IsSafeBaseModel(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.DatasetHash => DatasetHashRegex.IsMatch(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.Jurisdiction => JurisdictionValues.Contains(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.WarrantyType => WarrantyTypeValues.Contains(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.ProductType => ProductTypeValues.Contains(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.StatuteCode => SanitizeStatuteCode(value),
                KeySchemaKind.HospitalId => HospitalIdRegex.IsMatch(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.CptCode => CptCodeRegex.IsMatch(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.ServiceInstanceId => ServiceInstanceIdRegex.IsMatch(value) ? value : RedactedSensitiveValue,
                KeySchemaKind.RuleIds => SanitizeRuleIdsCsv(value),
                KeySchemaKind.StrictToken => SanitizeStrictToken(key, value),
                _ => (OpaqueDigestRegex.IsMatch(value) &&
                      (customValueDomains == null || !customValueDomains.TryGetValue(key, out var customDomain) ||
                       (!IsProhibitedCustomDomainKey(key) && customDomain.Contains(value))))
                    ? value
                    : RedactedSensitiveValue,
            };
        }
        catch (RegexMatchTimeoutException)
        {
            return RedactedSensitiveValue;
        }
    }

    public static bool ContainsSensitivePattern(string value) =>
        ContainsSensitivePattern(value, skipSsn: false);

    private static bool ContainsSensitivePattern(string value, bool skipSsn)
    {
        if (value is null || value.Length > MaxPatternCheckLength)
        {
            return true;
        }

        try
        {
            if (ControlOrMultilineRegex.IsMatch(value) ||
                EmailRegex.IsMatch(value) ||
                (!skipSsn && SsnRegex.IsMatch(value)) ||
                DelimitedCardRegex.IsMatch(value) ||
                SecretTokenRegex.IsMatch(value) ||
                LocalPathRegex.IsMatch(value))
            {
                return true;
            }

            foreach (Match match in ContiguousCardIinRegex.Matches(value))
            {
                if (PassesLuhn(match.Value))
                {
                    return true;
                }
            }
            return false;
        }
        catch (RegexMatchTimeoutException)
        {
            return true;
        }
    }

    public static string SanitizeSpanName(string? name, bool allowRawPayloads = false)
    {
        if (string.IsNullOrEmpty(name))
        {
            return "[REDACTED_SPAN_NAME]";
        }
        if (allowRawPayloads)
        {
            return name.Length > MaxStringLength ? FormatTruncatedDigest(name) : name;
        }
        return name.Length <= 128 && IsSafeEventName(name) && !ContainsSensitivePattern(name)
            ? name
            : "[REDACTED_SPAN_NAME]";
    }

    public static string SanitizeAllowlistedStringValue(string key, string value)
    {
        if (value is null) return RedactedSensitiveValue;
        return SanitizeStringForSchema(key, value, allowRawPayloads: false);
    }

    public object SanitizeValue(string key, object value, bool allowRawPayloads = false)
    {
        if (!allowRawPayloads &&
            (string.IsNullOrWhiteSpace(key) ||
             !_allowedKeys.ContainsKey(key) ||
             (!IsExplicitSafeSchemaKey(key) && !IsSafeCustomDomainKey(key))))
        {
            return RedactedNotAllowlisted;
        }

        if (value is null)
        {
            return RedactedSensitiveValue;
        }

        if (value is string s)
        {
            if (!allowRawPayloads &&
                _customValueDomains.TryGetValue(key, out var registeredDomain) &&
                s != RedactedSensitiveValue &&
                !TruncatedHashRegex.IsMatch(s))
            {
                if (IsProhibitedCustomDomainKey(key))
                {
                    return RedactedSensitiveValue;
                }
                if (key.Equals("rule_ids", StringComparison.OrdinalIgnoreCase))
                {
                    if (s.Length == 0)
                    {
                        return RedactedSensitiveValue;
                    }
                    if (s.Length > MaxRuleIdsCsvLength)
                    {
                        return FormatTruncatedDigest(s);
                    }
                    var parts = s.Split(',');
                    if (parts.Length > MaxRuleIds ||
                        !Array.TrueForAll(parts, part => registeredDomain.Contains(part)))
                    {
                        return RedactedSensitiveValue;
                    }
                }
                else if (!registeredDomain.Contains(s))
                {
                    return RedactedSensitiveValue;
                }
            }
            return SanitizeStringForSchema(key, s, allowRawPayloads, _customValueDomains);
        }

        var isExplicitSafePrimitiveKey =
            DefaultKeysSet.Contains(key) ||
            RegisteredNumericKeys.Contains(key) ||
            BooleanOnlyKeys.Contains(key);
        if (!allowRawPayloads &&
            !isExplicitSafePrimitiveKey &&
            (IsProhibitedCustomDomainKey(key) || ContainsSensitivePattern(key)))
        {
            return RedactedSensitiveValue;
        }

        var hasRegisteredDomain = _customValueDomains.ContainsKey(key);
        if (IsFiniteNumeric(value))
        {
            if (hasRegisteredDomain && !allowRawPayloads)
            {
                return RedactedSensitiveValue;
            }
            var kind = ClassifyKeyKind(key);
            return allowRawPayloads || kind == KeySchemaKind.Numeric
                ? value
                : RedactedSensitiveValue;
        }

        if (value is bool)
        {
            if (hasRegisteredDomain && !allowRawPayloads)
            {
                return RedactedSensitiveValue;
            }
            var kind = ClassifyKeyKind(key);
            return allowRawPayloads || kind == KeySchemaKind.Boolean || kind == KeySchemaKind.Custom
                ? value
                : RedactedSensitiveValue;
        }

        if (key.Equals("rule_ids", StringComparison.OrdinalIgnoreCase) &&
            value is System.Collections.IEnumerable seq)
        {
            return SanitizeRuleIdsSequence(seq, allowRawPayloads, _customValueDomains);
        }

        return RedactedSensitiveValue;
    }

    public Dictionary<string, object> Sanitize(
        IDictionary<string, object> attributes,
        bool allowRawPayloads = false)
    {
        var sanitized = new Dictionary<string, object>();

        foreach (var kv in attributes)
        {
            if (!allowRawPayloads &&
                (string.IsNullOrWhiteSpace(kv.Key) ||
                 !IsAllowed(kv.Key) ||
                 (!IsExplicitSafeSchemaKey(kv.Key) && !IsSafeCustomDomainKey(kv.Key))))
            {
                sanitized[RedactedUnallowlistedKey] = RedactedNotAllowlisted;
                continue;
            }
            var outputKey = allowRawPayloads && kv.Key.Length > MaxStringLength
                ? FormatTruncatedDigest(kv.Key)
                : kv.Key;
            sanitized[outputKey] = SanitizeValue(kv.Key, kv.Value, allowRawPayloads);
        }

        if (!allowRawPayloads)
        {
            RedactPatientQuasiIdentifierTriad(sanitized);
        }

        return sanitized;
    }
}
