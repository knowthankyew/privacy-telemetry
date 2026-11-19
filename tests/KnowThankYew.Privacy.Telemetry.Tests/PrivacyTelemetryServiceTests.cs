using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Configuration;
using KnowThankYew.Privacy.Telemetry.Core;
using KnowThankYew.Privacy.Telemetry.OpenTelemetry;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

// Sole assembly-level CollectionBehavior declaration: serializes all xUnit tests in this assembly because
// ActivitySource.AddActivityListener and DistributedContextPropagator.Current are process-global singletons.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace KnowThankYew.Privacy.Telemetry.Tests;

[Collection("ActivityListenerTests")]
public sealed class PrivacyTelemetryServiceTests
{
    private static IConfiguration CreateConfig(string mode = "memory_only", string? otlpEndpoint = null, bool burnEnabled = true)
    {
        var dict = new Dictionary<string, string?>
        {
            ["Telemetry:Mode"] = mode,
            ["Telemetry:OtlpEndpoint"] = otlpEndpoint,
            ["Privacy:BurnEnabled"] = burnEnabled.ToString().ToLowerInvariant(),
            ["Privacy:NetworkEgress"] = mode == "otlp" ? "allow_otlp" : "deny"
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(dict)
            .Build();
    }

    private static PrivacyTelemetryService CreateOtlpService(SafeAllowlist? allowlist = null) =>
        new(configuration: CreateConfig("otlp", "http://localhost:4318/v1/traces"), allowlist: allowlist);

    [Fact]
    public void RecordSpan_SanitizesNonAllowlistedAttributes()
    {
        var config = CreateConfig();
        var telemetry = new PrivacyTelemetryService(configuration: config);

        var attrs = new Dictionary<string, object>
        {
            ["dataset_hash"] = "abc123def456",
            ["device"] = "mps",
            ["patient_name"] = "Confidential Patient",
            ["ssn"] = "000-11-2222",
            ["prompt"] = "Confidential Prompt Text"
        };

        telemetry.RecordSpan("audit_performed", "job-100", "OK", 50, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        var span = spans[0];

        Assert.Equal("audit_performed", span.Name);
        Assert.Equal("job-100", span.Attributes["job_id"]);
        Assert.Equal("OK", span.Attributes["status"]);
        Assert.Equal("mps", span.Attributes["device"]);
        Assert.Equal("abc123def456", span.Attributes["dataset_hash"]);

        // Prohibited keys must be redacted fail-closed without retaining unregistered key text
        Assert.False(span.Attributes.ContainsKey("patient_name"));
        Assert.False(span.Attributes.ContainsKey("ssn"));
        Assert.False(span.Attributes.ContainsKey("prompt"));
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", span.Attributes["[REDACTED_KEY]"]);
    }

    [Fact]
    public void RecordSpan_TruncatesOversizedStrings()
    {
        var config = CreateConfig();
        var telemetry = new PrivacyTelemetryService(configuration: config);

        var longString = new string('X', 300);
        var attrs = new Dictionary<string, object>
        {
            ["rule_id"] = longString
        };

        telemetry.RecordSpan("parse_bill", "job-200", "OK", 10, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        Assert.Equal("[TRUNCATED_HASH_bbd2c3dd]", spans[0].Attributes["rule_id"]);
    }

    [Fact]
    public void RecordSpan_AllowsCustomDomainKeys()
    {
        var config = CreateConfig();
        var allowlist = new SafeAllowlist(new[] { "cpt_code", "hospital_id" });
        var telemetry = new PrivacyTelemetryService(configuration: config, allowlist: allowlist);

        var attrs = new Dictionary<string, object>
        {
            ["cpt_code"] = "99213",
            ["hospital_id"] = "HOSP-001",
            ["patient_diagnosis"] = "Confidential"
        };

        telemetry.RecordSpan("audit_medical_bill", "job-300", "OK", 25, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        Assert.Equal("99213", spans[0].Attributes["cpt_code"]);
        Assert.Equal("HOSP-001", spans[0].Attributes["hospital_id"]);
        Assert.False(spans[0].Attributes.ContainsKey("patient_diagnosis"));
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", spans[0].Attributes["[REDACTED_KEY]"]);
    }

    [Fact]
    public void Burn_PurgesBufferAndEnforcesTombstone()
    {
        var config = CreateConfig();
        var telemetry = new PrivacyTelemetryService(configuration: config);

        telemetry.RecordSpan("scan_started", "j-1", "OK");
        telemetry.RecordSpan("rules_evaluated", "j-2", "OK");
        // Need matching assertion? Keep lines untouched below:
        Assert.Equal(2, telemetry.GetBufferedSpans().Count);

        telemetry.Burn();
        Assert.Empty(telemetry.GetBufferedSpans());

        // Subsequent span is rejected by tombstone
        telemetry.RecordSpan("scan_completed", "j-3", "OK");
        Assert.Empty(telemetry.GetBufferedSpans());
    }

    [Fact]
    public void GetPrivacyAuditReport_ReportsHonestObservability()
    {
        // Consumer air-gapped mode
        var localConfig = CreateConfig("memory_only", null);
        var localTelemetry = new PrivacyTelemetryService(configuration: localConfig);
        var localReport = localTelemetry.GetPrivacyAuditReport();

        Assert.True(localReport.IsLocalOnlyHonest);
        Assert.Equal("memory_only", localReport.TelemetryMode);
        Assert.Equal("deny", localReport.NetworkEgress);
        Assert.Null(localReport.OtlpEndpoint);

        // Enterprise mode
        var enterpriseConfig = CreateConfig("otlp", "http://otel-collector:4318/v1/traces");
        var enterpriseTelemetry = new PrivacyTelemetryService(configuration: enterpriseConfig);
        var enterpriseReport = enterpriseTelemetry.GetPrivacyAuditReport();

        Assert.False(enterpriseReport.IsLocalOnlyHonest);
        Assert.Equal("otlp", enterpriseReport.TelemetryMode);
        Assert.Equal("allow_otlp", enterpriseReport.NetworkEgress);
        Assert.Equal("http://otel-collector:4318/v1/traces", enterpriseReport.OtlpEndpoint);
    }

    [Fact]
    public void RecordSpan_RedactsSensitiveValuesAndFreeTextInAllowlistedKeys()
    {
        var config = CreateConfig();
        var allowlist = new SafeAllowlist(new[] { "adapter_path", "dataset_relative_path" });
        var telemetry = new PrivacyTelemetryService(configuration: config, allowlist: allowlist);

        var attrs = new Dictionary<string, object>
        {
            ["rule_id"] = "Tenant owes $1500 rent for Apt 2",
            ["statute_code"] = "user@example.com",
            ["jurisdiction"] = "District of Columbia",
            ["device"] = "/Users/alice/private/device",
            ["adapter_path"] = "/Users/alice/adapters/run1",
            ["dataset_relative_path"] = "nested/dir/job-1.jsonl"
        };

        telemetry.RecordSpan("evaluate_lease_rules", "job-400", "line1\nline2", 15, attrs);

        var span = Assert.Single(telemetry.GetBufferedSpans());
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Status);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["status"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["rule_id"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["statute_code"]);
        Assert.Equal("District of Columbia", span.Attributes["jurisdiction"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["device"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["adapter_path"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, span.Attributes["dataset_relative_path"]);

        telemetry.RecordSpan("evaluate_edge_semantic_lora", "job-401", "OK", 10, new Dictionary<string, object>
        {
            ["adapter_path"] = "hmac:0123456789abcdef",
            ["dataset_relative_path"] = "job-401.jsonl"
        });
        var second = telemetry.GetBufferedSpans()[1];
        Assert.Equal("OK", second.Status);
        Assert.Equal("hmac:0123456789abcdef", second.Attributes["adapter_path"]);
        Assert.Equal("job-401.jsonl", second.Attributes["dataset_relative_path"]);

        telemetry.RecordSpan("scan_started", "job-402", "Patient Jane Doe", 5);
        var third = telemetry.GetBufferedSpans()[2];
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, third.Status);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, third.Attributes["status"]);
    }

    [Fact]
    public void SanitizeValue_EnforcesPerKeySchemasAndRejectsNonScalarOrNonFiniteValues()
    {
        var allowlist = new SafeAllowlist(new[]
        {
            "adapter_path",
            "dataset_relative_path",
            "report_path",
            "findings_count",
            "charity_eligible",
            "hospital_id",
            "agreement_title",
            "warranty_type",
            "product_type",
            "rule_ids"
        });

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("adapter_path", "sha256:0123456789abcdef"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("adapter_path", "hmac:0123"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", "Alice Smith owes $1500"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", "Alice.Smith.medical.pdf"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", "job-1.txt"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", "job.foo.jsonl"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", "run-12.log"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", "Jane_Doe_HIV_positive.pdf"));
        Assert.Equal("hmac:0123456789abcdef", allowlist.SanitizeValue("report_path", "hmac:0123456789abcdef"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("duration_ms", double.NaN));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("step", double.PositiveInfinity));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("findings_count", "3"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("charity_eligible", "true"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("loss", new { Leak = "123-45-6789" }));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("device", new[] { 1, 2, 3 }));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("action", null!));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "Tenant Alice Smith owes $1500"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("warranty_type", "Uncontrolled prose"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("product_type", "Alice Smith order"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("agreement_title", "Alice Smith Gym Contract"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_ids", new[] { "AR-001", "Alice Smith" }));

        Assert.Equal("hmac:0123456789abcdef", allowlist.SanitizeValue("adapter_path", "hmac:0123456789abcdef"));
        Assert.Equal("job-999.jsonl", allowlist.SanitizeValue("dataset_relative_path", "job-999.jsonl"));
        Assert.Equal(4, allowlist.SanitizeValue("findings_count", 4));
        Assert.Equal(true, allowlist.SanitizeValue("charity_eligible", true));
        Assert.Equal("cleveland-clinic-main", allowlist.SanitizeValue("hospital_id", "cleveland-clinic-main"));
        Assert.Equal("29 U.S.C. § 206", allowlist.SanitizeValue("statute_code", "29 U.S.C. § 206"));
        Assert.Equal("Disclaimed / As-Is", allowlist.SanitizeValue("warranty_type", "Disclaimed / As-Is"));
        Assert.Equal("Electronics & Laptops", allowlist.SanitizeValue("product_type", "Electronics & Laptops"));
        Assert.Equal(new[] { "AR-001", "CA-SEC-DEP-CAP-01" }, allowlist.SanitizeValue("rule_ids", new[] { "AR-001", "CA-SEC-DEP-CAP-01" }));
    }

    [Fact]
    public void SanitizeValue_TruncatesRawPayloadsOver256AndCatchesMultipleLuhnCards()
    {
        var allowlist = new SafeAllowlist();

        var rawTruncated = allowlist.SanitizeValue("custom_raw", new string('R', 300), allowRawPayloads: true) as string;
        Assert.NotNull(rawTruncated);
        Assert.StartsWith("[TRUNCATED_HASH_", rawTruncated);
        Assert.DoesNotContain("RRRR", rawTruncated);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("bad_obj", new { Secret = "pii" }, allowRawPayloads: true));
        Assert.Equal("dev debug note", allowlist.SanitizeValue("custom_raw", "dev debug note", allowRawPayloads: true));

        Assert.Equal(
            SafeAllowlist.RedactedSensitiveValue,
            allowlist.SanitizeValue("rule_id", "4111111111111112 4111111111111111")
        );

        // Direct pattern check + negative control verify scanning continues after an invalid Luhn candidate.
        Assert.True(SafeAllowlist.ContainsSensitivePattern("4111111111111112 4111111111111111"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("4111111111111112 4111111111111113"));

        // Verify idempotency for repeated sanitization of long rule_ids CSV and digest markers,
        // and verify finite item-count (MaxRuleIds = 50) and length (MaxRuleIdsCsvLength = 3600) bounds.
        var longCsv = string.Join(",", Enumerable.Range(0, 5).Select(i => "hmac:" + new string((char)('a' + i), 59)));
        var ruleAllowlist = new SafeAllowlist(new[] { "rule_ids" });
        Assert.Equal(longCsv, ruleAllowlist.SanitizeValue("rule_ids", longCsv));
        var tooManyRuleIdsCsv = string.Join(",", Enumerable.Range(0, 51).Select(_ => "AR-1"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, ruleAllowlist.SanitizeValue("rule_ids", tooManyRuleIdsCsv));
        var oversizedRuleIdsCsv = string.Join(",", Enumerable.Range(0, 60).Select(_ => "hmac:" + new string('a', 64)));
        var truncatedOversizedRuleIds = Assert.IsType<string>(ruleAllowlist.SanitizeValue("rule_ids", oversizedRuleIdsCsv));
        Assert.StartsWith("[TRUNCATED_HASH_", truncatedOversizedRuleIds);
        var firstTrunc = ruleAllowlist.SanitizeValue("rule_id", new string('Z', 300));
        Assert.Equal(firstTrunc, ruleAllowlist.SanitizeValue("rule_id", firstTrunc));
    }

    [Fact]
    public void SanitizeValue_EnforcesMastercard2SeriesStrictStatutesAndPathPrecedence()
    {
        var allowlist = new SafeAllowlist(new[]
        {
            "rule_id",
            "rule_ids",
            "adapter_path",
            "dataset_relative_path",
            "report_path"
        });

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_id", "2223000048400011"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_ids", new[] { "2223000048400011" }));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_id", "2223000048400012"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_id", "2220000000000000"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_id", "2721000000000004"));
        Assert.True(SafeAllowlist.ContainsSensitivePattern("2223000048400011"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("2223000048400012"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("2220000000000000"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("2721000000000004"));

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "Tenant Alice Smith 42 Code"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "Cal. Alice Smith § 42"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "123 SMITH 456"));
        Assert.Equal("123 SMITH 456", allowlist.SanitizeValue("statute_code", "123 SMITH 456", allowRawPayloads: true));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "42 USC 1.JaneDoe_HIV"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "815 ILCS 601/Jane_Doe"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("statute_code", "EU GDPR Art. 6.JaneDoe_HIV"));
        Assert.Equal("29 U.S.C. § 206", allowlist.SanitizeValue("statute_code", "29 U.S.C. § 206"));
        Assert.Equal("26 C.F.R. § 1.501(r)-6", allowlist.SanitizeValue("statute_code", "26 C.F.R. § 1.501(r)-6"));
        Assert.Equal("Or. Rev. Stat. § 646A.295", allowlist.SanitizeValue("statute_code", "Or. Rev. Stat. § 646A.295"));
        Assert.Equal("Cal. Bus. & Prof. Code § 17602(a)(2)", allowlist.SanitizeValue("statute_code", "Cal. Bus. & Prof. Code § 17602(a)(2)"));
        Assert.Equal("740 ILCS 14/", allowlist.SanitizeValue("statute_code", "740 ILCS 14/"));
        Assert.Equal("16 CFR Part 425", allowlist.SanitizeValue("statute_code", "16 CFR Part 425"));
        Assert.Equal("815 ILCS 601", allowlist.SanitizeValue("statute_code", "815 ILCS 601"));
        Assert.Equal("Mass. Gen. Laws ch. 149 § 150", allowlist.SanitizeValue("statute_code", "Mass. Gen. Laws ch. 149 § 150"));
        Assert.Equal("UCC § 2-314", allowlist.SanitizeValue("statute_code", "UCC § 2-314"));
        Assert.Equal("EU GDPR Art. 6", allowlist.SanitizeValue("statute_code", "EU GDPR Art. 6"));
        Assert.Equal(
            "UK Consumer Rights Act 2015, Part 1, Section 9",
            allowlist.SanitizeValue("statute_code", "UK Consumer Rights Act 2015, Part 1, Section 9")
        );

        var longPath = "/Users/alice/" + new string('a', 300);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("adapter_path", longPath));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("adapter_path", "[TRUNCATED_HASH_12345678]"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", longPath));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_relative_path", "[TRUNCATED_HASH_12345678]"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", longPath));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", "[TRUNCATED_HASH_12345678]"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", "run-12.log"));
        Assert.Equal("hmac:0123456789abcdef", allowlist.SanitizeValue("report_path", "hmac:0123456789abcdef"));
    }

    [Fact]
    public async Task RecordSpan_PreSanitizesActivityTagsBeforeUnwrappedExporterListenersRun()
    {
        var startedObserved = new Dictionary<string, object?>();
        var stoppedObserved = new Dictionary<string, object?>();
        const string spanOp = "audit_performed";

        using var unwrappedExporter = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName != spanOp) return;
                foreach (var kv in act.TagObjects)
                {
                    startedObserved[kv.Key] = kv.Value;
                }
            },
            ActivityStopped = act =>
            {
                if (act.OperationName != spanOp) return;
                foreach (var kv in act.TagObjects)
                {
                    stoppedObserved[kv.Key] = kv.Value;
                }
            }
        };
        System.Diagnostics.ActivitySource.AddActivityListener(unwrappedExporter);

        var telemetry = CreateOtlpService();
        telemetry.RecordSpan(spanOp, "job-1", "OK", 12, new Dictionary<string, object>
        {
            ["unauthorized_key"] = "secret",
            ["alice@example.com"] = "secret2",
            ["status"] = "alice@example.com",
            ["action"] = "scan_complete"
        });

        Assert.False(startedObserved.ContainsKey("unauthorized_key"));
        Assert.False(startedObserved.ContainsKey("alice@example.com"));
        Assert.False(startedObserved.ContainsKey("[REDACTED_KEY]"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, startedObserved["status"]);
        Assert.Equal("scan_complete", startedObserved["action"]);
        Assert.Equal(startedObserved, stoppedObserved);
        var buffered = Assert.Single(telemetry.GetBufferedSpans());
        Assert.False(buffered.Attributes.ContainsKey("unauthorized_key"));
        Assert.False(buffered.Attributes.ContainsKey("alice@example.com"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, buffered.Attributes["[REDACTED_KEY]"]);

        var customNumericAllowlist = new SafeAllowlist(new[]
        {
            "employee_ssn",
            "redflag_count",
            "matched_count",
            "ssn_count",
            "arbitrary_custom_count",
            "is_patient_pregnant",
            "has_income_verified",
            "rule_ids"
        });
        Assert.False(customNumericAllowlist.IsAllowed("employee_ssn"));
        Assert.False(customNumericAllowlist.IsAllowed("ssn_count"));
        Assert.False(customNumericAllowlist.IsAllowed("is_patient_pregnant"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, customNumericAllowlist.SanitizeValue("employee_ssn", 123456789));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, customNumericAllowlist.SanitizeValue("employee_ssn", true));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, customNumericAllowlist.SanitizeValue("ssn_count", 123456789));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, customNumericAllowlist.SanitizeValue("matched_count", 42));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, customNumericAllowlist.SanitizeValue("arbitrary_custom_count", 42));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, customNumericAllowlist.SanitizeValue("is_patient_pregnant", true));
        Assert.Equal(123456789, customNumericAllowlist.SanitizeValue("employee_ssn", 123456789, allowRawPayloads: true));
        Assert.Equal(123456789, customNumericAllowlist.SanitizeValue("ssn_count", 123456789, allowRawPayloads: true));
        Assert.Equal(42, customNumericAllowlist.SanitizeValue("redflag_count", 42));
        Assert.Equal(true, customNumericAllowlist.SanitizeValue("has_income_verified", true));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, customNumericAllowlist.SanitizeValue("has_income_verified", 150000));

        var postBurnStarted = 0;
        var postBurnStopped = 0;
        const string burnOp = "rules_evaluated";
        using var burnListener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName == burnOp) postBurnStarted++;
            },
            ActivityStopped = act =>
            {
                if (act.OperationName == burnOp) postBurnStopped++;
            }
        };
        System.Diagnostics.ActivitySource.AddActivityListener(burnListener);

        var reentrantTelemetry = CreateOtlpService(customNumericAllowlist);
        reentrantTelemetry.RecordSpan(burnOp, "job-burn", "OK", 5, new Dictionary<string, object>
        {
            ["rule_ids"] = new BurningRuleIdsEnumerable(reentrantTelemetry)
        });

        Assert.Equal(0, postBurnStarted);
        Assert.Equal(0, postBurnStopped);
        Assert.True(reentrantTelemetry.IsBurned);
        Assert.Empty(reentrantTelemetry.GetBufferedSpans());

        // Same-thread ActivityStarted callback invoking Burn() must also discard the in-flight span.
        var startBurnService = CreateOtlpService();
        const string startBurnOp = "audit_performed";
        var uniqueJobId = $"job-{Guid.NewGuid():N}";
        var startBurnCallbacks = 0;
        var stopBurnCallbacks = 0;
        var exportedBurnedSpanCount = 0;
        System.Diagnostics.Activity? targetActivity = null;
        var safeStopExport = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            act =>
            {
                if (ReferenceEquals(act, targetActivity))
                {
                    Interlocked.Increment(ref exportedBurnedSpanCount);
                }
            });
        using var burnOnStartListener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName == startBurnOp &&
                    string.Equals(act.GetTagItem("job_id") as string, uniqueJobId, StringComparison.Ordinal))
                {
                    targetActivity = act;
                    startBurnCallbacks++;
                    // Calling Burn() synchronously inside ActivityStarted must not deadlock.
                    startBurnService.Burn();
                }
            },
            ActivityStopped = act =>
            {
                if (ReferenceEquals(act, targetActivity))
                {
                    stopBurnCallbacks++;
                    Assert.False(act.Recorded);
                    Assert.False(act.IsAllDataRequested);
                    safeStopExport(act);
                }
            }
        };
        System.Diagnostics.ActivitySource.AddActivityListener(burnOnStartListener);
        await Task.Run(() => startBurnService.RecordSpan(startBurnOp, uniqueJobId, "OK", 5)).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, startBurnCallbacks);
        Assert.Equal(1, stopBurnCallbacks);
        Assert.Equal(0, exportedBurnedSpanCount);
        Assert.Empty(startBurnService.GetBufferedSpans());
    }

    [Fact]
    public async Task RecordSpan_ConcurrentBurnDuringSanitization_DiscardsInFlightSpan()
    {
        // Cross-thread concurrent Burn() while RecordSpan() is mid-sanitization must discard the in-flight span.
        var concurrentAllowlist = new SafeAllowlist(new[] { "rule_ids" });
        var concurrentTelemetry = CreateOtlpService(concurrentAllowlist);
        const string burnOp = "segment_clauses";
        var concurrentJobId = $"job-{Guid.NewGuid():N}";
        var concurrentStarted = 0;
        var concurrentStopped = 0;
        using var concurrentListener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName == burnOp)
                {
                    Interlocked.Increment(ref concurrentStarted);
                }
            },
            ActivityStopped = act =>
            {
                if (act.OperationName == burnOp)
                {
                    Interlocked.Increment(ref concurrentStopped);
                }
            }
        };
        System.Diagnostics.ActivitySource.AddActivityListener(concurrentListener);

        // Control: verify the listener observes burnOp without requiring a job_id tag.
        var controlTelemetry = CreateOtlpService(concurrentAllowlist);
        controlTelemetry.RecordSpan(burnOp, entityId: null, "OK", 1);
        Assert.Equal(1, concurrentStarted);
        Assert.Equal(1, concurrentStopped);

        using var enteredSanitize = new ManualResetEventSlim(false);
        using var releaseSanitize = new ManualResetEventSlim(false);
        var burnTask = Task.Run(() =>
        {
            Assert.True(enteredSanitize.Wait(TimeSpan.FromSeconds(5)));
            concurrentTelemetry.Burn();
            releaseSanitize.Set();
        });

        concurrentTelemetry.RecordSpan(burnOp, concurrentJobId, "OK", 5, new Dictionary<string, object>
        {
            ["rule_ids"] = new PausedRuleIdsEnumerable(enteredSanitize, releaseSanitize)
        });

        await burnTask.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, concurrentStarted);
        Assert.Equal(1, concurrentStopped);
        Assert.Empty(concurrentTelemetry.GetBufferedSpans());
    }

    [Fact]
    public void RecordSpan_SanitizesInheritedTraceStateAndSamplingTagsBeforeActivityStarted()
    {
        var service = CreateOtlpService();
        const string opName = "evaluate_subscription_agreement";
        string? observedTraceState = "unobserved";
        object? observedSamplingLeak = "unobserved";
        object? observedStatus = null;
        var startCount = 0;

        using var parentActivity = new System.Diagnostics.Activity("ambient-parent");
        parentActivity.TraceStateString = "tenant=jane@example.com";
        parentActivity.Start();
        try
        {
            using var listener = new System.Diagnostics.ActivityListener
            {
                ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
                Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> options) =>
                {
                    options.SamplingTags.Add("raw_sampler_secret", "jane@example.com");
                    options.SamplingTags.Add("status", "raw\nvalue");
                    return System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded;
                },
                ActivityStarted = act =>
                {
                    if (act.OperationName == opName)
                    {
                        startCount++;
                        observedTraceState = act.TraceStateString;
                        observedSamplingLeak = act.GetTagItem("raw_sampler_secret");
                        observedStatus = act.GetTagItem("status");
                    }
                }
            };
            System.Diagnostics.ActivitySource.AddActivityListener(listener);

            service.RecordSpan(opName, "job-100", "OK", 3);
            Assert.Equal(1, startCount);
            Assert.Equal(string.Empty, observedTraceState);
            Assert.Null(observedSamplingLeak);
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, observedStatus);
        }
        finally
        {
            parentActivity.Stop();
        }
    }

    [Fact]
    public async Task RecordSpan_BurnAndStopInsideActivityStarted_DoesNotExport()
    {
        var service = CreateOtlpService();
        const string opName = "scan_started";
        var jobId = $"job-{Guid.NewGuid():N}";
        System.Diagnostics.Activity? targetActivity = null;
        var stopCallbacks = 0;
        var exportedCount = 0;
        var safeStop = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            act =>
            {
                if (ReferenceEquals(act, targetActivity))
                {
                    Interlocked.Increment(ref exportedCount);
                }
            });

        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName == opName &&
                    string.Equals(act.GetTagItem("job_id") as string, jobId, StringComparison.Ordinal))
                {
                    targetActivity = act;
                    service.Burn();
                    act.Stop();
                }
            },
            ActivityStopped = act =>
            {
                if (ReferenceEquals(act, targetActivity))
                {
                    stopCallbacks++;
                    safeStop(act);
                    Assert.False(act.Recorded);
                    Assert.False(act.IsAllDataRequested);
                }
            }
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        await Task.Run(() => service.RecordSpan(opName, jobId, "OK", 2)).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, stopCallbacks);
        Assert.Equal(0, exportedCount);
        Assert.Empty(service.GetBufferedSpans());
    }

    [Fact]
    public async Task CreateExporterSafeStopCallback_CoordinatesDispatchWithBurnWithoutDeadlock()
    {
        using var allowSourceListener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded
        };
        System.Diagnostics.ActivitySource.AddActivityListener(allowSourceListener);

        var service = CreateOtlpService();
        using var enteredExporter = new ManualResetEventSlim(false);
        using var releaseExporter = new ManualResetEventSlim(false);
        var inFlightDispatches = 0;

        var waitingSafeStop = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                Interlocked.Increment(ref inFlightDispatches);
                enteredExporter.Set();
                Assert.True(releaseExporter.Wait(TimeSpan.FromSeconds(5)));
            },
            allowRawPayloads: false,
            isBurned: () => service.IsBurned);

        using var preBurnActivity = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(preBurnActivity);
        preBurnActivity.Stop();

        var exporterTask = Task.Run(() => waitingSafeStop(preBurnActivity));
        Assert.True(enteredExporter.Wait(TimeSpan.FromSeconds(5)));

        var burnTask = Task.Run(() => service.Burn());
        // Wait for Burn() to enter drain and latch IsBurned before asserting it remains blocked on exporter dispatch.
        Assert.True(SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnTask.IsCompleted, 50));

        releaseExporter.Set();
        await exporterTask.WaitAsync(TimeSpan.FromSeconds(5));
        await burnTask.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, inFlightDispatches);

        // Once Burn() has completed, subsequent stop callbacks never reach exporterOnStop.
        using var postBurnActivity = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(postBurnActivity);
        Assert.True(postBurnActivity.Recorded);
        postBurnActivity.Stop();
        waitingSafeStop(postBurnActivity);
        Assert.Equal(1, inFlightDispatches);
        Assert.False(postBurnActivity.Recorded);

        // Reentrant synchronous Burn() inside exporterOnStop must not deadlock.
        var reentrantService = CreateOtlpService();
        var reentrantCount = 0;
        var reentrantSafeStop = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                Interlocked.Increment(ref reentrantCount);
                reentrantService.Burn();
            },
            allowRawPayloads: false,
            isBurned: () => reentrantService.IsBurned);

        using var reentrantAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(reentrantAct);
        reentrantAct.Stop();
        await Task.Run(() => reentrantSafeStop(reentrantAct)).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, reentrantCount);
        Assert.True(reentrantService.IsBurned);
    }

    [Fact]
    public async Task BurnServiceAndWait_PeerCallbacksCallingBurnConcurrently_DoNotDeadlock()
    {
        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = source => source.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        var service = CreateOtlpService();
        using var bothEntered = new Barrier(2);
        var completedCount = 0;

        var safeStop = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                Assert.True(bothEntered.SignalAndWait(TimeSpan.FromSeconds(5)));
                service.Burn();
                Interlocked.Increment(ref completedCount);
            },
            allowRawPayloads: false,
            isBurned: () => service.IsBurned);

        using var act1 = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        using var act2 = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(act1);
        Assert.NotNull(act2);
        act1.Stop();
        act2.Stop();

        var t1 = Task.Run(() => safeStop(act1));
        var t2 = Task.Run(() => safeStop(act2));

        await Task.WhenAll(t1, t2).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(2, completedCount);
        Assert.True(service.IsBurned);
    }

    [Fact]
    public async Task BurnServiceAndWait_BlockedServiceADoesNotBlockServiceB_WhileServiceABurnStillWaits()
    {
        // Part A: service-owned callback invoked during RecordSpan
        var serviceA = CreateOtlpService();
        var serviceB = CreateOtlpService();
        using var enteredA = new ManualResetEventSlim(false);
        using var releaseA = new ManualResetEventSlim(false);
        Action<System.Diagnostics.Activity>? stopHook = null;

        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = source => source.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stopHook?.Invoke(activity)
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        var safeStopA = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                enteredA.Set();
                Assert.True(releaseA.Wait(TimeSpan.FromSeconds(5)));
            },
            allowRawPayloads: false,
            isBurned: () => serviceA.IsBurned);
        stopHook = safeStopA;

        var recordATask = Task.Run(() => serviceA.RecordSpan("scan_started"));
        Assert.True(enteredA.Wait(TimeSpan.FromSeconds(5)));

        // Unrelated serviceB must burn immediately without blocking on serviceA's callback.
        await Task.Run(() => serviceB.Burn()).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(serviceB.IsBurned);

        // serviceA.Burn() must still wait for serviceA's in-flight callback.
        var burnATask = Task.Run(() => serviceA.Burn());
        Assert.True(SpinWait.SpinUntil(() => serviceA.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnATask.IsCompleted, 50));

        releaseA.Set();
        await Task.WhenAll(recordATask, burnATask).WaitAsync(TimeSpan.FromSeconds(5));
        stopHook = null;
        Assert.True(serviceA.IsBurned);

        // Part B: standalone CreateExporterSafeStopCallback with external isBurned delegate (no prior RecordSpan)
        var serviceC = CreateOtlpService();
        var serviceD = CreateOtlpService();
        using var enteredC = new ManualResetEventSlim(false);
        using var releaseC = new ManualResetEventSlim(false);

        var safeStopC = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                enteredC.Set();
                Assert.True(releaseC.Wait(TimeSpan.FromSeconds(5)));
            },
            allowRawPayloads: false,
            isBurned: () => serviceC.IsBurned);

        using var actC = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(actC);
        actC.Stop();

        var stopCTask = Task.Run(() => safeStopC(actC));
        Assert.True(enteredC.Wait(TimeSpan.FromSeconds(5)));

        await Task.Run(() => serviceD.Burn()).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(serviceD.IsBurned);

        var burnCTask = Task.Run(() => serviceC.Burn());
        Assert.True(SpinWait.SpinUntil(() => serviceC.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnCTask.IsCompleted, 50));

        releaseC.Set();
        await Task.WhenAll(stopCTask, burnCTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(serviceC.IsBurned);
    }

    [Fact]
    public async Task BurnServiceAndWait_ExternalIsBurnedCallingBurn_DoesNotDeadlock()
    {
        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = source => source.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        var service = CreateOtlpService();
        using var checkEntered = new ManualResetEventSlim(false);
        using var releaseCheck = new ManualResetEventSlim(false);
        var checkCalls = 0;
        var exporterCount = 0;

        var safeStop = KnowThankYew.Privacy.Telemetry.OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ => Interlocked.Increment(ref exporterCount),
            allowRawPayloads: false,
            isBurned: () =>
            {
                if (Interlocked.Increment(ref checkCalls) == 3)
                {
                    // Simulate an expiration check invoked after lease registration that burns the service
                    // while another thread is concurrently calling service.Burn().
                    checkEntered.Set();
                    Assert.True(releaseCheck.Wait(TimeSpan.FromSeconds(5)));
                    service.Burn();
                }
                return service.IsBurned;
            });

        using var act = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        act.Stop();

        var stopTask = Task.Run(() => safeStop(act));
        Assert.True(checkEntered.Wait(TimeSpan.FromSeconds(5)));

        var concurrentBurnTask = Task.Run(() => service.Burn());
        Assert.True(SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => concurrentBurnTask.IsCompleted, 50));
        releaseCheck.Set();

        await Task.WhenAll(stopTask, concurrentBurnTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(service.IsBurned);
        Assert.Equal(0, exporterCount);
    }

    [Fact]
    public async Task Burn_DoesNotReturnEarly_WhileConcurrentBurnRunsOnUnownedExternalExporterCallback()
    {
        const string sourceName = "KnowThankYew.R17.External";
        using var externalSource = new ActivitySource(sourceName);
        using var samplingListener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, externalSource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(samplingListener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var serviceA = CreateOtlpService();
        var serviceB = CreateOtlpService();
        using var exporterEntered = new ManualResetEventSlim(false);
        using var releaseExporter = new ManualResetEventSlim(false);
        var completedExports = 0;

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ =>
            {
                exporterEntered.Set();
                Assert.True(releaseExporter.Wait(TimeSpan.FromSeconds(5)));
                Interlocked.Increment(ref completedExports);
            },
            allowRawPayloads: false,
            isBurned: () => serviceA.IsBurned);

        using var act = externalSource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        act.Stop();

        var stopTask = Task.Run(() => safeStop(act));
        Assert.True(exporterEntered.Wait(TimeSpan.FromSeconds(5)));

        // Concurrent unrelated burn must not claim ownership of the unowned lease for serviceA.
        var burnBTask = Task.Run(() => serviceB.Burn());
        await burnBTask.WaitAsync(TimeSpan.FromSeconds(5));

        var burnATask = Task.Run(() => serviceA.Burn());
        Assert.True(SpinWait.SpinUntil(() => serviceA.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnATask.IsCompleted, 50));

        releaseExporter.Set();
        await Task.WhenAll(stopTask, burnATask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, completedExports);
        Assert.True(serviceA.IsBurned);
        Assert.True(serviceB.IsBurned);
    }

    [Fact]
    public async Task CreateExporterSafeStopCallback_BoundToService_CoordinatesDrainPerServiceOwner()
    {
        const string sourceName = "KnowThankYew.R17.Bound";
        using var externalSource = new ActivitySource(sourceName);
        using var samplingListener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, externalSource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(samplingListener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var serviceA = CreateOtlpService();
        var serviceB = CreateOtlpService();
        using var exporterEntered = new ManualResetEventSlim(false);
        using var releaseExporter = new ManualResetEventSlim(false);
        var completedExports = 0;

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ =>
            {
                exporterEntered.Set();
                Assert.True(releaseExporter.Wait(TimeSpan.FromSeconds(5)));
                Interlocked.Increment(ref completedExports);
            },
            serviceA);

        using var act = externalSource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        act.Stop();

        var stopTask = Task.Run(() => safeStop(act));
        Assert.True(exporterEntered.Wait(TimeSpan.FromSeconds(5)));

        // Unrelated serviceB drains immediately because lease owner is explicitly serviceA.
        var burnBTask = Task.Run(() => serviceB.Burn());
        await burnBTask.WaitAsync(TimeSpan.FromSeconds(5));

        var burnATask = Task.Run(() => serviceA.Burn());
        Assert.True(SpinWait.SpinUntil(() => serviceA.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnATask.IsCompleted, 50));

        releaseExporter.Set();
        await Task.WhenAll(stopTask, burnATask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, completedExports);

        using var postBurnAct = externalSource.StartActivity("scan_started")!;
        Assert.NotNull(postBurnAct);
        postBurnAct.Stop();
        safeStop(postBurnAct);
        Assert.Equal(1, completedExports);
    }

    [Fact]
    public void CreateSanitizingListener_WithBurnPredicate_AttachesBurnCheckOnStart()
    {
        var service = CreateOtlpService();
        const string sourceName = "KnowThankYew.R17.Listener";
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        using var source = new ActivitySource(sourceName);
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            allowRawPayloads: false,
            shouldListenTo: s => ReferenceEquals(s, source),
            isBurned: () => service.IsBurned);
        ActivitySource.AddActivityListener(listener);

        using var act = source.StartActivity("scan_started")!;
        Assert.NotNull(act);
        Assert.True(act.IsAllDataRequested);

        act.SetSanitizedTag("rule_id", "AR-001", allowlist);
        Assert.Contains(act.TagObjects, kv => kv.Key == "rule_id" && Equals(kv.Value, "AR-001"));

        service.Burn();

        act.SetSanitizedTag("finding_category", "auto_renewal", allowlist);
        PrivacyActivityEnricher.AddSanitizedEvent(
            act,
            "rules_evaluated",
            allowlist,
            new[] { new KeyValuePair<string, object?>("rule_id", "AR-002") });

        Assert.Empty(act.TagObjects);
        Assert.Empty(act.Events);
        Assert.False(act.IsAllDataRequested);
        Assert.Equal(ActivityTraceFlags.None, act.ActivityTraceFlags & ActivityTraceFlags.Recorded);
    }

    [Fact]
    public async Task CreateExporterSafeStopCallback_AndListenerWithDistinctServices_CoordinatesDrainForAllOwners()
    {
        const string sourceName = "KnowThankYew.R18.MultiOwner";
        const string childSourceName = "KnowThankYew.R18.MultiOwner.Child";
        using var externalSource = new ActivitySource(sourceName);
        using var childSource = new ActivitySource(childSourceName);
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName, childSourceName });
        var serviceA = CreateOtlpService();
        var serviceB = CreateOtlpService();
        var serviceC = CreateOtlpService();

        using var listenerA = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            serviceA,
            shouldListenTo: s => ReferenceEquals(s, externalSource));
        using var childSamplingListener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, childSource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listenerA);
        ActivitySource.AddActivityListener(childSamplingListener);

        using var exporterEntered = new ManualResetEventSlim(false);
        using var releaseExporter = new ManualResetEventSlim(false);
        var completedExports = 0;

        var safeStopB = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ =>
            {
                exporterEntered.Set();
                Assert.True(releaseExporter.Wait(TimeSpan.FromSeconds(5)));
                Interlocked.Increment(ref completedExports);
            },
            serviceB);

        using var parentAct = externalSource.StartActivity("job.accepted")!;
        Assert.NotNull(parentAct);
        using var act = childSource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        Assert.Same(parentAct, act.Parent);
        act.Stop();

        var stopTask = Task.Run(() => safeStopB(act));
        Assert.True(exporterEntered.Wait(TimeSpan.FromSeconds(5)));

        // Unrelated serviceC burns immediately; both attached owner serviceA and explicit owner serviceB wait.
        var burnCTask = Task.Run(() => serviceC.Burn());
        await burnCTask.WaitAsync(TimeSpan.FromSeconds(5));

        var burnATask = Task.Run(() => serviceA.Burn());
        var burnBTask = Task.Run(() => serviceB.Burn());
        Assert.True(SpinWait.SpinUntil(() => serviceA.IsBurned && serviceB.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnATask.IsCompleted, 50));
        Assert.False(SpinWait.SpinUntil(() => burnBTask.IsCompleted, 50));

        releaseExporter.Set();
        await Task.WhenAll(stopTask, burnATask, burnBTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, completedExports);
    }

    [Fact]
    public void CreateSanitizingListener_BoundToServiceA_DoesNotSuppressServiceBRecordSpanWhenServiceABurns()
    {
        var allowlist = new SafeAllowlist();
        var serviceA = CreateOtlpService();
        var serviceB = CreateOtlpService();
        var exportedRecorded = 0;

        using var listenerA = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, serviceA);
        using var exporterListenerB = new ActivityListener
        {
            ShouldListenTo = s => s.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = act =>
            {
                if (Equals(act.GetTagItem("action"), "scan_complete") &&
                    (act.ActivityTraceFlags & ActivityTraceFlags.Recorded) != 0)
                {
                    Interlocked.Increment(ref exportedRecorded);
                }
            }
        };
        ActivitySource.AddActivityListener(listenerA);
        ActivitySource.AddActivityListener(exporterListenerB);

        serviceA.Burn();
        serviceB.RecordSpan(
            "scan_started",
            "job-r19-isolation",
            "OK",
            5,
            new Dictionary<string, object> { ["action"] = "scan_complete" });

        Assert.Equal(1, serviceB.GetPrivacyAuditReport().ActiveSpanCount);
        Assert.Equal(1, exportedRecorded);
    }

    [Fact]
    public void SanitizeActivity_UnstartedChildUnderAmbientParent_BlocksInheritedTraceStateString()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist();
        using var child = PrivacyTelemetryService.ActivitySource.CreateActivity("scan_started", ActivityKind.Internal)!;
        Assert.NotNull(child);
        Assert.Null(child.TraceStateString);

        PrivacyActivityEnricher.SanitizeActivity(child, allowlist);

        using var parent = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(parent);
        parent.TraceStateString = "tenant=acme-sensitive";

        child.Start();
        try
        {
            Assert.Same(parent, child.Parent);
            Assert.Equal(string.Empty, child.TraceStateString);
        }
        finally
        {
            child.Stop();
            parent.Stop();
        }
    }

    [Fact]
    public async Task Burn_RepeatedCall_DrainsActiveUnownedExporterCallback()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var service = CreateOtlpService();
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            new SafeAllowlist(),
            _ =>
            {
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(5)));
            },
            allowRawPayloads: false,
            isBurned: () => service.IsBurned);

        using var act = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        act.Stop();

        var stopTask = Task.Run(() => safeStop(act));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

        var firstBurnTask = Task.Run(() => service.Burn());
        Assert.True(SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));

        using var secondBurnEntered = new ManualResetEventSlim(false);
        var secondBurnTask = Task.Run(() =>
        {
            secondBurnEntered.Set();
            service.Burn();
        });
        Assert.True(secondBurnEntered.Wait(TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => firstBurnTask.IsCompleted || secondBurnTask.IsCompleted, 50));

        release.Set();
        await Task.WhenAll(stopTask, firstBurnTask, secondBurnTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(service.IsBurned);
    }

    [Fact]
    public async Task Burn_DuringActivityStartedCallback_DrainsBeforeReturningAndBlocksPostBurnPublication()
    {
        var preBurnJobId = Guid.NewGuid().ToString("N");
        var postBurnJobId = Guid.NewGuid().ToString("N");
        using var startedEntered = new ManualResetEventSlim(false);
        using var releaseStarted = new ManualResetEventSlim(false);
        var postBurnStartedCount = 0;

        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                var jobId = act.GetTagItem("job_id")?.ToString();
                if (string.Equals(jobId, preBurnJobId, StringComparison.Ordinal))
                {
                    startedEntered.Set();
                    Assert.True(releaseStarted.Wait(TimeSpan.FromSeconds(5)));
                }
                else if (string.Equals(jobId, postBurnJobId, StringComparison.Ordinal))
                {
                    Interlocked.Increment(ref postBurnStartedCount);
                }
            }
        };
        ActivitySource.AddActivityListener(listener);

        var service = CreateOtlpService();
        var recordTask = Task.Run(() => service.RecordSpan(
            "scan_started",
            preBurnJobId,
            "OK",
            1,
            new Dictionary<string, object> { ["action"] = "scan_started" }));

        Assert.True(startedEntered.Wait(TimeSpan.FromSeconds(5)));

        var burnTask = Task.Run(() => service.Burn());
        Assert.True(SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));
        Assert.False(SpinWait.SpinUntil(() => burnTask.IsCompleted, 50));

        releaseStarted.Set();
        await Task.WhenAll(recordTask, burnTask).WaitAsync(TimeSpan.FromSeconds(5));

        service.RecordSpan(
            "scan_started",
            postBurnJobId,
            "OK",
            1,
            new Dictionary<string, object> { ["action"] = "scan_started" });

        Assert.Empty(service.GetBufferedSpans());
        Assert.Equal(0, postBurnStartedCount);
    }

    [Fact]
    public void SafeAllowlist_GenericPathKeys_RequireKeyedHmacAndRejectUnsaltedSha256()
    {
        var allowlist = new SafeAllowlist(new[] { "artifact_path", "report_path" });
        var unsaltedSha = $"sha256:{new string('b', 64)}";
        var shortHmac = "hmac:0123456789abcdef";
        var fullHmac = $"hmac:{new string('c', 64)}";

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("artifact_path", unsaltedSha));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("report_path", unsaltedSha));
        Assert.Equal(shortHmac, allowlist.SanitizeValue("artifact_path", shortHmac));
        Assert.Equal(fullHmac, allowlist.SanitizeValue("artifact_path", fullHmac));
        Assert.Equal(shortHmac, allowlist.SanitizeValue("report_path", shortHmac));
        Assert.Equal(unsaltedSha, allowlist.SanitizeValue("artifact_path", unsaltedSha, allowRawPayloads: true));
    }

    [Fact]
    public async Task RecordSpan_WhenActivityStoppedThrows_ReleasesPublicationScopeSoSubsequentBurnDoesNotHang()
    {
        var jobId = Guid.NewGuid().ToString("N");
        using var throwingListener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = act =>
            {
                if (string.Equals(act.GetTagItem("job_id")?.ToString(), jobId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Simulated ActivityStopped listener failure");
                }
            }
        };
        ActivitySource.AddActivityListener(throwingListener);

        var service = CreateOtlpService();
        Assert.Throws<InvalidOperationException>(() =>
            service.RecordSpan("scan_started", jobId, "OK", 1));

        await Task.Run(() => service.Burn()).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(service.IsBurned);
    }

    [Fact]
    public void TrySanitizeActivity_RejectsNonSnapshotEnumerableInActivityEventTags()
    {
        var allowlist = new SafeAllowlist(new[] { "rule_ids" });
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        using var mutatingAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(mutatingAct);
        mutatingAct.AddEvent(new ActivityEvent(
            "rule.evaluated",
            tags: new ActivityTagsCollection { ["rule_ids"] = new MutatingRuleIdsEnumerable() }));

        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(mutatingAct, allowlist, out var reason));
        Assert.Contains("non-snapshot enumerable", reason, StringComparison.OrdinalIgnoreCase);

        using var listAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(listAct);
        listAct.AddEvent(new ActivityEvent(
            "rule.evaluated",
            tags: new ActivityTagsCollection { ["rule_ids"] = new List<string> { "AR-001" } }));

        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(listAct, allowlist, out var listReason));
        Assert.Contains("non-snapshot enumerable", listReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SafeAllowlist_RegisterValueDomain_RejectsSensitiveAndInvalidKeys()
    {
        const string digest = "hmac:0123456789abcdef";
        var unsafeKeys = new[]
        {
            "123-45-6789",
            "alice@example.com",
            "prefix_123-45-6789",
            "tok_sk-1234567890abcdef",
            "invalid key!"
        };

        var allowlist = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["123-45-6789"] = new[] { digest },
                ["alice@example.com"] = new[] { digest },
                ["prefix_123-45-6789"] = new[] { digest },
                ["safe_tier"] = new[] { digest }
            });
        allowlist.RegisterValueDomain("tok_sk-1234567890abcdef", new[] { digest });
        allowlist.RegisterValueDomain("invalid key!", new[] { digest });

        Assert.True(allowlist.IsAllowed("safe_tier"));
        foreach (var unsafeKey in unsafeKeys)
        {
            Assert.False(allowlist.IsAllowed(unsafeKey));
        }

        var attrs = new Dictionary<string, object>
        {
            ["123-45-6789"] = digest,
            ["alice@example.com"] = digest,
            ["prefix_123-45-6789"] = digest,
            ["tok_sk-1234567890abcdef"] = digest,
            ["invalid key!"] = digest,
            ["safe_tier"] = digest
        };
        var sanitized = allowlist.Sanitize(attrs);
        Assert.Equal(digest, sanitized["safe_tier"]);
        foreach (var unsafeKey in unsafeKeys)
        {
            Assert.False(sanitized.ContainsKey(unsafeKey));
        }

        // Raw payloads debug mode still works while unsafe keys remain excluded from registered domains/allowlist.
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("safe_tier", "cleartext_tier"));
        var rawSanitized = allowlist.Sanitize(attrs, allowRawPayloads: true);
        Assert.Equal(digest, rawSanitized["prefix_123-45-6789"]);
        Assert.False(allowlist.IsAllowed("prefix_123-45-6789"));
    }

    [Fact]
    public void TrySanitizeActivity_RejectsMutableCallerStringArrayAttachedDirectlyToActivityEvent()
    {
        var allowlist = new SafeAllowlist(new[] { "rule_ids" });
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var callerOwnedArray = new[] { "AR-001", "CA-SEC-DEP-CAP-01" };
        using var directArrayAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(directArrayAct);
        directArrayAct.AddEvent(new ActivityEvent(
            "rule.evaluated",
            tags: new ActivityTagsCollection { ["rule_ids"] = callerOwnedArray }));

        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(directArrayAct, allowlist, out var reason));
        Assert.Contains("non-snapshot enumerable", reason, StringComparison.OrdinalIgnoreCase);

        var callerInput = new[] { "AR-001", "CA-SEC-DEP-CAP-01" };
        using var sanitizedEventAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(sanitizedEventAct);
        PrivacyActivityEnricher.AddSanitizedEvent(sanitizedEventAct, "rule.evaluated", allowlist, new Dictionary<string, object?>
        {
            ["rule_ids"] = callerInput
        });
        callerInput[0] = "patient@example.com";

        Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(sanitizedEventAct, allowlist, out var safeReason));
        Assert.Null(safeReason);
        var evtTags = sanitizedEventAct.Events.Single().Tags.ToDictionary(kv => kv.Key, kv => kv.Value);
        var stored = Assert.IsType<System.Collections.Immutable.ImmutableArray<string>>(evtTags["rule_ids"]);
        Assert.Equal(new[] { "AR-001", "CA-SEC-DEP-CAP-01" }, stored.ToArray());
    }

    [Fact]
    public void CreateExporterSafeStopCallback_WhenRuleIdsIteratorMutatesActivityTags_RedactsInjectedTagBeforeExport()
    {
        var allowlist = new SafeAllowlist(new[] { "rule_ids" });
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => ReferenceEquals(s, PrivacyTelemetryService.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var exportedTags = new Dictionary<string, object?>(StringComparer.Ordinal);
        var exportedCount = 0;
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            act =>
            {
                Interlocked.Increment(ref exportedCount);
                foreach (var tag in act.TagObjects)
                {
                    if (tag.Key is not null)
                    {
                        exportedTags[tag.Key] = tag.Value;
                    }
                }
            },
            allowRawPayloads: false);

        using var act = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(act);
        act.SetTag("rule_ids", new ReentrantMutatingRuleIdsEnumerable(act));

        safeStop(act);

        Assert.Equal(1, exportedCount);
        Assert.False(exportedTags.ContainsKey("document_text"));
        Assert.Equal(new[] { "AR-001" }, Assert.IsType<string[]>(exportedTags["rule_ids"]));
        Assert.Null(act.GetTagItem("document_text"));

        // R47 #2: Revalidates detached rule_ids array on subsequent passes if another lazy tag mutates it in-place.
        exportedTags.Clear();
        using var inPlaceMutatedAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        Assert.NotNull(inPlaceMutatedAct);
        inPlaceMutatedAct.SetTag("rule_ids", new List<string> { "AR-001" });
        inPlaceMutatedAct.SetTag("RULE_IDS", new InPlaceArrayMutatingRuleIdsEnumerable(inPlaceMutatedAct));

        safeStop(inPlaceMutatedAct);

        Assert.Equal(2, exportedCount);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, exportedTags["rule_ids"]);
    }

    [Fact]
    public void RecordSpan_DefaultAirGappedMode_RetainsSpansInMemoryWithZeroExternalActivityPublication()
    {
        var savedOtelEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
        var savedKtyEndpoint = Environment.GetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT");
        var savedKtyMode = Environment.GetEnvironmentVariable("KTY_TELEMETRY_MODE");
        var savedKtyEgress = Environment.GetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS");

        Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
        Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", null);
        Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", null);
        Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", null);

        try
        {
            var currentThreadId = Environment.CurrentManagedThreadId;
            var observingDeniedWindow = false;
            var startedCount = 0;
            var stoppedCount = 0;
            var jobId = $"job-{Guid.NewGuid():N}";
            using var captureExporter = new ActivityListener
            {
                ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = act =>
                {
                    if ((observingDeniedWindow && Environment.CurrentManagedThreadId == currentThreadId) ||
                        string.Equals(act.GetTagItem("job_id")?.ToString(), jobId, StringComparison.Ordinal))
                    {
                        Interlocked.Increment(ref startedCount);
                    }
                },
                ActivityStopped = act =>
                {
                    if ((observingDeniedWindow && Environment.CurrentManagedThreadId == currentThreadId) ||
                        string.Equals(act.GetTagItem("job_id")?.ToString(), jobId, StringComparison.Ordinal))
                    {
                        Interlocked.Increment(ref stoppedCount);
                    }
                }
            };
            ActivitySource.AddActivityListener(captureExporter);

            observingDeniedWindow = true;
            try
            {
                var defaultService = new PrivacyTelemetryService();
                Assert.True(defaultService.IsLocalOnlyHonest);
                defaultService.RecordSpan("scan_started", jobId, "OK", 10);
                var defaultSpan = Assert.Single(defaultService.GetBufferedSpans());
                Assert.Equal(jobId, defaultSpan.Attributes["job_id"]);

                // R46 #11: Verify memory-only buffer capacity limit (500) and FIFO oldest-span eviction.
                var capacityService = new PrivacyTelemetryService();
                for (var i = 0; i <= 500; i++)
                {
                    capacityService.RecordSpan("scan_started", $"job-{i}", "OK", 1);
                }
                var boundedSpans = capacityService.GetBufferedSpans();
                Assert.Equal(500, boundedSpans.Count);
                Assert.DoesNotContain(boundedSpans, s => Equals(s.Attributes["job_id"], "job-0"));
                Assert.Equal("job-1", boundedSpans[0].Attributes["job_id"]);
                Assert.Equal("job-500", boundedSpans[^1].Attributes["job_id"]);

                var otlpWithExplicitDenyConfig = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Telemetry:Mode"] = "otlp",
                        ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                        ["Privacy:NetworkEgress"] = "deny"
                    })
                    .Build();
                var deniedOtlpService = new PrivacyTelemetryService(configuration: otlpWithExplicitDenyConfig);
                deniedOtlpService.RecordSpan("scan_completed", jobId, "OK", 15);
                var deniedSpan = Assert.Single(deniedOtlpService.GetBufferedSpans());
                Assert.Equal(jobId, deniedSpan.Attributes["job_id"]);
            }
            finally
            {
                observingDeniedWindow = false;
            }

            Assert.Equal(0, startedCount);
            Assert.Equal(0, stoppedCount);

            // Positive control: allowed OTLP service publishes an observable activity to the same listener.
            var allowedConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                    ["Privacy:NetworkEgress"] = "allow_otlp"
                })
                .Build();
            var allowedOtlpService = new PrivacyTelemetryService(configuration: allowedConfig);
            allowedOtlpService.RecordSpan("scan_started", jobId, "OK", 5);
            Assert.Equal(1, startedCount);
            Assert.Equal(1, stoppedCount);
        }
        finally
        {
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", savedOtelEndpoint);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", savedKtyEndpoint);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", savedKtyMode);
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", savedKtyEgress);
        }
    }

    [Fact]
    public void R26Hardening_ExplicitOptionsDenyMissingOtlpEndpointAndExporterCallback_SuppressExternalPublication()
    {
        var jobIdPrefix = $"r26-airgap-{Guid.NewGuid():N}";
        var currentThreadId = Environment.CurrentManagedThreadId;
        var observingDeniedWindow = false;
        var publishedActivities = 0;

        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = act =>
            {
                if ((observingDeniedWindow && Environment.CurrentManagedThreadId == currentThreadId) ||
                    (act.GetTagItem("job_id") as string)?.StartsWith(jobIdPrefix, StringComparison.Ordinal) == true)
                {
                    publishedActivities++;
                }
            }
        };
        ActivitySource.AddActivityListener(listener);

        observingDeniedWindow = true;
        try
        {
            var explicitOptionsDeny = new PrivacyTelemetryService(Options.Create(new PrivacyTelemetryOptions
            {
                Telemetry = { Mode = "otlp", OtlpEndpoint = "http://localhost:4318/v1/traces" },
                Privacy = { NetworkEgress = "deny" }
            }));
            Assert.Equal("deny", explicitOptionsDeny.GetPrivacyAuditReport().NetworkEgress);
            explicitOptionsDeny.RecordSpan("scan_started", $"{jobIdPrefix}-1", "OK", 5);
            Assert.Single(explicitOptionsDeny.GetBufferedSpans());

            var implicitOptionsOtlp = new PrivacyTelemetryService(Options.Create(new PrivacyTelemetryOptions
            {
                Telemetry = { OtlpEndpoint = "http://localhost:4318/v1/traces" }
            }));
            var implicitReport = implicitOptionsOtlp.GetPrivacyAuditReport();
            Assert.Equal("memory_only", implicitReport.TelemetryMode);
            Assert.Equal("deny", implicitReport.NetworkEgress);
            implicitOptionsOtlp.RecordSpan("scan_started", $"{jobIdPrefix}-implicit-opt", "OK", 5);
            Assert.Single(implicitOptionsOtlp.GetBufferedSpans());
            Assert.Equal(0, publishedActivities);

            var emptyEndpointConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "   ",
                    ["Privacy:NetworkEgress"] = "allow_otlp"
                })
                .Build();
            var noEndpointService = new PrivacyTelemetryService(configuration: emptyEndpointConfig);
            Assert.Null(noEndpointService.GetPrivacyAuditReport().OtlpEndpoint);
            noEndpointService.RecordSpan("scan_started", $"{jobIdPrefix}-2", "OK", 5);
            Assert.Single(noEndpointService.GetBufferedSpans());
            Assert.Equal(0, publishedActivities);
        }
        finally
        {
            observingDeniedWindow = false;
        }

        // Positive control: allowed OTLP service publishes an observable activity to the same listener.
        observingDeniedWindow = true;
        try
        {
            var allowedOptionsService = new PrivacyTelemetryService(Options.Create(new PrivacyTelemetryOptions
            {
                Telemetry = { Mode = "otlp", OtlpEndpoint = "http://localhost:4318/v1/traces" },
                Privacy = { NetworkEgress = "allow_otlp" }
            }));
            allowedOptionsService.RecordSpan("scan_started", $"job-{Guid.NewGuid():N}", "OK", 5);
        }
        finally
        {
            observingDeniedWindow = false;
        }
        Assert.Equal(1, publishedActivities);

        const string sourceName = "KnowThankYew.Custom.R26AirGap";
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var airGappedService = new PrivacyTelemetryService(
            Options.Create(new PrivacyTelemetryOptions()),
            allowlist: allowlist);
        using var source = new ActivitySource(sourceName);
        using var customListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(customListener);

        var exporterCalls = 0;
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ => exporterCalls++,
            airGappedService);

        using var activity = source.StartActivity("scan_started");
        Assert.NotNull(activity);
        activity!.SetTag("job_id", $"{jobIdPrefix}-3");
        activity.SetTag("raw_text", "private sensitive text");
        safeStop(activity);

        Assert.Equal(0, exporterCalls);
        Assert.Null(activity.GetTagItem("raw_text"));
    }

    [Fact]
    public void R27Hardening_UnboundExporterCallback_SuppressesDispatchForAttachedAirGappedService()
    {
        const string sourceName = "KnowThankYew.Custom.R27Attached";
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var airGappedService = new PrivacyTelemetryService(
            Options.Create(new PrivacyTelemetryOptions()),
            allowlist: allowlist);
        using var source = new ActivitySource(sourceName);
        using var sanitizingListener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            airGappedService,
            shouldListenTo: src => src.Name == sourceName);
        ActivitySource.AddActivityListener(sanitizingListener);

        var unboundExporterCalls = 0;
        var unboundSafeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ => unboundExporterCalls++);
        using var exporterListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = unboundSafeStop
        };
        ActivitySource.AddActivityListener(exporterListener);

        using (var activity = source.StartActivity("scan_started"))
        {
            Assert.NotNull(activity);
            activity!.SetTag("raw_text", "private consumer input");
            activity.Stop();
            Assert.Null(activity.GetTagItem("raw_text"));
        }

        Assert.Equal(0, unboundExporterCalls);

        // Verify a consumer sanitizing listener on the shared KnowThankYew source still permits an OTLP service's own spans.
        var otlpJobId = $"job-{Guid.NewGuid():N}";
        var otlpService = CreateOtlpService();
        using var sharedSanitizer = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, airGappedService);
        ActivitySource.AddActivityListener(sharedSanitizer);
        var otlpExporterCalls = 0;
        using var otlpExporter = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                act =>
                {
                    if (Equals(act.GetTagItem("job_id"), otlpJobId))
                    {
                        otlpExporterCalls++;
                    }
                })
        };
        ActivitySource.AddActivityListener(otlpExporter);

        otlpService.RecordSpan("scan_started", otlpJobId, "OK", 10);
        Assert.Equal(1, otlpExporterCalls);
    }

    [Fact]
    public void R28Hardening_TrySanitizeActivity_RejectsExternallyStartedCanonicalActivityOwnedByDefaultConsumerService()
    {
        var origOtlp = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
        var origKtyOtlp = Environment.GetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT");
        var origMode = Environment.GetEnvironmentVariable("KTY_TELEMETRY_MODE");
        var origEgress = Environment.GetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS");
        Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
        Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", null);
        Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", null);
        Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", null);
        try
        {
            var allowlist = new SafeAllowlist();
            var defaultConsumerService = new PrivacyTelemetryService(allowlist: allowlist);
            using (var listener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, defaultConsumerService))
            using (var sampler = new ActivityListener
                   {
                       ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
                       Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
                   })
            {
                ActivitySource.AddActivityListener(listener);
                ActivitySource.AddActivityListener(sampler);

                using var activity = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started");
                Assert.NotNull(activity);
                activity!.SetTag("raw_text", "sensitive payload");

                var allowed = PrivacyActivityEnricher.TrySanitizeActivity(activity, allowlist, out var reason);

                Assert.False(allowed);
                Assert.NotNull(reason);
                Assert.Equal(ActivityTraceFlags.None, activity.ActivityTraceFlags & ActivityTraceFlags.Recorded);
                Assert.False(activity.IsAllDataRequested);
                Assert.Null(activity.GetTagItem("raw_text"));
                activity.Stop();
            }
            Activity.Current = null;

            // Control: an equivalent scan_started activity owned by an explicit OTLP + allow_otlp service passes sanitization.
            var otlpConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                    ["Privacy:NetworkEgress"] = "allow_otlp",
                })
                .Build();
            var allowedOtlpService = new PrivacyTelemetryService(configuration: otlpConfig, allowlist: allowlist);
            var controlSourceName = "KnowThankYew.Privacy.Control." + Guid.NewGuid().ToString("N");
            var controlAllowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { controlSourceName });
            using var controlSource = new ActivitySource(controlSourceName);
            using var controlSampler = new ActivityListener
            {
                ShouldListenTo = src => ReferenceEquals(src, controlSource),
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            };
            using var controlListener = PrivacyActivityEnricher.CreateSanitizingListener(
                controlAllowlist,
                allowedOtlpService,
                src => ReferenceEquals(src, controlSource));
            ActivitySource.AddActivityListener(controlSampler);
            ActivitySource.AddActivityListener(controlListener);
            using var controlActivity = controlSource.StartActivity("scan_started");
            Assert.NotNull(controlActivity);
            controlActivity!.SetTag("raw_text", "sensitive payload");
            var controlAllowed = PrivacyActivityEnricher.TrySanitizeActivity(controlActivity, controlAllowlist, out var controlReason);
            Assert.True(controlAllowed);
            Assert.Null(controlReason);
            Assert.Null(controlActivity.GetTagItem("raw_text"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", origOtlp);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", origKtyOtlp);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", origMode);
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", origEgress);
        }
    }

    [Fact]
    public void R29Hardening_BurnPurgesQueuedExporterSpansBeforeFlushCanDeliver()
    {
        var allowlist = new SafeAllowlist();
        var options = new PrivacyTelemetryOptions
        {
            Telemetry = new TelemetryOptions
            {
                Mode = "otlp",
                OtlpEndpoint = "http://localhost:4318"
            },
            Privacy = new PrivacyOptions
            {
                NetworkEgress = "allow_otlp",
                BurnEnabled = true
            }
        };
        var service = new PrivacyTelemetryService(Options.Create(options), allowlist: allowlist);

        var pendingQueue = new Queue<string>();
        var delivered = new List<string>();
        var queueSync = new object();

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            act =>
            {
                lock (queueSync)
                {
                    if (!service.IsBurned)
                    {
                        pendingQueue.Enqueue(act.OperationName);
                    }
                }
            },
            service,
            allowRawPayloads: false,
            onBurnPurge: () =>
            {
                lock (queueSync)
                {
                    pendingQueue.Clear();
                }
            });

        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, service);
        ActivitySource.AddActivityListener(listener);

        using var exporterListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = safeStop
        };
        ActivitySource.AddActivityListener(exporterListener);

        using (var act = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started"))
        {
            Assert.NotNull(act);
            act!.SetTag("jurisdiction", "CA");
        }

        lock (queueSync)
        {
            Assert.Single(pendingQueue);
        }

        // Burn before downstream exporter flushes the queue
        service.Burn();

        lock (queueSync)
        {
            Assert.Empty(pendingQueue);
            while (pendingQueue.Count > 0)
            {
                delivered.Add(pendingQueue.Dequeue());
            }
        }

        Assert.Empty(delivered);
    }

    [Fact]
    public void R35Hardening_FailedOnBurnPurge_ThrowsAndRemainsRetryableUntilQueueClears()
    {
        var allowlist = new SafeAllowlist();
        var options = new PrivacyTelemetryOptions
        {
            Telemetry = new TelemetryOptions
            {
                Mode = "otlp",
                OtlpEndpoint = "http://localhost:4318/v1/traces"
            },
            Privacy = new PrivacyOptions
            {
                BurnEnabled = true,
                NetworkEgress = "allow_otlp"
            }
        };
        var service = new PrivacyTelemetryService(Options.Create(options), allowlist: allowlist);

        var pendingQueue = new Queue<string>();
        var queueSync = new object();
        var purgeAttempts = 0;

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            act =>
            {
                lock (queueSync)
                {
                    if (!service.IsBurned)
                    {
                        pendingQueue.Enqueue(act.OperationName);
                    }
                }
            },
            service,
            allowRawPayloads: false,
            onBurnPurge: () =>
            {
                if (Interlocked.Increment(ref purgeAttempts) == 1)
                {
                    throw new InvalidOperationException("Simulated transient purge failure");
                }
                lock (queueSync)
                {
                    pendingQueue.Clear();
                }
            });

        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, service);
        ActivitySource.AddActivityListener(listener);

        using var exporterListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = safeStop
        };
        ActivitySource.AddActivityListener(exporterListener);

        using (var act = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started"))
        {
            Assert.NotNull(act);
            act!.SetTag("jurisdiction", "CA");
        }

        lock (queueSync)
        {
            Assert.Single(pendingQueue);
        }

        var ex = Assert.Throws<InvalidOperationException>(() => service.Burn());
        Assert.Equal("Simulated transient purge failure", ex.Message);
        Assert.True(service.IsBurned);
        Assert.Equal(1, purgeAttempts);
        lock (queueSync)
        {
            Assert.Single(pendingQueue);
        }

        service.Burn();
        Assert.Equal(2, purgeAttempts);
        lock (queueSync)
        {
            Assert.Empty(pendingQueue);
        }
    }

    [Fact]
    public void R35Hardening_PresentBlankNetworkEgress_RemainsFailClosedDenyWithOtlpEndpoint()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                ["Privacy:NetworkEgress"] = "   "
            })
            .Build();

        var exported = 0;
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _ => Interlocked.Increment(ref exported)
        };
        ActivitySource.AddActivityListener(listener);

        var service = new PrivacyTelemetryService(configuration: config);
        service.RecordSpan("scan_started", "doc-r35", "OK", 5);
        var report = service.GetPrivacyAuditReport();

        Assert.Equal("deny", report.NetworkEgress);
        Assert.Equal(0, exported);
        Assert.Single(service.GetBufferedSpans());
    }

    [Fact]
    public async Task R30Hardening_ConcurrentBurnWaitsForSlowPurgeHook_ReentrantStopPurges_AndRecordSpanIsolatesAmbientParentBaggage()
    {
        // 1. Concurrent Burn() must wait for an in-flight slow purge hook before returning
        var slowService = new PrivacyTelemetryService(Options.Create(new PrivacyTelemetryOptions
        {
            Telemetry = { Mode = "memory_only" },
            Privacy = { NetworkEgress = "deny", BurnEnabled = true },
        }));
        var slowQueue = new System.Collections.Concurrent.ConcurrentQueue<string>();
        slowQueue.Enqueue("queued-secret");
        using var hookEntered = new ManualResetEventSlim(false);
        using var allowHookFinish = new ManualResetEventSlim(false);
        var callCount = 0;

        slowService.RegisterBurnPurgeHook(() =>
        {
            if (Interlocked.Increment(ref callCount) == 1)
            {
                hookEntered.Set();
                Assert.True(allowHookFinish.Wait(TimeSpan.FromSeconds(5)));
                while (slowQueue.TryDequeue(out _)) { }
            }
        });

        var firstBurn = Task.Run(() => slowService.Burn());
        Assert.True(hookEntered.Wait(TimeSpan.FromSeconds(5)));

        using var secondBurnEntered = new ManualResetEventSlim(false);
        var secondBurnReturnedEarly = false;
        var secondBurn = Task.Run(() =>
        {
            secondBurnEntered.Set();
            slowService.Burn();
            secondBurnReturnedEarly = !slowQueue.IsEmpty;
        });

        Assert.True(secondBurnEntered.Wait(TimeSpan.FromSeconds(5)));
        await Task.Delay(50);
        Assert.False(secondBurn.IsCompleted);
        allowHookFinish.Set();

        await Task.WhenAll(firstBurn, secondBurn).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(secondBurnReturnedEarly);
        Assert.Empty(slowQueue);

        // 2. Reentrant Burn() followed by post-Burn enqueue inside exporterOnStop must be purged in safeStop finally
        const string reentrantOp = "rules_evaluated";
        var reentrantSource = $"KnowThankYew.EnricherTest.{Guid.NewGuid():N}";
        var allowlist = new SafeAllowlist(null, new[] { reentrantSource });
        var reentrantService = new PrivacyTelemetryService(
            Options.Create(new PrivacyTelemetryOptions
            {
                Telemetry = { Mode = "otlp", OtlpEndpoint = "http://localhost:4318" },
                Privacy = { NetworkEgress = "allow_otlp", BurnEnabled = true },
            }),
            allowlist: allowlist);
        var reentrantQueue = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var reentrantExporterCalls = 0;
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            act =>
            {
                Interlocked.Increment(ref reentrantExporterCalls);
                reentrantService.Burn();
                // Simulate delayed enqueue executing in the tail of exporterOnStop after reentrant Burn()
                reentrantQueue.Enqueue(act.DisplayName);
            },
            reentrantService,
            allowRawPayloads: false,
            onBurnPurge: () =>
            {
                while (reentrantQueue.TryDequeue(out _)) { }
            });

        await Task.Run(() =>
        {
            using var src = new ActivitySource(reentrantSource);
            using var listener = new ActivityListener
            {
                ShouldListenTo = s => s.Name == reentrantSource,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = safeStop
            };
            ActivitySource.AddActivityListener(listener);
            using var act = src.StartActivity(reentrantOp);
            Assert.NotNull(act);
        }).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, Volatile.Read(ref reentrantExporterCalls));
        Assert.True(reentrantService.IsBurned);
        Assert.Empty(reentrantQueue);

        // 3. RecordSpan must hide ambient Activity.Current baggage (e.g., email) from ActivityStarted listeners
        const string traceOp = "audit_performed";
        var ambientService = new PrivacyTelemetryService(Options.Create(new PrivacyTelemetryOptions
        {
            Telemetry = { Mode = "otlp", OtlpEndpoint = "http://localhost:4318" },
            Privacy = { NetworkEgress = "allow_otlp", BurnEnabled = true },
        }));
        string? observedStartedBaggageEmail = null;
        string? observedTraceState = "not-checked";
        string? observedTraceId = null;
        string? observedParentSpanId = null;
        var startedObserved = false;

        using var ambientParent = new Activity("upstream-request");
        ambientParent.AddBaggage("email", "alice@example.com");
        ambientParent.TraceStateString = "tenant=acme";
        ambientParent.Start();
        try
        {
            using var listener = new ActivityListener
            {
                ShouldListenTo = s => s.Name == PrivacyTelemetryService.ActivitySourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = act =>
                {
                    if (act.DisplayName == traceOp)
                    {
                        startedObserved = true;
                        observedStartedBaggageEmail = act.GetBaggageItem("email");
                        observedTraceState = act.TraceStateString;
                        observedTraceId = act.TraceId.ToString();
                        observedParentSpanId = act.ParentSpanId.ToString();
                    }
                }
            };
            ActivitySource.AddActivityListener(listener);
            ambientService.RecordSpan(traceOp, status: "OK", durationMs: 7);

            Assert.True(startedObserved);
            Assert.Null(observedStartedBaggageEmail);
            Assert.True(string.IsNullOrEmpty(observedTraceState));
            Assert.Equal(ambientParent.TraceId.ToString(), observedTraceId);
            Assert.Equal(ambientParent.SpanId.ToString(), observedParentSpanId);
            Assert.Same(ambientParent, Activity.Current);
        }
        finally
        {
            ambientParent.Stop();
        }
    }

    private sealed class ReentrantMutatingRuleIdsEnumerable : IEnumerable<string>
    {
        private readonly Activity _activity;

        public ReentrantMutatingRuleIdsEnumerable(Activity activity)
        {
            _activity = activity;
        }

        public IEnumerator<string> GetEnumerator()
        {
            _activity.SetTag("document_text", "private document text");
            yield return "AR-001";
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class InPlaceArrayMutatingRuleIdsEnumerable : IEnumerable<string>
    {
        private readonly Activity _activity;

        public InPlaceArrayMutatingRuleIdsEnumerable(Activity activity)
        {
            _activity = activity;
        }

        public IEnumerator<string> GetEnumerator()
        {
            if (_activity.GetTagItem("rule_ids") is string[] existing && existing.Length > 0)
            {
                existing[0] = "patient@example.com";
            }
            yield return "AR-001";
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class MutatingRuleIdsEnumerable : IEnumerable<string>
    {
        private int _calls;

        public IEnumerator<string> GetEnumerator()
        {
            var call = Interlocked.Increment(ref _calls);
            yield return call <= 2 ? "AR-001" : "patient@example.com";
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void SafeAllowlist_AdditionalKeysAndRegisterKeys_RejectSensitiveAndMalformedKeys()
    {
        const string digest = "hmac:abcdefabcdefabcd";
        var unsafeKeys = new[]
        {
            "alice@example.com",
            "123-45-6789",
            "prefix_123-45-6789",
            "tok_sk-1234567890abcdef",
            "invalid key!",
            "/Users/alice/secret"
        };

        var allowlist = new SafeAllowlist(additionalKeys: unsafeKeys.Concat(new[] { "safe_custom_key" }));
        allowlist.RegisterKeys(new[] { "bob@example.com", "sk-abcdef1234567890abcdef", "safe_registered_key" });

        Assert.True(allowlist.IsAllowed("safe_custom_key"));
        Assert.True(allowlist.IsAllowed("safe_registered_key"));
        foreach (var unsafeKey in unsafeKeys.Concat(new[] { "bob@example.com", "sk-abcdef1234567890abcdef" }))
        {
            Assert.False(allowlist.IsAllowed(unsafeKey));
            Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, allowlist.SanitizeValue(unsafeKey, digest));
        }

        var attrs = new Dictionary<string, object>
        {
            ["alice@example.com"] = digest,
            ["bob@example.com"] = 42,
            ["tok_sk-1234567890abcdef"] = true,
            ["invalid key!"] = digest,
            ["safe_custom_key"] = digest
        };
        var sanitized = allowlist.Sanitize(attrs);
        Assert.Equal(digest, sanitized["safe_custom_key"]);
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, sanitized["[REDACTED_KEY]"]);
        Assert.False(sanitized.ContainsKey("alice@example.com"));
        Assert.False(sanitized.ContainsKey("bob@example.com"));
        Assert.False(sanitized.ContainsKey("tok_sk-1234567890abcdef"));
        Assert.False(sanitized.ContainsKey("invalid key!"));
    }

    [Fact]
    public async Task R31Hardening_BurnPurgeHookCallingBurnReentrantly_DoesNotRecurseOrDeadlock()
    {
        var opts = Options.Create(new PrivacyTelemetryOptions
        {
            Telemetry = new TelemetryOptions { Mode = "memory_only" },
            Privacy = new PrivacyOptions { BurnEnabled = true }
        });
        var service = new PrivacyTelemetryService(opts, allowlist: new SafeAllowlist());
        var hookCalls = 0;
        var reentrantHookCalls = 0;
        var inHookContext = new AsyncLocal<bool>();
        var enteredHook = new ManualResetEventSlim(false);
        var releaseHook = new ManualResetEventSlim(false);
        PrivacyTelemetryService? target = service;

        service.RegisterBurnPurgeHook(() =>
        {
            if (inHookContext.Value)
            {
                Interlocked.Increment(ref reentrantHookCalls);
                return;
            }

            if (Interlocked.Increment(ref hookCalls) == 1)
            {
                enteredHook.Set();
                Assert.True(releaseHook.Wait(TimeSpan.FromSeconds(5)));
                // Re-entrant Burn() from within an active purge hook must not recurse indefinitely or deadlock.
                inHookContext.Value = true;
                try
                {
                    target!.Burn();
                }
                finally
                {
                    inHookContext.Value = false;
                }
            }
        });

        var primaryBurnTask = Task.Run(() => service.Burn());
        Assert.True(enteredHook.Wait(TimeSpan.FromSeconds(5)));

        using var concurrentBurnEntered = new ManualResetEventSlim(false);
        var concurrentBurnFinished = false;
        var concurrentBurnTask = Task.Run(() =>
        {
            concurrentBurnEntered.Set();
            service.Burn();
            Volatile.Write(ref concurrentBurnFinished, true);
        });

        Assert.True(concurrentBurnEntered.Wait(TimeSpan.FromSeconds(5)));
        await Task.Delay(120);
        Assert.False(Volatile.Read(ref concurrentBurnFinished));

        releaseHook.Set();
        await Task.WhenAll(primaryBurnTask, concurrentBurnTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, Volatile.Read(ref reentrantHookCalls));
        Assert.Equal(2, Volatile.Read(ref hookCalls));
        Assert.True(Volatile.Read(ref concurrentBurnFinished));
    }

    [Fact]
    public void R32Hardening_ExplicitDisabledMode_RemainsDisabledEvenWithOtlpEndpoint()
    {
        var exported = 0;
        var allowlist = new SafeAllowlist();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "disabled",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
            })
            .Build();

        var service = new PrivacyTelemetryService(configuration: config, allowlist: allowlist);
        Assert.Equal("disabled", service.Mode);
        var audit = service.GetPrivacyAuditReport();
        Assert.Equal("disabled", audit.TelemetryMode);
        Assert.Equal("deny", audit.NetworkEgress);

        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = s => s.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
        };
        var exporterStop = OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ => Interlocked.Increment(ref exported),
            service: service,
            allowRawPayloads: false);
        listener.ActivityStopped = exporterStop;
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        service.RecordSpan("scan_started", "doc-1", "OK", 5, new Dictionary<string, object> { ["rule_id"] = "AR-001" });

        Assert.Empty(service.GetBufferedSpans());
        Assert.Equal(0, exported);
    }

    [Fact]
    public async Task R33Hardening_CrossServiceMutualBurnPurgeHooks_DoNotDeadlock()
    {
        var opts = Options.Create(new PrivacyTelemetryOptions
        {
            Telemetry = new TelemetryOptions { Mode = "memory_only" },
            Privacy = new PrivacyOptions { BurnEnabled = true },
        });
        var serviceA = new PrivacyTelemetryService(opts, allowlist: new SafeAllowlist());
        var serviceB = new PrivacyTelemetryService(opts, allowlist: new SafeAllowlist());

        var hookACalls = 0;
        var hookBCalls = 0;
        using var bothEntered = new Barrier(2);

        serviceA.RegisterBurnPurgeHook(() =>
        {
            if (Interlocked.Increment(ref hookACalls) == 1)
            {
                Assert.True(bothEntered.SignalAndWait(TimeSpan.FromSeconds(5)));
                serviceB.Burn();
            }
        });

        serviceB.RegisterBurnPurgeHook(() =>
        {
            if (Interlocked.Increment(ref hookBCalls) == 1)
            {
                Assert.True(bothEntered.SignalAndWait(TimeSpan.FromSeconds(5)));
                serviceA.Burn();
            }
        });

        var burnATask = Task.Run(() => serviceA.Burn());
        var burnBTask = Task.Run(() => serviceB.Burn());

        await Task.WhenAll(burnATask, burnBTask).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(serviceA.IsBurned);
        Assert.True(serviceB.IsBurned);
        Assert.Equal(2, hookACalls);
        Assert.Equal(2, hookBCalls);
    }

    [Fact]
    public void R34Hardening_ExporterCallbackAndConcurrentBurnPurgeHooks_DoNotDeadlock()
    {
        var allowlistA = new SafeAllowlist();
        var serviceA = CreateOtlpService(allowlistA);
        var serviceB = new PrivacyTelemetryService(
            configuration: CreateConfig("memory_only", burnEnabled: true),
            allowlist: new SafeAllowlist());

        using var aEnteredExporter = new ManualResetEventSlim(false);
        using var bEnteredHook = new ManualResetEventSlim(false);
        var hookBCalls = 0;
        var exporterInvocations = 0;
        Exception? burnBError = null;
        Exception? recorderError = null;

        Thread? burnBThread = null;
        burnBThread = new Thread(() =>
        {
            try
            {
                Assert.True(aEnteredExporter.Wait(TimeSpan.FromSeconds(5)));
                serviceB.Burn();
            }
            catch (Exception ex)
            {
                burnBError = ex;
            }
        });
        burnBThread.IsBackground = true;

        serviceB.RegisterBurnPurgeHook(() =>
        {
            if (Interlocked.Increment(ref hookBCalls) == 1)
            {
                bEnteredHook.Set();
                serviceA.Burn();
            }
        });

        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlistA,
                _ =>
                {
                    if (Interlocked.Increment(ref exporterInvocations) != 1)
                    {
                        return;
                    }
                    aEnteredExporter.Set();
                    Assert.True(bEnteredHook.Wait(TimeSpan.FromSeconds(5)));
                    Assert.True(
                        SpinWait.SpinUntil(
                            () => (burnBThread.ThreadState & System.Threading.ThreadState.WaitSleepJoin) != 0,
                            TimeSpan.FromSeconds(5)));
                    serviceB.Burn();
                },
                service: serviceA,
                allowRawPayloads: false,
                onBurnPurge: null)
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);

        var recorderThread = new Thread(() =>
        {
            try
            {
                serviceA.RecordSpan(
                    "scan_started",
                    "doc-r34",
                    "OK",
                    5,
                    new Dictionary<string, object> { ["rule_id"] = "AR-001" });
            }
            catch (Exception ex)
            {
                recorderError = ex;
            }
        });
        recorderThread.IsBackground = true;

        burnBThread.Start();
        recorderThread.Start();

        Assert.True(recorderThread.Join(TimeSpan.FromSeconds(5)));
        Assert.True(burnBThread.Join(TimeSpan.FromSeconds(5)));
        Assert.Null(recorderError);
        Assert.Null(burnBError);
        Assert.True(serviceA.IsBurned);
        Assert.True(serviceB.IsBurned);
        Assert.Equal(1, exporterInvocations);
        Assert.Equal(2, hookBCalls);
    }

    [Fact]
    public void R41Hardening_EnvironmentVariablesAndImplicitConfigOtlpEndpoint_EnforceFailClosedPrecedence()
    {
        var origOtlp = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
        var origKtyOtlp = Environment.GetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT");
        var origMode = Environment.GetEnvironmentVariable("KTY_TELEMETRY_MODE");
        var origEgress = Environment.GetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS");

        try
        {
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", null);

            // 1. OTEL_EXPORTER_OTLP_ENDPOINT + KTY_TELEMETRY_MODE=otlp + KTY_PRIVACY_NETWORK_EGRESS=deny blocks external publication.
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces");
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", "otlp");
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", "deny");

            var deniedByEnv = new PrivacyTelemetryService();
            var deniedReport = deniedByEnv.GetPrivacyAuditReport();
            Assert.Equal("otlp", deniedReport.TelemetryMode);
            Assert.Equal("deny", deniedReport.NetworkEgress);
            Assert.False(deniedReport.IsLocalOnlyHonest);

            var exportedCalls = 0;
            var allowlist = new SafeAllowlist();
            var safeStopDenied = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                _ => exportedCalls++,
                deniedByEnv);
            using var listener = new ActivityListener
            {
                ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };
            ActivitySource.AddActivityListener(listener);
            using (var deniedAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!)
            {
                Assert.NotNull(deniedAct);
                deniedAct.Stop();
                safeStopDenied(deniedAct);
            }
            Assert.Equal(0, exportedCalls);

            // 2. OTEL_EXPORTER_OTLP_ENDPOINT + KTY_TELEMETRY_MODE=memory_only stays memory_only and deny.
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", "memory_only");
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", null);
            var envMemoryOnly = new PrivacyTelemetryService();
            var envMemoryReport = envMemoryOnly.GetPrivacyAuditReport();
            Assert.Equal("memory_only", envMemoryReport.TelemetryMode);
            Assert.Equal("deny", envMemoryReport.NetworkEgress);

            // 3. OTEL_EXPORTER_OTLP_ENDPOINT alone (without KTY_TELEMETRY_MODE=otlp) stays memory_only + deny in consumer defaults.
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", null);
            var envEndpointOnly = new PrivacyTelemetryService();
            var endpointOnlyReport = envEndpointOnly.GetPrivacyAuditReport();
            Assert.Equal("memory_only", endpointOnlyReport.TelemetryMode);
            Assert.Equal("deny", endpointOnlyReport.NetworkEgress);
            Assert.Null(endpointOnlyReport.OtlpEndpoint);
            Assert.True(endpointOnlyReport.IsLocalOnlyHonest);

            var safeStopEndpointOnly = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                _ => exportedCalls++,
                envEndpointOnly);
            using (var endpointOnlyAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!)
            {
                Assert.NotNull(endpointOnlyAct);
                endpointOnlyAct.Stop();
                safeStopEndpointOnly(endpointOnlyAct);
            }
            Assert.Equal(0, exportedCalls);

            // 4. Explicit KTY_TELEMETRY_MODE=otlp + OTEL_EXPORTER_OTLP_ENDPOINT enables allow_otlp when egress is not denied.
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", "otlp");
            var envExplicitOtlp = new PrivacyTelemetryService();
            var explicitOtlpReport = envExplicitOtlp.GetPrivacyAuditReport();
            Assert.Equal("otlp", explicitOtlpReport.TelemetryMode);
            Assert.Equal("allow_otlp", explicitOtlpReport.NetworkEgress);

            var safeStopAllowed = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                _ => exportedCalls++,
                envExplicitOtlp);
            using (var allowedAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!)
            {
                Assert.NotNull(allowedAct);
                allowedAct.Stop();
                safeStopAllowed(allowedAct);
            }
            Assert.Equal(1, exportedCalls);

            // 5. Config endpoint without Telemetry:Mode=otlp does NOT auto-escalate mode or egress.
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", null);
            var configImplicit = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces"
                })
                .Build();
            var configService = new PrivacyTelemetryService(configuration: configImplicit);
            var configReport = configService.GetPrivacyAuditReport();
            Assert.Equal("memory_only", configReport.TelemetryMode);
            Assert.Equal("deny", configReport.NetworkEgress);
            Assert.Null(configReport.OtlpEndpoint);
            Assert.True(configReport.IsLocalOnlyHonest);

            // 6. R46 #2: Rejected external Activity publication (e.g. non-W3C IdFormat) still buffers local span record when not burned.
            var prevDefaultFormat = Activity.DefaultIdFormat;
            var prevForceFormat = Activity.ForceDefaultIdFormat;
            try
            {
                Activity.DefaultIdFormat = ActivityIdFormat.Hierarchical;
                Activity.ForceDefaultIdFormat = true;
                envExplicitOtlp.RecordSpan("scan_started", "job-46", "OK", 12);
                var buffered = envExplicitOtlp.GetBufferedSpans();
                var retainedLocal = Assert.Single(buffered, s => Equals(s.Attributes["job_id"], "job-46"));
                Assert.True(Guid.TryParseExact(retainedLocal.Id, "N", out _));
            }
            finally
            {
                Activity.DefaultIdFormat = prevDefaultFormat;
                Activity.ForceDefaultIdFormat = prevForceFormat;
            }

            // 7. R48 #1 & R52 #1: risk_score is classified as Numeric, and RegisterValueDomain enforces closed-domain membership on built-in string/path keys while preserving schema checks.
            var riskAllowlist = new SafeAllowlist(additionalKeys: new[] { "risk_score", "adapter_path" });
            Assert.Equal(72, riskAllowlist.SanitizeValue("risk_score", 72));
            riskAllowlist.RegisterValueDomain("adapter_path", new[] { "hmac:0123456789abcdef", "sha256:0123456789abcdef" });
            Assert.Equal("hmac:0123456789abcdef", riskAllowlist.SanitizeValue("adapter_path", "hmac:0123456789abcdef"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("adapter_path", "hmac:fedcba9876543210"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("adapter_path", "sha256:0123456789abcdef"));
            riskAllowlist.RegisterValueDomain("job_id", new[] { "hmac:0123456789abcdef" });
            Assert.Equal("hmac:0123456789abcdef", riskAllowlist.SanitizeValue("job_id", "hmac:0123456789abcdef"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("job_id", "hmac:fedcba9876543210"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("job_id", "job-1234"));
            riskAllowlist.RegisterValueDomain("base_model", new[] { "hmac:0123456789abcdef" });
            Assert.Equal("hmac:0123456789abcdef", riskAllowlist.SanitizeValue("base_model", "hmac:0123456789abcdef"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("base_model", "hmac:fedcba9876543210"));
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, riskAllowlist.SanitizeValue("base_model", "Llama-3-8B"));
            riskAllowlist.RegisterValueDomain("rule_ids", new[] { "hmac:0123456789abcdef", "hmac:fedcba9876543210" });
            Assert.Equal(
                "hmac:0123456789abcdef,hmac:fedcba9876543210",
                riskAllowlist.SanitizeValue("rule_ids", "hmac:0123456789abcdef,hmac:fedcba9876543210"));
            Assert.Equal(
                SafeAllowlist.RedactedSensitiveValue,
                riskAllowlist.SanitizeValue("rule_ids", "hmac:0123456789abcdef,hmac:aaaaaaaaaaaaaaaa"));

            // R49 #1: Clean caller-owned rule_ids string[] is replaced with a detached array before deferred export handoff.
            var queuedActivities = new List<Activity>();
            var deferredStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                act => queuedActivities.Add(act),
                envExplicitOtlp);
            var callerRuleIds = new[] { "AR-001" };
            using (var ruleIdsAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!)
            {
                Assert.NotNull(ruleIdsAct);
                ruleIdsAct.SetTag("rule_ids", callerRuleIds);
                ruleIdsAct.Stop();
                deferredStop(ruleIdsAct);
            }
            callerRuleIds[0] = "raw secret document text";
            var exportedRuleIdsAct = Assert.Single(queuedActivities);
            var exportedRuleIds = Assert.IsType<string[]>(exportedRuleIdsAct.GetTagItem("rule_ids"));
            Assert.NotSame(callerRuleIds, exportedRuleIds);
            Assert.Equal(new[] { "AR-001" }, exportedRuleIds);

            // 8. R48 #2: Telemetry mode is normalized to lowercase documented values ("otlp", "disabled", "memory_only").
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces");
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", "OTLP");
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", null);
            var uppercaseOtlp = new PrivacyTelemetryService();
            Assert.Equal("otlp", uppercaseOtlp.Mode);
            Assert.Equal("otlp", uppercaseOtlp.GetPrivacyAuditReport().TelemetryMode);
            Assert.False(uppercaseOtlp.IsLocalOnlyHonest);

            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", "memory-only");
            var unknownModeService = new PrivacyTelemetryService();
            Assert.Equal("memory_only", unknownModeService.Mode);
            Assert.Equal("memory_only", unknownModeService.GetPrivacyAuditReport().TelemetryMode);
            Assert.True(unknownModeService.IsLocalOnlyHonest);

            // 9. R48 #3 & #4: DI RegisterActivitySourceNames admits custom source names and UsePrivacySafePropagator is explicit opt-in.
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", null);
            var customDiSourceName = "KnowThankYew.CustomDiSource." + Guid.NewGuid().ToString("N");
            var diConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                    ["Privacy:NetworkEgress"] = "allow_otlp",
                })
                .Build();
            var prevGlobalPropagator = DistributedContextPropagator.Current;
            var prevCurrentActivity = Activity.Current;
            Activity.Current = null;
            try
            {
                var baselinePropagator = DistributedContextPropagator.CreateDefaultPropagator();
                DistributedContextPropagator.Current = baselinePropagator;

                var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
                KnowThankYew.Privacy.Telemetry.Extensions.ServiceCollectionExtensions.AddPrivacyTelemetry(
                    services,
                    diConfig,
                    al => al.RegisterActivitySourceNames(new[] { customDiSourceName }));
                Assert.Same(baselinePropagator, DistributedContextPropagator.Current);

                using var provider = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services);
                var diAllowlist = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<SafeAllowlist>(provider);
                using var customSource = new ActivitySource(customDiSourceName);
                using var customListener = new ActivityListener
                {
                    ShouldListenTo = src => ReferenceEquals(src, customSource),
                    Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                };
                ActivitySource.AddActivityListener(customListener);
                using var customAct = customSource.StartActivity("scan_started")!;
                Assert.NotNull(customAct);
                Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(customAct, diAllowlist, out var customReject));
                Assert.Null(customReject);

                KnowThankYew.Privacy.Telemetry.Extensions.ServiceCollectionExtensions.UsePrivacySafePropagator(provider);
                Assert.NotSame(baselinePropagator, DistributedContextPropagator.Current);

                // Constructing an unrelated memory_only service later does not overwrite the DI singleton propagator owner.
                _ = new PrivacyTelemetryService();
                customAct.AddBaggage("job_id", "job-48");
                var diHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                DistributedContextPropagator.Current.Inject(
                    customAct,
                    diHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);
                Assert.True(diHeaders.ContainsKey("baggage"));
                Assert.Contains("job_id=job-48", diHeaders["baggage"]);

                // R55 #1: A memory-only service's exporter callback on a shared ActivitySource must not attach itself
                // as a denying owner or suppress an OTLP service's span.
                var memoryOnlyService = new PrivacyTelemetryService();
                var otlpOwnerService = CreateOtlpService();
                var memoryOnlyExports = 0;
                var otlpOwnerExports = 0;
                var memoryOnlyStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    diAllowlist,
                    _ => Interlocked.Increment(ref memoryOnlyExports),
                    memoryOnlyService);
                var otlpOwnerStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    diAllowlist,
                    _ => Interlocked.Increment(ref otlpOwnerExports),
                    otlpOwnerService);
                using (var sharedOwnerListener = PrivacyActivityEnricher.CreateSanitizingListener(
                           diAllowlist,
                           otlpOwnerService,
                           src => ReferenceEquals(src, customSource)))
                {
                    ActivitySource.AddActivityListener(sharedOwnerListener);
                    using var ownedByOtlpAct = customSource.StartActivity("scan_started")!;
                    Assert.NotNull(ownedByOtlpAct);
                    ownedByOtlpAct.Stop();
                    memoryOnlyStop(ownedByOtlpAct);
                    otlpOwnerStop(ownedByOtlpAct);
                    Assert.Equal(0, memoryOnlyExports);
                    Assert.Equal(1, otlpOwnerExports);
                }

                // R55 #2 & #3: rule_ids aggregate length backstop runs before Split(','), and quasi-identifier triad is redacted.
                var triadAllowlist = new SafeAllowlist(
                    additionalKeys: new[] { "hospital_id", "household_size", "fpl_percentage", "rule_ids" },
                    additionalActivitySourceNames: null,
                    customValueDomains: new Dictionary<string, IEnumerable<string>>
                    {
                        ["rule_ids"] = new[] { "hmac:0123456789abcdef" },
                    });
                var oversizedRuleIds = string.Join(",", Enumerable.Repeat("hmac:0123456789abcdef", 300));
                Assert.True(oversizedRuleIds.Length > 3600);
                var truncatedRuleIds = Assert.IsType<string>(triadAllowlist.SanitizeValue("rule_ids", oversizedRuleIds));
                Assert.StartsWith("[TRUNCATED_HASH_", truncatedRuleIds, StringComparison.Ordinal);

                var triadSanitized = triadAllowlist.Sanitize(new Dictionary<string, object>
                {
                    ["hospital_id"] = "cleveland-clinic-main",
                    ["household_size"] = 3,
                    ["fpl_percentage"] = 125,
                });
                Assert.Equal(SafeAllowlist.RedactedSensitiveValue, triadSanitized["hospital_id"]);
                Assert.Equal(SafeAllowlist.RedactedSensitiveValue, triadSanitized["household_size"]);
                Assert.Equal(SafeAllowlist.RedactedSensitiveValue, triadSanitized["fpl_percentage"]);
            }
            finally
            {
                Activity.Current = prevCurrentActivity;
                DistributedContextPropagator.Current = prevGlobalPropagator;
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", origOtlp);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT", origKtyOtlp);
            Environment.SetEnvironmentVariable("KTY_TELEMETRY_MODE", origMode);
            Environment.SetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS", origEgress);
        }
    }

    private sealed class BurningRuleIdsEnumerable : IEnumerable<string>, System.Collections.IEnumerable
    {
        private readonly PrivacyTelemetryService _telemetry;

        public BurningRuleIdsEnumerable(PrivacyTelemetryService telemetry)
        {
            _telemetry = telemetry;
        }

        public IEnumerator<string> GetEnumerator()
        {
            _telemetry.Burn();
            yield return "AR-001";
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class PausedRuleIdsEnumerable : IEnumerable<string>, System.Collections.IEnumerable
    {
        private readonly ManualResetEventSlim _entered;
        private readonly ManualResetEventSlim _release;

        public PausedRuleIdsEnumerable(ManualResetEventSlim entered, ManualResetEventSlim release)
        {
            _entered = entered;
            _release = release;
        }

        public IEnumerator<string> GetEnumerator()
        {
            _entered.Set();
            Assert.True(_release.Wait(TimeSpan.FromSeconds(5)));
            yield return "AR-001";
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
