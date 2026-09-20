using KnowThankYew.Privacy.Telemetry.Configuration;
using KnowThankYew.Privacy.Telemetry.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace KnowThankYew.Privacy.Telemetry.Tests;

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

        telemetry.RecordSpan("test.operation", "job-100", "OK", 50, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        var span = spans[0];

        Assert.Equal("test.operation", span.Name);
        Assert.Equal("job-100", span.Attributes["job_id"]);
        Assert.Equal("OK", span.Attributes["status"]);
        Assert.Equal("mps", span.Attributes["device"]);
        Assert.Equal("abc123def456", span.Attributes["dataset_hash"]);

        // Prohibited keys must be redacted fail-closed
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", span.Attributes["patient_name"]);
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", span.Attributes["ssn"]);
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", span.Attributes["prompt"]);
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

        telemetry.RecordSpan("test.truncate", "job-200", "OK", 10, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        Assert.Equal("[TRUNCATED_HASH_XXXXXXXX...]", spans[0].Attributes["rule_id"]);
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

        telemetry.RecordSpan("carecheck.audit", "job-300", "OK", 25, attrs);

        var spans = telemetry.GetBufferedSpans();
        Assert.Single(spans);
        Assert.Equal("99213", spans[0].Attributes["cpt_code"]);
        Assert.Equal("HOSP-001", spans[0].Attributes["hospital_id"]);
        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", spans[0].Attributes["patient_diagnosis"]);
    }

    [Fact]
    public void Burn_PurgesBufferAndEnforcesTombstone()
    {
        var config = CreateConfig();
        var telemetry = new PrivacyTelemetryService(configuration: config);

        telemetry.RecordSpan("step.1", "j-1", "OK");
        telemetry.RecordSpan("step.2", "j-2", "OK");
        Assert.Equal(2, telemetry.GetBufferedSpans().Count);

        telemetry.Burn();
        Assert.Empty(telemetry.GetBufferedSpans());

        // Subsequent span is rejected by tombstone
        telemetry.RecordSpan("step.3", "j-3", "OK");
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
}
