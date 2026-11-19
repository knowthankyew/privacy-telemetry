using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Configuration;
using KnowThankYew.Privacy.Telemetry.Core;
using KnowThankYew.Privacy.Telemetry.OpenTelemetry;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KnowThankYew.Privacy.Telemetry.Tests;

[Collection("ActivityListenerTests")]
public sealed class PrivacyTelemetryHardeningTests
{
    private static SafeAllowlist CreateTestAllowlist(IEnumerable<string>? additionalActivitySourceNames = null) =>
        new(new[] { "state", "product_type", "product_category", "rule_ids" }, additionalActivitySourceNames);

    [Fact]
    public void SanitizeValue_EnforcesClosedDomainJurisdictionAndProductType()
    {
        var allowlist = CreateTestAllowlist();

        Assert.Equal("CA", allowlist.SanitizeValue("jurisdiction", "CA"));
        Assert.Equal("District of Columbia", allowlist.SanitizeValue("jurisdiction", "District of Columbia"));
        Assert.Equal("Ohio", allowlist.SanitizeValue("state", "Ohio"));
        Assert.Equal("FTC", allowlist.SanitizeValue("jurisdiction", "FTC"));
        Assert.Equal("Automotive / EV", allowlist.SanitizeValue("product_type", "Automotive / EV"));
        Assert.Equal("Tools & Equipment", allowlist.SanitizeValue("product_category", "Tools & Equipment"));

        // Arbitrary single-token tenant names and PHI values must be rejected fail-closed.
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("jurisdiction", "Acme-Property-Management"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("state", "john_doe"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("product_type", "HIV-positive"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("product_category", "CustomSecretSKU"));
    }

    [Fact]
    public void ContainsSensitivePattern_DetectsEmbeddedSsnsAndFileUriLocalPaths()
    {
        Assert.True(SafeAllowlist.ContainsSensitivePattern("customer_123-45-6789"));
        Assert.True(SafeAllowlist.ContainsSensitivePattern("file:///Users/alice/private/model"));
        Assert.True(SafeAllowlist.ContainsSensitivePattern("file://localhost/Users/alice/private/model"));
        Assert.True(SafeAllowlist.ContainsSensitivePattern("file:///C:/Users/alice/docs"));
        Assert.True(SafeAllowlist.ContainsSensitivePattern("path=/Users/alice/x"));

        // Negative controls
        Assert.False(SafeAllowlist.ContainsSensitivePattern("id_12-345-6789"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("order_1234-56-7890"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("org/users/profile"));
        Assert.False(SafeAllowlist.ContainsSensitivePattern("https://example.com/home/page"));
    }

    [Fact]
    public void ContainsSensitivePattern_DetectsBrandSpecificPanLengthsAndSkipsNegativeControls()
    {
        Assert.True(SafeAllowlist.ContainsSensitivePattern("card=4000000000006")); // 13-digit Visa (Luhn valid)
        Assert.True(SafeAllowlist.ContainsSensitivePattern("amex=378282246310005")); // 15-digit Amex (Luhn valid)
        Assert.True(SafeAllowlist.ContainsSensitivePattern("disc16=6440000000000005")); // 16-digit Discover (Luhn valid)
        Assert.True(SafeAllowlist.ContainsSensitivePattern("visa19=4000000000000000006")); // 19-digit Visa (Luhn valid)
        Assert.True(SafeAllowlist.ContainsSensitivePattern("disc19=6011000000000000001")); // 19-digit Discover (Luhn valid)

        // Negative controls: Luhn-valid unsupported 14/17-digit numbers, Luhn-valid non-IIN 9-prefix, and non-Luhn 19-digit
        Assert.False(SafeAllowlist.ContainsSensitivePattern("id=40000000000002")); // 14 digits
        Assert.False(SafeAllowlist.ContainsSensitivePattern("id=40000000000000006")); // 17 digits (Luhn valid)
        Assert.False(SafeAllowlist.ContainsSensitivePattern("id=9000000000000001")); // non-IIN (Luhn valid)
        Assert.False(SafeAllowlist.ContainsSensitivePattern("id=4000000000000000001")); // non-Luhn 19-digit
    }

    [Fact]
    public void SanitizeRuleIds_EnforcesMaxCountAndAggregateLengthBoundary()
    {
        var allowlist = CreateTestAllowlist();
        var validFifty = Enumerable.Range(1, 50).Select(i => $"hmac:{i:x16}").ToArray();
        var validFiftyCsv = string.Join(",", validFifty);
        Assert.Equal(validFifty, Assert.IsType<string[]>(allowlist.SanitizeValue("rule_ids", validFifty)));
        Assert.Equal(validFiftyCsv, allowlist.SanitizeValue("rule_ids", validFiftyCsv));

        var fiftyOne = Enumerable.Range(1, 51).Select(i => $"hmac:{i:x16}").ToArray();
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_ids", fiftyOne));
        var fiftyOneShortCsvOut = Assert.IsType<string>(allowlist.SanitizeValue("rule_ids", string.Join(",", Enumerable.Repeat("AR-001", 51))));
        Assert.DoesNotContain("AR-001", fiftyOneShortCsvOut);
        Assert.Matches(@"^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$", fiftyOneShortCsvOut);
        var fiftyOneCsvOut = Assert.IsType<string>(allowlist.SanitizeValue("rule_ids", string.Join(",", fiftyOne)));
        Assert.DoesNotContain("hmac:", fiftyOneCsvOut);
        Assert.Matches(@"^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$", fiftyOneCsvOut);

        var oversizedArray = Enumerable.Repeat("sha256:" + new string('a', 65), 50).ToArray();
        var oversizedCsv = string.Join(",", oversizedArray);
        Assert.True(oversizedCsv.Length > 3600);

        var oversizedArrayOut = Assert.IsType<string>(allowlist.SanitizeValue("rule_ids", oversizedArray));
        Assert.DoesNotContain("sha256:", oversizedArrayOut);
        Assert.Matches(@"^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$", oversizedArrayOut);

        var oversizedCsvOut = Assert.IsType<string>(allowlist.SanitizeValue("rule_ids", oversizedCsv));
        Assert.DoesNotContain("sha256:", oversizedCsvOut);
        Assert.Matches(@"^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$", oversizedCsvOut);
    }

    [Fact]
    public void RecordSpan_DeduplicatesDurationMsWhenProvidedInAttributes()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                ["Privacy:BurnEnabled"] = "true",
                ["Privacy:NetworkEgress"] = "allow_otlp"
            })
            .Build();

        Activity? captured = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = act => captured = act
        };
        ActivitySource.AddActivityListener(listener);

        var service = new PrivacyTelemetryService(configuration: config);
        service.RecordSpan("job.accepted", "job-001", "OK", 42L, new Dictionary<string, object>
        {
            ["duration_ms"] = 999L
        });

        Assert.NotNull(captured);
        var durationTags = captured!.TagObjects
            .Where(t => string.Equals(t.Key, "duration_ms", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.Single(durationTags);
        Assert.Equal(42L, durationTags[0].Value);
    }

    [Fact]
    public void SanitizeActivity_RemovesDuplicateTagsAndFailsClosedOnPoisonedDuplicate()
    {
        var srcName = $"KnowThankYew.DupTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var activity = src.StartActivity("job.accepted")!;
        activity.AddTag("rule_id", "AR-001");
        activity.AddTag("rule_id", "alice@example.com");

        PrivacyActivityEnricher.SanitizeActivity(activity, allowlist);

        var matching = activity.TagObjects.Where(t => t.Key == "rule_id").ToList();
        Assert.Single(matching);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, matching[0].Value);
    }

    [Fact]
    public void SanitizeActivity_FailsClosedOnUnsanitizedActivityEventTags()
    {
        var srcName = $"KnowThankYew.EvtFailTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var activity = src.StartActivity("job.accepted")!;
        activity.AddEvent(new ActivityEvent("raw_evt", tags: new ActivityTagsCollection
        {
            ["raw_ssn"] = "123-45-6789"
        }));

        Assert.Throws<InvalidOperationException>(() =>
            PrivacyActivityEnricher.SanitizeActivity(activity, allowlist));
    }

    [Fact]
    public void AddSanitizedEvent_AllowsSanitizedActivityEventAtExportBoundary()
    {
        var srcName = $"KnowThankYew.EvtOkTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var activity = src.StartActivity("job.accepted")!;
        PrivacyActivityEnricher.AddSanitizedEvent(activity, "checked_evt", allowlist, new Dictionary<string, object?>
        {
            ["rule_id"] = "AR-001",
            ["raw_ssn"] = "123-45-6789"
        });

        PrivacyActivityEnricher.SanitizeActivity(activity, allowlist);
        var evtTags = activity.Events.Single().Tags.ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.Equal("AR-001", evtTags["rule_id"]);
        Assert.False(evtTags.ContainsKey("raw_ssn"));
    }

    [Fact]
    public void CreateSanitizingListener_DoesNotThrowOnStopWithUnsafeEvent_AndClearsRecordingFlags()
    {
        var srcName = $"KnowThankYew.ListenerSafeTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            shouldListenTo: s => s.Name == srcName);
        ActivitySource.AddActivityListener(listener);

        using var activity = src.StartActivity("job.accepted")!;
        Assert.True(activity.IsAllDataRequested);
        activity.ActivityTraceFlags |= ActivityTraceFlags.Recorded;
        activity.AddEvent(new ActivityEvent(
            "unsafe_evt",
            tags: new ActivityTagsCollection { ["snippet"] = "Patient-has-HIV-in-chart" }));

        var ex = Record.Exception(() => activity.Stop());
        Assert.Null(ex);
        Assert.False(activity.IsAllDataRequested);
        Assert.False(activity.Recorded);
    }

    [Fact]
    public void CreateExporterSafeStopCallback_SkipsExporterForUnsafeEventOrLink_UnlessRawPayloadsAllowed()
    {
        var srcName = $"KnowThankYew.ExporterSafeTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        var unsafeLink = new ActivityLink(
            new ActivityContext(ActivityTraceId.CreateRandom(), ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded),
            new ActivityTagsCollection { ["snippet"] = "raw patient link text" });

        using var linkedActivity = src.StartActivity(
            "job.accepted",
            ActivityKind.Internal,
            default(ActivityContext),
            links: new[] { unsafeLink })!;

        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(linkedActivity, allowlist, out var linkReason));
        Assert.False(string.IsNullOrWhiteSpace(linkReason));
        Assert.False(linkedActivity.IsAllDataRequested);
        Assert.False(linkedActivity.Recorded);

        var exportedCount = 0;
        var guardedCallback = PrivacyActivityEnricher.CreateExporterSafeStopCallback(allowlist, _ => exportedCount++);
        guardedCallback(linkedActivity);
        Assert.Equal(0, exportedCount);

        using var eventActivity = src.StartActivity("job.accepted")!;
        eventActivity.AddEvent(new ActivityEvent(
            "unsafe_evt",
            tags: new ActivityTagsCollection { ["email"] = "patient@example.org" }));
        guardedCallback(eventActivity);
        Assert.Equal(0, exportedCount);

        Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(linkedActivity, allowlist, out var okReason, allowRawPayloads: true));
        Assert.Null(okReason);
        var rawCallback = PrivacyActivityEnricher.CreateExporterSafeStopCallback(allowlist, _ => exportedCount++, allowRawPayloads: true);
        rawCallback(linkedActivity);
        Assert.Equal(1, exportedCount);
    }

    [Fact]
    public void AddSanitizedEvent_WithRuleIdsArray_PassesIdempotentSanitizeActivityAndTrySanitizeActivity()
    {
        var srcName = $"KnowThankYew.RuleIdsEvtTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var activity = src.StartActivity("audit_performed")!;
        PrivacyActivityEnricher.AddSanitizedEvent(activity, "rule.evaluated", allowlist, new Dictionary<string, object?>
        {
            ["rule_ids"] = new[] { "AR-001", "implied_warranty_disclaimer" }
        });

        PrivacyActivityEnricher.SanitizeActivity(activity, allowlist);
        Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(activity, allowlist, out var reason));
        Assert.Null(reason);
        var evtTags = activity.Events.Single().Tags.ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.Equal(new[] { "AR-001", "implied_warranty_disclaimer" }, Assert.IsType<System.Collections.Immutable.ImmutableArray<string>>(evtTags["rule_ids"]));
    }

    [Fact]
    public void SafeAllowlist_EnforcesClosedDomainsAndStrictTokenFormats()
    {
        var allowlist = new SafeAllowlist(new[]
        {
            "status", "risk_level", "action", "device", "rule_id", "rule_ids",
            "job_id", "error_code", "app.version", "hospital_id", "cpt_code", "custom_field"
        });

        var smuggled = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["status"] = "Patient-has-HIV",
            ["risk_level"] = "Patient-has-HIV",
            ["action"] = "Patient-has-HIV",
            ["device"] = "Patient-has-HIV",
            ["rule_id"] = "Patient-has-HIV",
            ["rule_ids"] = "AR-001,Patient-has-HIV",
            ["job_id"] = "Patient-has-HIV",
            ["error_code"] = "Patient-has-HIV",
            ["app.version"] = "Patient-has-HIV",
            ["hospital_id"] = "Patient-has-HIV",
            ["cpt_code"] = "123456789",
            ["custom_field"] = "Patient-has-HIV"
        });

        foreach (var kv in smuggled)
        {
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, kv.Value);
        }

        var numericSmuggled = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["job_id"] = "123456789",
            ["cpt_code"] = "123456789",
            ["custom_field"] = "123456789"
        });
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, numericSmuggled["job_id"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, numericSmuggled["cpt_code"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, numericSmuggled["custom_field"]);

        var valid = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["status"] = "Completed",
            ["risk_level"] = "HIGH",
            ["action"] = "scan_completed",
            ["device"] = "CUDA:0",
            ["rule_id"] = "CA_CIV_1950_5",
            ["rule_ids"] = new[] { "AR-001", "implied_warranty_disclaimer" },
            ["job_id"] = "job-123",
            ["error_code"] = "edge_inference_notice",
            ["app.version"] = "2.1.0",
            ["hospital_id"] = "cleveland-clinic-main",
            ["cpt_code"] = "99213",
            ["custom_field"] = "hmac:0123456789abcdef"
        });

        Assert.Equal("Completed", valid["status"]);
        Assert.Equal("HIGH", valid["risk_level"]);
        Assert.Equal("scan_completed", valid["action"]);
        Assert.Equal("CUDA:0", valid["device"]);
        Assert.Equal("CA_CIV_1950_5", valid["rule_id"]);
        Assert.Equal(new[] { "AR-001", "implied_warranty_disclaimer" }, Assert.IsType<string[]>(valid["rule_ids"]));
        Assert.Equal("job-123", valid["job_id"]);
        Assert.Equal("edge_inference_notice", valid["error_code"]);
        Assert.Equal("2.1.0", valid["app.version"]);
        Assert.Equal("cleveland-clinic-main", valid["hospital_id"]);
        Assert.Equal("99213", valid["cpt_code"]);
        Assert.Equal("hmac:0123456789abcdef", valid["custom_field"]);
    }

    [Fact]
    public void R8Hardening_RedactsCompactSsnUnderscoreCardDatasetAndStatuteAndRecognizesDefaultServiceName()
    {
        var allowlist = new SafeAllowlist(new[] { "dataset_relative_path", "statute_code", "custom_field", "service.name" });

        var smuggled = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["rule_id"] = "123456789",
            ["rule_ids"] = new[] { "AR-001", "123456789" },
            ["job_id"] = "job_4111111111111111",
            ["custom_field"] = "123456789",
            ["dataset_relative_path"] = "Jane_Doe_HIV_positive.jsonl",
            ["statute_code"] = "Jane.Doe_HIV_positive",
        });

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["rule_id"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["rule_ids"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["job_id"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["custom_field"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["dataset_relative_path"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, smuggled["statute_code"]);

        var compactSsnJob = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["job_id"] = "123456789"
        });
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, compactSsnJob["job_id"]);

        var valid = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["dataset_relative_path"] = "job-42.jsonl",
            ["statute_code"] = "Cal. Civ. Code § 1950.5",
            ["service"] = "knowthankyew-app",
            ["service.name"] = "knowthankyew-app",
            ["rule_id"] = "FLSA_EXEMPT_541"
        });

        Assert.Equal("job-42.jsonl", valid["dataset_relative_path"]);
        Assert.Equal("Cal. Civ. Code § 1950.5", valid["statute_code"]);
        Assert.Equal("knowthankyew-app", valid["service"]);
        Assert.Equal("knowthankyew-app", valid["service.name"]);
        Assert.Equal("FLSA_EXEMPT_541", valid["rule_id"]);

        var multiWordStatute = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["statute_code"] = "42 U.S.C. § 1983"
        });
        Assert.Equal("42 U.S.C. § 1983", multiWordStatute["statute_code"]);
    }

    [Fact]
    public void R8Hardening_SanitizesUnsafeActivityEventNamesOnAddAndExportBoundary()
    {
        var allowlist = CreateTestAllowlist(new[] { "Kty.R8.EventNameTests" });
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "Kty.R8.EventNameTests",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);
        using var source = new ActivitySource("Kty.R8.EventNameTests");

        using var safeActivity = source.StartActivity("job.transition");
        Assert.NotNull(safeActivity);

        PrivacyActivityEnricher.AddSanitizedEvent(safeActivity!, "Jane Doe: HIV positive", allowlist);
        PrivacyActivityEnricher.AddSanitizedEvent(safeActivity!, "job.completed", allowlist);

        var addedEvents = safeActivity!.Events.ToList();
        Assert.Equal(2, addedEvents.Count);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, addedEvents[0].Name);
        Assert.Equal("job.completed", addedEvents[1].Name);
        Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(safeActivity!, allowlist, out var cleanReason));
        Assert.Null(cleanReason);

        using var rawBypassActivity = source.StartActivity("job.raw_bypass");
        Assert.NotNull(rawBypassActivity);
        rawBypassActivity!.AddEvent(new ActivityEvent("Jane Doe: HIV positive"));
        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(rawBypassActivity!, allowlist, out var rejectReason));
        Assert.Contains("unsanitized event name", rejectReason, StringComparison.Ordinal);

        using var debugRawActivity = source.StartActivity("job.raw_debug");
        Assert.NotNull(debugRawActivity);
        PrivacyActivityEnricher.AddSanitizedEvent(
            debugRawActivity!,
            "Jane Doe: HIV positive",
            allowlist,
            allowRawPayloads: true);
        Assert.Equal("Jane Doe: HIV positive", debugRawActivity!.Events.Single().Name);
    }

    [Fact]
    public void R9Hardening_RemovesUnallowlistedKeysAndSanitizesDisplayNameAndStatusDescription()
    {
        var allowlist = CreateTestAllowlist(new[] { "Kty.R9.ActivityBoundaryTests" });
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "Kty.R9.ActivityBoundaryTests",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);
        using var source = new ActivitySource("Kty.R9.ActivityBoundaryTests");

        Activity? exported = null;
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(allowlist, act => exported = act);
        using (var activity = source.StartActivity("job.transition"))
        {
            Assert.NotNull(activity);
            activity!.DisplayName = "GET /users/jane@example.com";
            activity.SetStatus(ActivityStatusCode.Error, "Denied for jane@example.com");
            activity.SetTag("patient=jane@example.com", "raw-tag-val");
            activity.SetSanitizedTag("other_unallowlisted=alice@example.com", "secret", allowlist);
            Assert.DoesNotContain(activity.TagObjects, t => t.Key == "other_unallowlisted=alice@example.com");

            PrivacyActivityEnricher.AddSanitizedEvent(activity, "job.completed", allowlist, new Dictionary<string, object?>
            {
                ["rule_id"] = "AR-001",
                ["patient=jane@example.com"] = "secret"
            });

            safeStop(activity);
            Assert.Same(activity, exported);
            Assert.Equal("[REDACTED_SPAN_NAME]", exported!.DisplayName);
            Assert.Equal(ActivityStatusCode.Error, exported.Status);
            Assert.True(string.IsNullOrEmpty(exported.StatusDescription));
            Assert.DoesNotContain(exported.TagObjects, t => t.Key == "patient=jane@example.com");

            var evtTags = exported.Events.Single().Tags.ToDictionary(kv => kv.Key, kv => kv.Value);
            Assert.Equal("AR-001", evtTags["rule_id"]);
            Assert.DoesNotContain("patient=jane@example.com", evtTags.Keys);
        }

        // Negative control: allowRawPayloads=true preserves DisplayName, StatusDescription, and unallowlisted keys.
        Activity? rawExported = null;
        var rawStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(allowlist, act => rawExported = act, allowRawPayloads: true);
        using (var rawActivity = source.StartActivity("job.transition"))
        {
            Assert.NotNull(rawActivity);
            rawActivity!.DisplayName = "GET /users/jane@example.com";
            rawActivity.SetStatus(ActivityStatusCode.Error, "Denied for jane@example.com");
            rawActivity.SetTag("patient=jane@example.com", "raw-tag-val");
            rawStop(rawActivity);
            Assert.Same(rawActivity, rawExported);
            Assert.Equal("GET /users/jane@example.com", rawExported!.DisplayName);
            Assert.Equal("Denied for jane@example.com", rawExported.StatusDescription);
            Assert.Equal("raw-tag-val", rawExported.GetTagItem("patient=jane@example.com"));
        }

        // Direct immutable ActivityEvent and ActivityLink with unallowlisted key (even pre-redacted) must fail closed.
        var bypassCount = 0;
        var failClosedStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(allowlist, _ => bypassCount++);
        using (var evtBypass = source.StartActivity("job.transition"))
        {
            Assert.NotNull(evtBypass);
            evtBypass!.AddEvent(new ActivityEvent("job.completed", tags: new ActivityTagsCollection
            {
                ["patient=jane@example.com"] = SafeAllowlist.RedactedNotAllowlisted
            }));
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(evtBypass, allowlist, out var reason));
            Assert.Contains("unallowlisted tag", reason, StringComparison.Ordinal);
            failClosedStop(evtBypass);
        }

        var linkContext = new ActivityContext(ActivityTraceId.CreateRandom(), ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded);
        var unsafeLink = new ActivityLink(linkContext, new ActivityTagsCollection
        {
            ["patient=jane@example.com"] = SafeAllowlist.RedactedNotAllowlisted
        });
        using (var linkBypass = source.StartActivity("job.transition", ActivityKind.Internal, parentContext: default, links: new[] { unsafeLink }))
        {
            Assert.NotNull(linkBypass);
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(linkBypass!, allowlist, out var reason));
            Assert.Contains("unallowlisted tag", reason, StringComparison.Ordinal);
            failClosedStop(linkBypass!);
        }
        Assert.Equal(0, bypassCount);
    }

    [Fact]
    public void R9Hardening_DatasetHashRejectsArbitraryTextWhileAcceptingHexDigests()
    {
        var allowlist = new SafeAllowlist();
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_hash", "patient_HIV_positive"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("dataset_hash", "DeadBeefCafe"));
        Assert.Equal("abc123def456", allowlist.SanitizeValue("dataset_hash", "abc123def456"));

        const string digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Assert.Equal(digest, allowlist.SanitizeValue("dataset_hash", digest));
        Assert.Equal($"sha256:{digest}", allowlist.SanitizeValue("dataset_hash", $"sha256:{digest}"));
    }

    [Fact]
    public void R10Hardening_FileUriPaths_TraceState_ScopeTags_SpanNames_AndOpaqueIds()
    {
        var allowlist = new SafeAllowlist(new[] { "dataset_relative_path" });

        // 1. Single-slash file:/ URIs must be caught before base_model accepts them.
        Assert.Equal(
            SafeAllowlist.RedactedSensitiveValue,
            allowlist.SanitizeValue("base_model", "file:/Users/JaneDoe/models/private-model"));
        Assert.Equal(
            SafeAllowlist.RedactedSensitiveValue,
            allowlist.SanitizeValue("base_model", "FILE:/home/alice/lora-weights"));

        // 2. Valid constrained UUIDs / hex dataset_hash with 9 digits must survive,
        // while free-form job-* tokens with SSNs remain redacted.
        const string uuidNineDigits = "12345678-1234-4abc-8abc-123456789abc";
        const string hexNineDigits = "123456789abcdef0123456789abcdef0";
        Assert.Equal(uuidNineDigits, allowlist.SanitizeValue("job_id", uuidNineDigits));
        Assert.Equal(hexNineDigits, allowlist.SanitizeValue("dataset_hash", hexNineDigits));
        Assert.Equal($"{uuidNineDigits}.jsonl", allowlist.SanitizeValue("dataset_relative_path", $"{uuidNineDigits}.jsonl"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("job_id", "job-123-45-6789"));

        // 3. PrivacyTelemetryService sanitizes unsafe span names.
        var service = new PrivacyTelemetryService(allowlist: allowlist);
        service.RecordSpan("Jane Doe 123-45-6789", entityId: uuidNineDigits, status: "OK");
        Assert.Equal("[REDACTED_SPAN_NAME]", Assert.Single(service.GetBufferedSpans()).Name);

        // 4. Span TraceStateString is cleared, and immutable link TraceState (even with null Tags)
        // & immutable ActivitySource.Tags fail closed with fixed non-leaking reason messages.
        var cleanSourceName = "Kty.R10.CleanSource." + Guid.NewGuid().ToString("N");
        var taggedSourceName = "Kty.R10.TaggedSource." + Guid.NewGuid().ToString("N");
        var sourceAllowlist = new SafeAllowlist(
            new[] { "dataset_relative_path" },
            new[] { cleanSourceName, taggedSourceName });
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name.StartsWith("Kty.R10.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);
        using var cleanSource = new ActivitySource(cleanSourceName);

        using (var spanTraceStateAct = cleanSource.StartActivity("job.accepted"))
        {
            Assert.NotNull(spanTraceStateAct);
            spanTraceStateAct!.TraceStateString = "tenant=jane@example.com";
            Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(spanTraceStateAct, sourceAllowlist, out _));
            Assert.Equal(string.Empty, spanTraceStateAct.TraceStateString);
        }

        // Parent TraceStateString must not leak into sanitized child Activity via null-fallback getter.
        using (var parentTraceStateAct = cleanSource.StartActivity("job.accepted"))
        {
            Assert.NotNull(parentTraceStateAct);
            parentTraceStateAct!.TraceStateString = "tenant=jane@example.com";
            using var childInheritedAct = cleanSource.StartActivity("job.completed");
            Assert.NotNull(childInheritedAct);
            Assert.Equal("tenant=jane@example.com", childInheritedAct!.TraceStateString);
            Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(childInheritedAct, sourceAllowlist, out _));
            Assert.Equal(string.Empty, childInheritedAct.TraceStateString);
        }

        var taggedLinkCtx = new ActivityContext(
            ActivityTraceId.CreateRandom(),
            ActivitySpanId.CreateRandom(),
            ActivityTraceFlags.Recorded,
            traceState: "tenant=jane@example.com");
        var linkNoTags = new ActivityLink(taggedLinkCtx);
        using (var linkTraceStateAct = cleanSource.StartActivity("job.accepted", ActivityKind.Internal, parentContext: default, links: new[] { linkNoTags }))
        {
            Assert.NotNull(linkTraceStateAct);
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(linkTraceStateAct!, sourceAllowlist, out var reason));
            Assert.DoesNotContain("jane@example.com", reason);
            Assert.DoesNotContain("tenant=", reason);
        }

        using (var secretEvtAct = cleanSource.StartActivity("patient=alice@example.com"))
        {
            Assert.NotNull(secretEvtAct);
            secretEvtAct!.AddEvent(new ActivityEvent("jane@example.com", tags: new ActivityTagsCollection
            {
                ["secret_key_alice@example.com"] = "val"
            }));
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(secretEvtAct, sourceAllowlist, out var reason));
            Assert.DoesNotContain("jane@example.com", reason);
            Assert.DoesNotContain("alice@example.com", reason);
            Assert.Contains("unsanitized event name", reason, StringComparison.Ordinal);
        }

        using var taggedSource = new ActivitySource(new ActivitySourceOptions(taggedSourceName)
        {
            Tags = new[] { new KeyValuePair<string, object?>("tenant_name", "Acme Corp") }
        });
        using (var scopedAct = taggedSource.StartActivity("job.accepted"))
        {
            Assert.NotNull(scopedAct);
            var exportedCount = 0;
            var stopCb = PrivacyActivityEnricher.CreateExporterSafeStopCallback(sourceAllowlist, _ => exportedCount++);
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(scopedAct!, sourceAllowlist, out var scopeReason));
            Assert.DoesNotContain("Acme Corp", scopeReason);
            Assert.DoesNotContain("tenant_name", scopeReason);
            stopCb(scopedAct!);
            Assert.Equal(0, exportedCount);
        }
    }

    [Fact]
    public void SanitizeSpanName_EnforcesClosedRegisteredEventSet()
    {
        Assert.Equal("[REDACTED_SPAN_NAME]", SafeAllowlist.SanitizeSpanName("patient_jane_doe_hiv_positive"));
        Assert.Equal("[REDACTED_SPAN_NAME]", SafeAllowlist.SanitizeSpanName("custom.unregistered_event"));
        Assert.Equal("analyze_paystub", SafeAllowlist.SanitizeSpanName("analyze_paystub"));
        Assert.Equal("job.transition.training", SafeAllowlist.SanitizeSpanName("job.transition.training"));
        Assert.Equal("extension.page_scan", SafeAllowlist.SanitizeSpanName("extension.page_scan"));
    }

    [Fact]
    public void Sanitize_RejectsHumanTextAndPanLookalikesInJobId()
    {
        var allowlist = new SafeAllowlist();
        var clean = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["job_id"] = "job-001",
            ["service"] = "ftaas-api"
        });
        Assert.Equal("job-001", clean["job_id"]);

        foreach (var unsafeJobId in new[]
        {
            "job-tenant_Alice_Smith",
            "job-123-45-6789",
            "job_4111111111111111",
            "123456789"
        })
        {
            var redacted = allowlist.Sanitize(new Dictionary<string, object> { ["job_id"] = unsafeJobId });
            Assert.Equal(SafeAllowlist.RedactedSensitiveValue, redacted["job_id"]);
        }

        foreach (var safeJobId in new[]
        {
            "run-42",
            "hmac:0123456789abcdef",
            "sha256:" + new string('a', 64)
        })
        {
            var preserved = allowlist.Sanitize(new Dictionary<string, object> { ["job_id"] = safeJobId });
            Assert.Equal(safeJobId, preserved["job_id"]);
        }
    }

    [Fact]
    public void SetSanitizedTag_PurgesPreExistingDuplicateTagsOnAllowlistedKeys()
    {
        var srcName = $"KnowThankYew.DuplicateTagTest.{Guid.NewGuid():N}";
        using var src = new ActivitySource(srcName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == srcName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { srcName });
        using var activity = src.StartActivity("job.accepted")!;
        activity.AddTag("status", "OK");
        activity.AddTag("status", "alice@example.com");

        activity.SetSanitizedTag("status", "Completed", allowlist);
        var statusTags = activity.TagObjects.Where(t => t.Key == "status").ToList();
        Assert.Single(statusTags);
        Assert.Equal("Completed", statusTags[0].Value);

        activity.SetSanitizedTag("status", "bob@example.com", allowlist);
        statusTags = activity.TagObjects.Where(t => t.Key == "status").ToList();
        Assert.Single(statusTags);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, statusTags[0].Value);
    }

    [Fact]
    public void TrySanitizeActivity_RejectsUnsafeActivitySourceMetadata_AndClearsRecordingFlags()
    {
        var badName = $"patient=alice@example.com.{Guid.NewGuid():N}";
        var badVersionName = $"KnowThankYew.BadVersion.{Guid.NewGuid():N}";
        var badSchemaName = $"KnowThankYew.BadSchema.{Guid.NewGuid():N}";

        using var badNameSrc = new ActivitySource(badName);
        using var badVersionSrc = new ActivitySource(new ActivitySourceOptions(badVersionName)
        {
            Version = "1.0.0-jane@example.com"
        });
        using var badSchemaSrc = new ActivitySource(new ActivitySourceOptions(badSchemaName)
        {
            TelemetrySchemaUrl = "https://evil.example/alice@example.com"
        });

        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == badName || s.Name == badVersionName || s.Name == badSchemaName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { badVersionName, badSchemaName });

        using (var act = badNameSrc.StartActivity("job.accepted")!)
        {
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, allowlist, out var reason));
            Assert.NotNull(reason);
            Assert.DoesNotContain("alice@example.com", reason);
            Assert.False(act.IsAllDataRequested);
            Assert.False(act.Recorded);
        }

        using (var act = badVersionSrc.StartActivity("job.accepted")!)
        {
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, allowlist, out var reason));
            Assert.NotNull(reason);
            Assert.DoesNotContain("jane@example.com", reason);
            Assert.False(act.IsAllDataRequested);
            Assert.False(act.Recorded);
        }

        using (var act = badSchemaSrc.StartActivity("job.accepted")!)
        {
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, allowlist, out var reason));
            Assert.NotNull(reason);
            Assert.DoesNotContain("evil.example", reason);
            Assert.False(act.IsAllDataRequested);
            Assert.False(act.Recorded);
        }

        // Tenant names smuggled in prerelease/build metadata must also fail closed in both ActivitySource.Version and app.version.
        var tenantPrereleaseName = $"KnowThankYew.TenantPre.{Guid.NewGuid():N}";
        var tenantBuildName = $"KnowThankYew.TenantBuild.{Guid.NewGuid():N}";
        var safeVersionName = $"KnowThankYew.SafeVer.{Guid.NewGuid():N}";
        using var tenantPreSrc = new ActivitySource(new ActivitySourceOptions(tenantPrereleaseName)
        {
            Version = "1.0.0-AcmeTenant"
        });
        using var tenantBuildSrc = new ActivitySource(new ActivitySourceOptions(tenantBuildName)
        {
            Version = "1.0.0+AcmeTenant"
        });
        using var safeVerSrc = new ActivitySource(new ActivitySourceOptions(safeVersionName)
        {
            Version = "2.1.0-rc.1+0db0099"
        });
        using var verListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == tenantPrereleaseName || s.Name == tenantBuildName || s.Name == safeVersionName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(verListener);
        var verAllowlist = new SafeAllowlist(
            additionalKeys: new[] { "app.version" },
            additionalActivitySourceNames: new[] { tenantPrereleaseName, tenantBuildName, safeVersionName });

        using (var act = tenantPreSrc.StartActivity("job.accepted")!)
        {
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, verAllowlist, out _));
        }
        using (var act = tenantBuildSrc.StartActivity("job.accepted")!)
        {
            Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, verAllowlist, out _));
        }
        using (var act = safeVerSrc.StartActivity("job.accepted")!)
        {
            Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(act, verAllowlist, out _));
        }
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, verAllowlist.SanitizeValue("app.version", "1.0.0-AcmeTenant"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, verAllowlist.SanitizeValue("app.version", "1.0.0+AcmeTenant"));
        Assert.Equal("2.1.0-rc.1+0db0099", verAllowlist.SanitizeValue("app.version", "2.1.0-rc.1+0db0099"));
    }

    [Fact]
    public void StrictClosedSets_RejectDefaultCustomActivitySources_UnregisteredRuleIds_AndUnregisteredBaseModels()
    {
        var allowlist = new SafeAllowlist(new[] { "rule_ids" });

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_id", "PATIENT_HAS_HIV"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_ids", new[] { "AR-001", "PATIENT_HAS_HIV" }));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("rule_ids", "AR-001,PATIENT_HAS_HIV"));

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("base_model", "Tenant_Acme"));
        Assert.Equal("google/gemma-2-2b-it", allowlist.SanitizeValue("base_model", "google/gemma-2-2b-it"));
        Assert.Equal("microsoft/BitNet-b1.58-2B-4T", allowlist.SanitizeValue("base_model", "microsoft/BitNet-b1.58-2B-4T"));
        var validSha256 = "sha256:" + new string('a', 64);
        Assert.Equal(validSha256, allowlist.SanitizeValue("base_model", validSha256));
        Assert.Equal("state_daily_overtime_CA", allowlist.SanitizeValue("rule_id", "state_daily_overtime_CA"));
        Assert.Equal("state_implied_override_TX", allowlist.SanitizeValue("rule_id", "state_implied_override_TX"));
        Assert.Equal(validSha256, allowlist.SanitizeValue("rule_id", validSha256));

        var tenantSourceName = "KnowThankYew.Tenant_Acme";
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == tenantSourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);
        var tenantSource = new ActivitySource(tenantSourceName);
        using var act = tenantSource.StartActivity("job.accepted")!;
        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(act, allowlist, out var reason));
        Assert.NotNull(reason);
        Assert.DoesNotContain("Tenant_Acme", reason);
        Assert.False(act.IsAllDataRequested);
        Assert.False(act.Recorded);
    }

    [Fact]
    public void EnforcesServiceInstanceIdSchema_DigitRunSha256_SafeUnallowlistedKeys_AndImmutableOperationName()
    {
        var allowlist = new SafeAllowlist(new[] { "rule_ids", "service.instance.id", "extension.rule_id", "error_type" });
        var digitRunSha256 = "sha256:123456789" + new string('a', 55);

        Assert.Equal("550e8400-e29b-41d4-a716-446655440000", allowlist.SanitizeValue("service.instance.id", "550e8400-e29b-41d4-a716-446655440000"));
        Assert.Equal("0123456789abcdef0123456789abcdef", allowlist.SanitizeValue("service.instance.id", "0123456789abcdef0123456789abcdef"));
        Assert.Equal(digitRunSha256, allowlist.SanitizeValue("service.instance.id", digitRunSha256));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("service.instance.id", "ALICE_SMITH"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("service.instance.id", "alice-macbook-1a2b"));

        Assert.Equal(digitRunSha256, allowlist.SanitizeValue("rule_id", digitRunSha256));
        Assert.Equal(digitRunSha256, allowlist.SanitizeValue("extension.rule_id", digitRunSha256));
        Assert.Equal(digitRunSha256, allowlist.SanitizeValue("base_model", digitRunSha256));
        Assert.Equal($"AR-001,{digitRunSha256}", allowlist.SanitizeValue("rule_ids", $"AR-001,{digitRunSha256}"));
        Assert.Equal(new[] { "AR-001", digitRunSha256 }, Assert.IsType<string[]>(allowlist.SanitizeValue("rule_ids", new[] { "AR-001", digitRunSha256 })));

        var sanitizedDict = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["alice@example.com"] = "secret",
            ["/Users/alice/private.txt"] = "secret",
            ["rule_id"] = "AR-001"
        });
        Assert.False(sanitizedDict.ContainsKey("alice@example.com"));
        Assert.False(sanitizedDict.ContainsKey("/Users/alice/private.txt"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, sanitizedDict["[REDACTED_KEY]"]);
        Assert.Equal("AR-001", sanitizedDict["rule_id"]);

        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("error_code", "ACME_CORPORATION"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("error_type", "AcmeError"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("error_code", "acme_corp"));
        Assert.Equal("HTTP_503", allowlist.SanitizeValue("error_code", "HTTP_503"));
        Assert.Equal("TimeoutError", allowlist.SanitizeValue("error_type", "TimeoutError"));
        Assert.Equal(digitRunSha256, allowlist.SanitizeValue("error_code", digitRunSha256));

        using var cleanListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(cleanListener);

        using var unsafeOpAct = PrivacyTelemetryService.ActivitySource.StartActivity("patient_jane_doe_hiv_positive")!;
        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(unsafeOpAct, allowlist, out var opReason));
        Assert.NotNull(opReason);
        Assert.DoesNotContain("jane_doe", opReason);
        Assert.False(unsafeOpAct.IsAllDataRequested);
        Assert.False(unsafeOpAct.Recorded);
        Assert.Throws<InvalidOperationException>(() => PrivacyActivityEnricher.SanitizeActivity(unsafeOpAct, allowlist));

        using var nullTagAct = PrivacyTelemetryService.ActivitySource.StartActivity("scan_started")!;
        nullTagAct.AddTag(null!, "patient text");
        Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(nullTagAct, allowlist, out var nullReason));
        Assert.NotNull(nullReason);
        Assert.False(nullTagAct.IsAllDataRequested);
        Assert.False(nullTagAct.Recorded);
        Assert.Throws<InvalidOperationException>(() => PrivacyActivityEnricher.SanitizeActivity(nullTagAct, allowlist));

        var rawEvt = PrivacyActivityEnricher.CreateSanitizedEvent(new string('Q', 300), allowlist, allowRawPayloads: true);
        Assert.StartsWith("[TRUNCATED_HASH_", rawEvt.Name);
        Assert.DoesNotContain("QQQQ", rawEvt.Name);
    }

    [Fact]
    public void R12Hardening_CustomKeysRequireClosedValueDomainOrOpaqueDigest()
    {
        var openKeyOnly = new SafeAllowlist(new[] { "tenant" });
        Assert.False(openKeyOnly.IsAllowed("tenant"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, openKeyOnly.SanitizeValue("tenant", "ACME_CORP"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, openKeyOnly.SanitizeValue("tenant", "hmac:0123456789abcdef"));
        Assert.Equal("ACME_CORP", openKeyOnly.SanitizeValue("tenant", "ACME_CORP", allowRawPayloads: true));

        var sampleHmacTier = "hmac:0123456789abcdef";
        var sampleHmacReport = "hmac:fedcba9876543210";
        var sampleShaReport = $"sha256:{new string('a', 64)}";
        var closedDomain = new SafeAllowlist(
            additionalKeys: new[] { "subscription_tier", "report_path" },
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["subscription_tier"] = new[] { "tier_free", "tier_pro", sampleHmacTier },
                ["report_path"] = new[] { "run-12.log", sampleHmacReport, sampleShaReport }
            });
        Assert.Equal(sampleHmacTier, closedDomain.SanitizeValue("subscription_tier", sampleHmacTier));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("subscription_tier", "tier_pro"));
        Assert.Equal("tier_pro", closedDomain.SanitizeValue("subscription_tier", "tier_pro", allowRawPayloads: true));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("subscription_tier", "ACME_CORP"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("subscription_tier", 123456789));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("subscription_tier", true));
        Assert.Equal(123456789, closedDomain.SanitizeValue("subscription_tier", 123456789, allowRawPayloads: true));
        Assert.Equal(sampleHmacReport, closedDomain.SanitizeValue("report_path", sampleHmacReport));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("report_path", sampleShaReport));
        Assert.Equal(sampleShaReport, closedDomain.SanitizeValue("report_path", sampleShaReport, allowRawPayloads: true));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("report_path", "run-12.log"));
        Assert.Equal("run-12.log", closedDomain.SanitizeValue("report_path", "run-12.log", allowRawPayloads: true));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, closedDomain.SanitizeValue("report_path", "Jane_Doe_HIV_positive.pdf"));

        var redactedKeyDict = closedDomain.Sanitize(new Dictionary<string, object>
        {
            ["Jane_Doe_HIV_positive"] = true,
            ["subscription_tier"] = sampleHmacTier
        });
        Assert.False(redactedKeyDict.ContainsKey("Jane_Doe_HIV_positive"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, redactedKeyDict["[REDACTED_KEY]"]);
        Assert.Equal(sampleHmacTier, redactedKeyDict["subscription_tier"]);

        // Prohibited tenant/identity keys cannot be authorized via customValueDomains unless allowRawPayloads is true.
        var tenantDomainOnly = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["tenant"] = new[] { "ACME_CORP" },
                ["tenant_name"] = new[] { "Acme Corp" }
            });
        Assert.False(tenantDomainOnly.IsAllowed("tenant"));
        Assert.False(tenantDomainOnly.IsAllowed("tenant_name"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, tenantDomainOnly.SanitizeValue("tenant", "ACME_CORP"));

        var tenantKeyWithCustomDomain = new SafeAllowlist(
            additionalKeys: new[] { "tenant" },
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["tenant"] = new[] { "ACME_CORP" }
            });
        Assert.False(tenantKeyWithCustomDomain.IsAllowed("tenant"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, tenantKeyWithCustomDomain.SanitizeValue("tenant", "ACME_CORP"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, tenantKeyWithCustomDomain.SanitizeValue("tenant", "hmac:0123456789abcdef"));
        Assert.Equal("ACME_CORP", tenantKeyWithCustomDomain.SanitizeValue("tenant", "ACME_CORP", allowRawPayloads: true));

        // CamelCase prohibited keys (tenantName, employeeName, matchedText) cannot be registered or authorized via customValueDomains,
        // whereas non-sensitive camelCase keys (planTier) can.
        var planDigest = "hmac:0123456789abcdef";
        var camelCaseDomains = new SafeAllowlist(
            additionalKeys: new[] { "tenantName", "employeeName", "matchedText", "dataset_relative_path" },
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["tenantName"] = new[] { "Acme Holdings" },
                ["employeeName"] = new[] { "Jane Doe" },
                ["matchedText"] = new[] { "binding arbitration" },
                ["planTier"] = new[] { "standard", planDigest }
            });
        Assert.False(camelCaseDomains.IsAllowed("tenantName"));
        Assert.False(camelCaseDomains.IsAllowed("employeeName"));
        Assert.False(camelCaseDomains.IsAllowed("matchedText"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, camelCaseDomains.SanitizeValue("tenantName", "Acme Holdings"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, camelCaseDomains.SanitizeValue("employeeName", "Jane Doe"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, camelCaseDomains.SanitizeValue("matchedText", "binding arbitration"));
        Assert.Equal(planDigest, camelCaseDomains.SanitizeValue("planTier", planDigest));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, camelCaseDomains.SanitizeValue("planTier", "standard"));
        Assert.Equal("standard", camelCaseDomains.SanitizeValue("planTier", "standard", allowRawPayloads: true));
        Assert.Equal("Acme Holdings", camelCaseDomains.SanitizeValue("tenantName", "Acme Holdings", allowRawPayloads: true));

        var unallowlistedCamelCase = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["tenantName"] = new[] { "Acme Holdings" },
                ["employeeName"] = new[] { "Jane Doe" },
                ["matchedText"] = new[] { "binding arbitration" },
                ["planTier"] = new[] { "standard", planDigest }
            });
        Assert.False(unallowlistedCamelCase.IsAllowed("tenantName"));
        Assert.False(unallowlistedCamelCase.IsAllowed("employeeName"));
        Assert.False(unallowlistedCamelCase.IsAllowed("matchedText"));
        Assert.True(unallowlistedCamelCase.IsAllowed("planTier"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, unallowlistedCamelCase.SanitizeValue("planTier", "standard"));
        Assert.Equal(planDigest, unallowlistedCamelCase.SanitizeValue("planTier", planDigest));

        // Supported sha256:/hmac: job_ids and dataset JSONL stems containing 9 consecutive digits are exempt from SSN false positives.
        var shaJob = "sha256:" + new string('a', 20) + "123456789" + new string('b', 35);
        var hmacJob = "hmac:" + new string('c', 20) + "123456789" + new string('d', 35);
        Assert.Equal(shaJob, camelCaseDomains.SanitizeValue("job_id", shaJob));
        Assert.Equal(hmacJob, camelCaseDomains.SanitizeValue("job_id", hmacJob));
        Assert.Equal($"{shaJob}.jsonl", camelCaseDomains.SanitizeValue("dataset_relative_path", $"{shaJob}.jsonl"));
        Assert.Equal($"job-{shaJob}.jsonl", camelCaseDomains.SanitizeValue("dataset_relative_path", $"job-{shaJob}.jsonl"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, camelCaseDomains.SanitizeValue("job_id", "job-123456789"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, camelCaseDomains.SanitizeValue("dataset_relative_path", "job-123-45-6789.jsonl"));
    }

    [Fact]
    public async Task RegisterValueDomain_ConcurrentWithSanitizeValue_IsThreadSafe()
    {
        var seedDigest = "hmac:0000000000000000";
        var validChannelDigest = "hmac:0123456789abcdef";
        var allowlist = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["planTier"] = new[] { seedDigest },
                ["review_channel"] = new[] { "Patient Jane Doe has HIV", "portal", "acme_holdings", validChannelDigest }
            });
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("review_channel", "Patient Jane Doe has HIV"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("review_channel", "portal"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, allowlist.SanitizeValue("review_channel", "acme_holdings"));
        Assert.Equal(validChannelDigest, allowlist.SanitizeValue("review_channel", validChannelDigest));

        var cleartextOnlyAllowlist = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["review_channel"] = new[] { "acme_holdings" }
            });
        Assert.NotEqual("acme_holdings", cleartextOnlyAllowlist.SanitizeValue("review_channel", "acme_holdings"));

        using var startGate = new ManualResetEventSlim(false);
        var writerTask = Task.Run(() =>
        {
            startGate.Wait();
            for (var i = 0; i < 500; i++)
            {
                allowlist.RegisterValueDomain("planTier", new[] { $"hmac:{i % 10:x16}" });
                allowlist.RegisterKeys(new[] { $"dynamic_metric_{i % 20}" });
            }
        });

        var readerTask = Task.Run(() =>
        {
            startGate.Wait();
            for (var i = 0; i < 1000; i++)
            {
                var candidate = $"hmac:{i % 10:x16}";
                var value = allowlist.SanitizeValue("planTier", candidate);
                Assert.True(
                    Equals(value, candidate) ||
                    Equals(value, SafeAllowlist.RedactedSensitiveValue));
                _ = allowlist.IsAllowed($"dynamic_metric_{i % 20}");
            }
        });

        startGate.Set();
        await Task.WhenAll(writerTask, readerTask);
    }

    [Fact]
    public void SafeAllowlist_RejectsPhiAndPersonSmugglingAdditionalKeys_InCtorRegisterKeysAndSerializedOutput()
    {
        var adversarialKeys = new[]
        {
            "patient_Jane_Doe_HIV_positive",
            "patient_jane_doe_hiv_positive",
            "Jane_Doe_HIV_positive",
            "diagnosis_HIV_positive",
            "patient123",
            "claimant_Bob_Smith"
        };

        var allowlist = new SafeAllowlist(adversarialKeys.Concat(new[] { "subscription_tier" }));
        allowlist.RegisterKeys(adversarialKeys);

        foreach (var badKey in adversarialKeys)
        {
            Assert.False(allowlist.IsAllowed(badKey));
        }
        Assert.True(allowlist.IsAllowed("subscription_tier"));

        var sanitized = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["patient_Jane_Doe_HIV_positive"] = true,
            ["Jane_Doe_HIV_positive"] = "hmac:0123456789abcdef",
            ["diagnosis_HIV_positive"] = "hmac:fedcba9876543210",
            ["patient123"] = 42,
            ["action"] = "scan_completed"
        });

        var serialized = System.Text.Json.JsonSerializer.Serialize(sanitized);
        Assert.DoesNotContain("patient", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Jane", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Doe", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HIV", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("diagnosis", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("0123456789abcdef", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, sanitized["[REDACTED_KEY]"]);
        Assert.Equal("scan_completed", sanitized["action"]);
    }

    [Fact]
    public void Allowlist_RawPayloadMode_BoundsOversizedAttributeKeysDeterministically()
    {
        var allowlist = new SafeAllowlist();
        var oversizedKey = new string('k', 320);
        var sanitized = allowlist.Sanitize(
            new Dictionary<string, object>
            {
                [oversizedKey] = "raw_value",
                ["normal_key"] = "ok"
            },
            allowRawPayloads: true);

        var expectedDigestKey = SafeAllowlist.FormatTruncatedDigest(oversizedKey);
        Assert.False(sanitized.ContainsKey(oversizedKey));
        Assert.Equal("raw_value", sanitized[expectedDigestKey]);
        Assert.Equal("ok", sanitized["normal_key"]);
        Assert.All(sanitized.Keys, k => Assert.True(k.Length <= 256));
    }

    [Fact]
    public void SafeAllowlist_CustomDomainKeys_RejectEntityNounsAndEmptyCustomDomainsFailClosed()
    {
        var digest = "hmac:0123456789abcdef";
        var allowlist = new SafeAllowlist(
            additionalKeys: new[]
            {
                "acme_holdings", "contoso_ops", "alice_smith_status", "contoso_ops_status",
                "review_channel", "hospital_id", "subscription_tier", "document_path"
            },
            additionalActivitySourceNames: null,
            customValueDomains: new Dictionary<string, IEnumerable<string>>
            {
                ["acme_holdings"] = new[] { digest },
                ["contoso_ops"] = new[] { digest },
                ["alice_smith_status"] = new[] { digest },
                ["contoso_ops_status"] = new[] { digest },
                ["subscription_tier"] = new[] { "cleartext_only_value" },
                ["document_path"] = Array.Empty<string>(),
                ["unkeyed_cleartext_tier"] = new[] { "cleartext_only_value" },
            });

        Assert.False(allowlist.IsAllowed("acme_holdings"));
        Assert.False(allowlist.IsAllowed("contoso_ops"));
        Assert.False(allowlist.IsAllowed("alice_smith_status"));
        Assert.False(allowlist.IsAllowed("contoso_ops_status"));
        Assert.False(allowlist.IsAllowed("unkeyed_cleartext_tier"));
        Assert.True(allowlist.IsAllowed("review_channel"));
        Assert.True(allowlist.IsAllowed("hospital_id"));
        Assert.True(allowlist.IsAllowed("subscription_tier"));
        Assert.True(allowlist.IsAllowed("document_path"));

        // Even if RegisterKeys is later called for an empty-domain key, the recorded empty domain stays closed.
        allowlist.RegisterKeys(new[] { "unkeyed_cleartext_tier" });

        var sanitized = allowlist.Sanitize(new Dictionary<string, object>
        {
            ["acme_holdings"] = digest,
            ["contoso_ops"] = digest,
            ["alice_smith_status"] = true,
            ["contoso_ops_status"] = "OK",
            ["unkeyed_cleartext_tier"] = digest,
            ["subscription_tier"] = digest,
            ["document_path"] = digest,
            ["review_channel"] = digest,
        });

        Assert.False(sanitized.ContainsKey("acme_holdings"));
        Assert.False(sanitized.ContainsKey("contoso_ops"));
        Assert.False(sanitized.ContainsKey("alice_smith_status"));
        Assert.False(sanitized.ContainsKey("contoso_ops_status"));
        Assert.Equal(SafeAllowlist.RedactedNotAllowlisted, sanitized["[REDACTED_KEY]"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, sanitized["unkeyed_cleartext_tier"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, sanitized["subscription_tier"]);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, sanitized["document_path"]);
        Assert.Equal(digest, sanitized["review_channel"]);
    }
}
