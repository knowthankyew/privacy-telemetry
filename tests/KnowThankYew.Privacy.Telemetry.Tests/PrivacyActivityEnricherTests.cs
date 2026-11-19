using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Core;
using KnowThankYew.Privacy.Telemetry.OpenTelemetry;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KnowThankYew.Privacy.Telemetry.Tests;

[CollectionDefinition("ActivityListenerTests", DisableParallelization = true)]
public sealed class ActivityListenerCollectionDefinition
{
}

[Collection("ActivityListenerTests")]
public sealed class PrivacyActivityEnricherTests
{
    [Fact]
    public void CreateSanitizingListener_SanitizesAndTruncatesTagsWithoutExposingSourceText()
    {
        var sourceName = "KnowThankYew.EnricherTest." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            shouldListenTo: src => src.Name == sourceName);
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("job.accepted");
        Assert.NotNull(activity);

        activity.SetTag("unauthorized_key", "secret-value");
        activity.SetTag("rule_id", new string('Z', 300));
        activity.SetTag("status", "alice@example.com");
        activity.Stop();

        Assert.Null(activity.GetTagItem("unauthorized_key"));
        Assert.DoesNotContain(activity.TagObjects, t => t.Key == "unauthorized_key");
        var truncatedTag = activity.GetTagItem("rule_id") as string;
        Assert.NotNull(truncatedTag);
        Assert.StartsWith("[TRUNCATED_HASH_", truncatedTag);
        Assert.DoesNotContain("ZZZZ", truncatedTag);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("status"));
    }

    [Fact]
    public void CreateSanitizingListener_InspectsTypedTagObjects()
    {
        var sourceName = "KnowThankYew.TypedTagTest." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(new[] { "rule_ids" }, new[] { sourceName });
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            shouldListenTo: src => src.Name == sourceName);
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("job.published");
        Assert.NotNull(activity);

        activity.SetTag("duration_ms", 42);
        activity.SetTag("step", double.NaN);
        activity.SetTag("loss", "not-a-number");
        activity.SetTag("device", new { Ssn = "123-45-6789" });
        activity.SetTag("rule_ids", new[] { "AR-001", "CA-SEC-DEP-CAP-01" });
        activity.Stop();

        Assert.Equal(42, activity.GetTagItem("duration_ms"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("step"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("loss"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("device"));
        Assert.Equal(new[] { "AR-001", "CA-SEC-DEP-CAP-01" }, activity.GetTagItem("rule_ids"));
    }

    [Fact]
    public void CreateSanitizingListener_TruncatesOversizedTagsEvenWhenAllowRawPayloadsIsTrue()
    {
        var sourceName = "KnowThankYew.RawEnricherTest." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            allowRawPayloads: true,
            shouldListenTo: src => src.Name == sourceName);
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("raw-activity");
        Assert.NotNull(activity);

        activity.SetTag("rule_id", new string('X', 300));
        activity.SetTag("custom_obj", new { Pii = "123-45-6789" });
        activity.SetTag("custom_short", "raw diagnostic note");
        activity.Stop();

        var truncatedTag = activity.GetTagItem("rule_id") as string;
        Assert.NotNull(truncatedTag);
        Assert.StartsWith("[TRUNCATED_HASH_", truncatedTag);
        Assert.DoesNotContain("XXXX", truncatedTag);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("custom_obj"));
        Assert.Equal("raw diagnostic note", activity.GetTagItem("custom_short"));
    }

    [Fact]
    public void ExporterObservedTags_AreSanitizedInListenerFirstOrder()
    {
        var sourceName = "KnowThankYew.ExporterOrderFirst." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var captured = new Dictionary<string, object?>();

        using var sanitizingListener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist);
        sanitizingListener.ShouldListenTo = src => src.Name == sourceName;
        ActivitySource.AddActivityListener(sanitizingListener);

        using var exporterListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = act =>
            {
                foreach (var kv in act.TagObjects)
                {
                    captured[kv.Key] = kv.Value;
                }
            }
        };
        ActivitySource.AddActivityListener(exporterListener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("job.completed");
        Assert.NotNull(activity);
        activity.SetTag("unauthorized_key", "secret");
        activity.SetTag("status", "alice@example.com");
        activity.SetTag("action", "scan_complete");
        activity.Stop();

        Assert.DoesNotContain("unauthorized_key", captured.Keys);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, captured["status"]);
        Assert.Equal("scan_complete", captured["action"]);
    }

    [Fact]
    public void CreateExporterSafeStopCallback_ProtectsExporterRegisteredFirst()
    {
        var sourceName = "KnowThankYew.ExporterFirst." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var captured = new Dictionary<string, object?>();

        using var exporterListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                act =>
                {
                    foreach (var kv in act.TagObjects)
                    {
                        captured[kv.Key] = kv.Value;
                    }
                })
        };
        ActivitySource.AddActivityListener(exporterListener);

        using var sanitizingListener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist);
        sanitizingListener.ShouldListenTo = src => src.Name == sourceName;
        ActivitySource.AddActivityListener(sanitizingListener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("job.completed");
        Assert.NotNull(activity);
        activity.SetTag("unauthorized_key", "secret");
        activity.SetTag("status", "alice@example.com");
        activity.SetTag("action", "scan_complete");
        activity.Stop();

        Assert.DoesNotContain("unauthorized_key", captured.Keys);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, captured["status"]);
        Assert.Equal("scan_complete", captured["action"]);

        // Verify production DI integration when the exporter listener is registered BEFORE AddPrivacyTelemetry
        // and BEFORE CreateSanitizingListener:
        // (a) CreateExporterSafeActivityListener sanitizes direct ActivitySource spans before exporter observation.
        // (b) PrivacyTelemetryService.RecordSpan pre-sanitizes initialTags and re-sanitizes before Dispose()/Stop()
        //     even when an un-wrapped exporter listener (or ActivityStarted mutator) was registered first.
        var diSourceName = "KnowThankYew.DiExporterFirst." + Guid.NewGuid().ToString("N");
        var rawFirstCaptured = new Dictionary<string, object?>();
        using var rawExporterRegisteredFirst = new ActivityListener
        {
            ShouldListenTo = src => src.Name == PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                // Simulate a pre-registered listener mutating tags after Start() before Stop().
                act.SetTag("unauthorized_key", "injected_after_start");
                act.SetTag("status", "alice@example.com");
            },
            ActivityStopped = act =>
            {
                if (Equals(act.GetTagItem("job_id"), "job-52"))
                {
                    foreach (var kv in act.TagObjects)
                    {
                        rawFirstCaptured[kv.Key] = kv.Value;
                    }
                }
            }
        };
        ActivitySource.AddActivityListener(rawExporterRegisteredFirst);

        var diConfig = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                ["Privacy:NetworkEgress"] = "allow_otlp",
            })
            .Build();
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        KnowThankYew.Privacy.Telemetry.Extensions.ServiceCollectionExtensions.AddPrivacyTelemetry(
            services,
            diConfig,
            al => al.RegisterActivitySourceNames(new[] { diSourceName }));
        using var provider = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services);
        var diAllowlist = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<SafeAllowlist>(provider);
        var diTelemetry = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<PrivacyTelemetryService>(provider);

        var diExporterCaptured = new Dictionary<string, object?>();
        using var diExporterListener = KnowThankYew.Privacy.Telemetry.Extensions.ServiceCollectionExtensions.CreateExporterSafeActivityListener(
            provider,
            act =>
            {
                foreach (var kv in act.TagObjects)
                {
                    diExporterCaptured[kv.Key] = kv.Value;
                }
            },
            src => src.Name == diSourceName);
        ActivitySource.AddActivityListener(diExporterListener);

        using var diSanitizingListener = PrivacyActivityEnricher.CreateSanitizingListener(
            diAllowlist,
            diTelemetry,
            src => src.Name == diSourceName || src.Name == PrivacyTelemetryService.ActivitySourceName);
        ActivitySource.AddActivityListener(diSanitizingListener);

        diTelemetry.RecordSpan(
            "scan_complete",
            entityId: "job-52",
            status: "alice@example.com",
            durationMs: 5,
            attributes: new Dictionary<string, object>
            {
                ["unauthorized_key"] = "secret",
                ["action"] = "scan_complete",
            });

        Assert.DoesNotContain("unauthorized_key", rawFirstCaptured.Keys);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, rawFirstCaptured["status"]);
        Assert.Equal("scan_complete", rawFirstCaptured["action"]);

        using var diSource = new ActivitySource(diSourceName);
        using (var diActivity = diSource.StartActivity("job.completed"))
        {
            Assert.NotNull(diActivity);
            diActivity.SetTag("unauthorized_key", "secret");
            diActivity.SetTag("status", "alice@example.com");
            diActivity.SetTag("action", "scan_complete");
            diActivity.Stop();
        }

        Assert.DoesNotContain("unauthorized_key", diExporterCaptured.Keys);
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, diExporterCaptured["status"]);
        Assert.Equal("scan_complete", diExporterCaptured["action"]);
    }

    [Fact]
    public void SetSanitizedTag_SanitizesAtWriteTimeBeforeStop()
    {
        var sourceName = "KnowThankYew.WriteTimeSanitize." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource(sourceName);
        using var activity = source.StartActivity("job.completed");
        Assert.NotNull(activity);

        activity.SetSanitizedTag("unauthorized_key", "secret", allowlist);
        activity.SetSanitizedTag("status", "alice@example.com", allowlist);
        activity.SetSanitizedTag("action", "scan_complete", allowlist);

        // Verified prior to Stop() so mid-flight readers/processors never observe raw or unallowlisted tags.
        Assert.Null(activity.GetTagItem("unauthorized_key"));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, activity.GetTagItem("status"));
        Assert.Equal("scan_complete", activity.GetTagItem("action"));
    }

    private static IEnumerable<string> ThrowIoAfterFirstRuleId()
    {
        yield return "AR-001";
        throw new System.IO.IOException("Simulated enumerator I/O failure");
    }

    [Fact]
    public void TrySanitizeActivity_CatchesEnumeratorExceptionsWithoutEscapingAndRedactsCustomRawTokens()
    {
        var sourceName = "KnowThankYew.IteratorFailure." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(new[] { "rule_ids", "custom_field", "tenant" }, new[] { sourceName });
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        Activity? targetActivity = null;
        var downstreamObservedTags = new List<KeyValuePair<string, object?>>();
        using var downstreamListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = act =>
            {
                if (ReferenceEquals(act, targetActivity))
                {
                    downstreamObservedTags.AddRange(act.TagObjects);
                }
            }
        };
        ActivitySource.AddActivityListener(downstreamListener);

        using var source = new ActivitySource(sourceName);
        using var throwingAct = source.StartActivity("job.completed");
        Assert.NotNull(throwingAct);
        targetActivity = throwingAct;
        throwingAct!.SetTag("rule_ids", ThrowIoAfterFirstRuleId());
        throwingAct.SetTag("status", "alice@example.com");

        var ok = PrivacyActivityEnricher.TrySanitizeActivity(throwingAct, allowlist, out _);
        Assert.False(ok);
        Assert.False(throwingAct.Recorded);
        Assert.False(throwingAct.IsAllDataRequested);
        throwingAct.Stop();
        Assert.Empty(downstreamObservedTags);
        Assert.DoesNotContain(downstreamObservedTags, t => t.Value?.ToString()?.Contains("alice@example.com", StringComparison.Ordinal) == true);

        using var listenerCallbackAct = source.StartActivity("job.completed");
        Assert.NotNull(listenerCallbackAct);
        listenerCallbackAct!.SetTag("custom_field", "ACME_CORP");
        listenerCallbackAct.SetTag("tenant", "ACME_CORP");
        Assert.True(PrivacyActivityEnricher.TrySanitizeActivity(listenerCallbackAct, allowlist, out _));
        Assert.Equal(SafeAllowlist.RedactedSensitiveValue, listenerCallbackAct.GetTagItem("custom_field"));
        Assert.Null(listenerCallbackAct.GetTagItem("tenant"));
        Assert.Null(listenerCallbackAct.GetTagItem("[REDACTED_KEY]"));

        listenerCallbackAct.SetTag("rule_ids", ThrowIoAfterFirstRuleId());
        using var sanitizingListener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist);
        sanitizingListener.ShouldListenTo = src => src.Name == sourceName;
        ActivitySource.AddActivityListener(sanitizingListener);
        listenerCallbackAct.Stop();
        Assert.False(listenerCallbackAct.Recorded);
        Assert.False(listenerCallbackAct.IsAllDataRequested);
    }

    [Fact]
    public void AddSanitizedEvent_And_SetSanitizedTag_DiscardWritesAfterBurn()
    {
        var allowlist = new SafeAllowlist();
        var otlpConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                ["Privacy:BurnEnabled"] = "true",
                ["Privacy:NetworkEgress"] = "allow_otlp"
            })
            .Build();
        var telemetry = new KnowThankYew.Privacy.Telemetry.Core.PrivacyTelemetryService(
            configuration: otlpConfig,
            allowlist: allowlist);
        var uniqueJobId = $"job-{Guid.NewGuid():N}";
        Activity? captured = null;
        var burned = false;

        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == KnowThankYew.Privacy.Telemetry.Core.PrivacyTelemetryService.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = act =>
            {
                if (act.OperationName == "scan_started" &&
                    Equals(act.GetTagItem("job_id"), uniqueJobId))
                {
                    captured = act;
                    burned = true;
                    telemetry.Burn();
                    // Retaining the Activity and writing tags or events after Burn() must be a no-op.
                    captured.SetSanitizedTag("action", "scan_complete", allowlist);
                    PrivacyActivityEnricher.AddSanitizedEvent(captured, "rules_evaluated", allowlist);
                }
            }
        };
        ActivitySource.AddActivityListener(listener);

        telemetry.RecordSpan("scan_started", uniqueJobId, "OK", 1);
        Assert.True(burned);
        Assert.NotNull(captured);
        Assert.Empty(captured!.Events);
        Assert.Empty(captured.TagObjects);
        Assert.Empty(telemetry.GetBufferedSpans());
    }

    [Fact]
    public void TrySanitizeActivity_BurnDuringSanitizationAndThrowingBurnPredicate_FailClosed()
    {
        var allowlist = new SafeAllowlist(
            additionalKeys: new[] { "rule_ids" },
            additionalActivitySourceNames: new[] { "KnowThankYew.Custom.BurnDuringSanitize" });
        using var source = new ActivitySource("KnowThankYew.Custom.BurnDuringSanitize");
        using var sampler = new ActivityListener
        {
            ShouldListenTo = src => src.Name == "KnowThankYew.Custom.BurnDuringSanitize",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(sampler);

        // 1. Enumerating rule_ids during SanitizeActivity flips burned=true -> must still scrub and reject export.
        var isBurnedFlag = false;
        var exportCalled = 0;
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ => exportCalled++,
            allowRawPayloads: false,
            isBurned: () => isBurnedFlag);

        using var midBurnActivity = source.StartActivity("scan_started");
        Assert.NotNull(midBurnActivity);
        midBurnActivity!.SetTag("rule_ids", FlipBurnDuringEnumeration(() => isBurnedFlag = true));
        safeStop(midBurnActivity);
        Assert.Equal(0, exportCalled);
        Assert.False(midBurnActivity.Recorded);
        Assert.False(midBurnActivity.IsAllDataRequested);
        Assert.Empty(midBurnActivity.TagObjects);

        // 2. A throwing burn predicate must be contained and fail closed.
        var throwingStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            _ => exportCalled++,
            allowRawPayloads: false,
            isBurned: () => throw new ObjectDisposedException("session"));
        using var throwingPredActivity = source.StartActivity("scan_started");
        Assert.NotNull(throwingPredActivity);
        throwingPredActivity!.SetTag("action", "scan_started");
        throwingStop(throwingPredActivity);
        Assert.Equal(0, exportCalled);
        Assert.False(throwingPredActivity.Recorded);
        Assert.Empty(throwingPredActivity.TagObjects);

        // 3. Explicit 2-parameter CreateSanitizingListener(SafeAllowlist, bool) overload remains preserved.
        using var twoArgListener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, false);
        Assert.NotNull(twoArgListener);
    }

    [Fact]
    public void R29Hardening_BaggageCannotBypassSanitizationOrExporterBoundary_UnlessRawPayloadsAllowed()
    {
        var sourceName = "KnowThankYew.EnricherTest." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        using var source = new ActivitySource(sourceName);
        using var sampler = new ActivityListener
        {
            ShouldListenTo = s => s.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(sampler);

        // 1. Direct Activity.AddBaggage with PHI key (including duplicates) is stripped and allowlisted sensitive values are scrubbed when allowRawPayloads=false
        using (var directAct = source.StartActivity("parse_document"))
        {
            Assert.NotNull(directAct);
            directAct!.AddBaggage("patient_name", "Jane Doe");
            directAct.AddBaggage("patient_name", "Alice Smith");
            directAct.AddBaggage("jurisdiction", "CA");
            directAct.AddBaggage("rule_id", "alice@example.com");

            var ok = PrivacyActivityEnricher.TrySanitizeActivity(directAct, allowlist, out var reason, allowRawPayloads: false);
            Assert.True(ok, $"Expected benign activity after baggage scrub, got: {reason}");
            Assert.DoesNotContain(directAct.Baggage, b => b.Key == "patient_name");
            Assert.Contains(directAct.Baggage, b => b.Key == "jurisdiction" && b.Value == "CA");
            Assert.Contains(directAct.Baggage, b => b.Key == "rule_id" && b.Value == SafeAllowlist.RedactedSensitiveValue);
        }

        // 2. When allowRawPayloads=true, raw baggage is preserved
        using (var rawAct = source.StartActivity("parse_document"))
        {
            Assert.NotNull(rawAct);
            rawAct!.AddBaggage("patient_name", "Jane Doe");

            var ok = PrivacyActivityEnricher.TrySanitizeActivity(rawAct, allowlist, out _, allowRawPayloads: true);
            Assert.True(ok);
            Assert.Contains(rawAct.Baggage, b => b.Key == "patient_name" && b.Value == "Jane Doe");
        }

        // 3. Inherited parent Activity.Baggage cannot be removed from child enumeration, so TrySanitizeActivity fails closed
        using (var parentAct = source.StartActivity("parse_document"))
        {
            Assert.NotNull(parentAct);
            parentAct!.AddBaggage("patient_name", "Jane Doe");

            using var childAct = source.StartActivity("parse_document");
            Assert.NotNull(childAct);

            var exported = 0;
            var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                _ => exported++,
                allowRawPayloads: false);
            safeStop(childAct!);

            Assert.Equal(0, exported);
            Assert.False(childAct.Recorded);
            Assert.False(childAct.IsAllDataRequested);
        }
    }

    [Fact]
    public async Task AddSanitizedEvent_And_SetSanitizedTag_CoordinateWithLazyAndConcurrentBurn()
    {
        var allowlist = new SafeAllowlist(
            additionalKeys: new[] { "rule_ids" },
            additionalActivitySourceNames: new[]
            {
                "KnowThankYew.Custom.R36LazyEvent",
                "KnowThankYew.Custom.R36LazyTag",
                "KnowThankYew.Custom.R36Race"
            });
        var otlpConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://localhost:4318/v1/traces",
                ["Privacy:BurnEnabled"] = "true",
                ["Privacy:NetworkEgress"] = "allow_otlp"
            })
            .Build();

        // 1. Lazy tag enumerable triggering Burn() on the same thread during AddSanitizedEvent must neither deadlock nor leave event/tags.
        var lazyEventService = new KnowThankYew.Privacy.Telemetry.Core.PrivacyTelemetryService(
            configuration: otlpConfig,
            allowlist: allowlist);
        using var lazyEventSource = new ActivitySource("KnowThankYew.Custom.R36LazyEvent");
        using var lazyEventListener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            lazyEventService,
            shouldListenTo: src => src.Name == "KnowThankYew.Custom.R36LazyEvent");
        ActivitySource.AddActivityListener(lazyEventListener);

        using (var lazyEventActivity = lazyEventSource.StartActivity("scan_started"))
        {
            Assert.NotNull(lazyEventActivity);
            PrivacyActivityEnricher.AddSanitizedEvent(
                lazyEventActivity!,
                "rule.evaluated",
                allowlist,
                tags: FlipBurnDuringTagEnumeration(() => lazyEventService.Burn()));

            Assert.True(lazyEventService.IsBurned);
            Assert.Empty(lazyEventActivity!.Events);
            Assert.Empty(lazyEventActivity.TagObjects);
            Assert.False(lazyEventActivity.Recorded);
            Assert.False(lazyEventActivity.IsAllDataRequested);
        }

        // 2. Lazy value enumerable triggering Burn() during SetSanitizedTag must neither deadlock nor attach the tag.
        var lazyTagService = new KnowThankYew.Privacy.Telemetry.Core.PrivacyTelemetryService(
            configuration: otlpConfig,
            allowlist: allowlist);
        using var lazyTagSource = new ActivitySource("KnowThankYew.Custom.R36LazyTag");
        using var lazyTagListener = PrivacyActivityEnricher.CreateSanitizingListener(
            allowlist,
            lazyTagService,
            shouldListenTo: src => src.Name == "KnowThankYew.Custom.R36LazyTag");
        ActivitySource.AddActivityListener(lazyTagListener);

        using (var lazyTagActivity = lazyTagSource.StartActivity("scan_started"))
        {
            Assert.NotNull(lazyTagActivity);
            lazyTagActivity!.SetSanitizedTag(
                "rule_ids",
                FlipBurnDuringEnumeration(() => lazyTagService.Burn()),
                allowlist);

            Assert.True(lazyTagService.IsBurned);
            Assert.Empty(lazyTagActivity.TagObjects);
            Assert.False(lazyTagActivity.Recorded);
            Assert.False(lazyTagActivity.IsAllDataRequested);
        }

        // 3. Concurrent Burn() vs SetSanitizedTag/AddSanitizedEvent must drain in-flight writes so nothing remains after Burn() returns.
        using var raceSource = new ActivitySource("KnowThankYew.Custom.R36Race");
        for (var iteration = 0; iteration < 40; iteration++)
        {
            var raceService = new KnowThankYew.Privacy.Telemetry.Core.PrivacyTelemetryService(
                configuration: otlpConfig,
                allowlist: allowlist);
            using var raceListener = PrivacyActivityEnricher.CreateSanitizingListener(
                allowlist,
                raceService,
                shouldListenTo: src => src.Name == "KnowThankYew.Custom.R36Race");
            ActivitySource.AddActivityListener(raceListener);

            if (iteration == 0)
            {
                using var checkActivity = raceSource.StartActivity("scan_started");
                Assert.NotNull(checkActivity);
                Assert.True(checkActivity!.IsAllDataRequested);
                checkActivity.SetSanitizedTag("action", "scan_started", allowlist);
                Assert.NotEmpty(checkActivity.TagObjects);
            }

            using var raceActivity = raceSource.StartActivity("scan_started");
            Assert.NotNull(raceActivity);
            Assert.True(raceActivity!.IsAllDataRequested);

            using var startGate = new ManualResetEventSlim(false);
            using var inFlightWriteEntered = new ManualResetEventSlim(false);
            using var releaseInFlightWrite = new ManualResetEventSlim(false);
            var writerTask = Task.Run(() =>
            {
                startGate.Wait();
                raceActivity!.SetSanitizedTag(
                    "rule_ids",
                    new HandshakeRuleIdsEnumerable(inFlightWriteEntered, releaseInFlightWrite),
                    allowlist);
                for (var w = 0; w < 25; w++)
                {
                    raceActivity.SetSanitizedTag("action", "scan_complete", allowlist);
                    PrivacyActivityEnricher.AddSanitizedEvent(raceActivity, "rule.evaluated", allowlist);
                }
            });

            startGate.Set();
            Assert.True(inFlightWriteEntered.Wait(TimeSpan.FromSeconds(5)));
            var burnTask = Task.Run(() => raceService.Burn());
            Assert.True(SpinWait.SpinUntil(() => raceService.IsBurned, TimeSpan.FromSeconds(5)));
            releaseInFlightWrite.Set();

            await burnTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Empty(raceActivity!.TagObjects);
            Assert.Empty(raceActivity.Events);
            Assert.False(raceActivity.Recorded);
            Assert.False(raceActivity.IsAllDataRequested);

            await writerTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Empty(raceActivity.TagObjects);
            Assert.Empty(raceActivity.Events);
        }
    }

    [Fact]
    public void AllowRawPayloads_EnforcesMetadataLengthBoundsOnMutableAndImmutableActivityMetadata()
    {
        var sourceName = "KnowThankYew.EnricherTest.RawLength." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var exported = new List<Activity>();
        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            exported.Add,
            allowRawPayloads: true);

        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = safeStop,
        };
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource(sourceName);

        // 1. Mutable metadata (DisplayName, StatusDescription, TraceStateString, Baggage, mutable tag key & value)
        // must still be truncated to [TRUNCATED_HASH_...] when allowRawPayloads is enabled.
        using (var mutableActivity = source.StartActivity("scan_started"))
        {
            Assert.NotNull(mutableActivity);
            mutableActivity!.DisplayName = new string('d', 10_000);
            mutableActivity.SetStatus(ActivityStatusCode.Error, new string('s', 10_000));
            mutableActivity.TraceStateString = new string('t', 10_000);
            mutableActivity.SetBaggage("raw_baggage", new string('b', 10_000));
            mutableActivity.SetTag(new string('k', 10_000), new string('v', 10_000));
            mutableActivity.Stop();

            Assert.Single(exported);
            Assert.StartsWith("[TRUNCATED_HASH_", mutableActivity.DisplayName);
            Assert.NotNull(mutableActivity.StatusDescription);
            Assert.StartsWith("[TRUNCATED_HASH_", mutableActivity.StatusDescription!);
            Assert.NotNull(mutableActivity.TraceStateString);
            Assert.StartsWith("[TRUNCATED_HASH_", mutableActivity.TraceStateString!);
            var baggageVal = Assert.Single(mutableActivity.Baggage).Value;
            Assert.NotNull(baggageVal);
            Assert.StartsWith("[TRUNCATED_HASH_", baggageVal!);
            var tag = Assert.Single(mutableActivity.TagObjects);
            Assert.StartsWith("[TRUNCATED_HASH_", tag.Key);
            Assert.StartsWith("[TRUNCATED_HASH_", Assert.IsType<string>(tag.Value));
        }

        // 2. Oversized immutable event tag values must fail closed and drop the span even in allowRawPayloads mode.
        exported.Clear();
        using (var eventActivity = source.StartActivity("scan_started"))
        {
            Assert.NotNull(eventActivity);
            eventActivity!.AddEvent(new ActivityEvent(
                "raw_evt",
                tags: new ActivityTagsCollection
                {
                    ["event_blob"] = new string('e', 10_000),
                }));

            var ok = PrivacyActivityEnricher.TrySanitizeActivity(
                eventActivity,
                allowlist,
                out var rejectionReason,
                allowRawPayloads: true);

            Assert.False(ok);
            Assert.NotNull(rejectionReason);
            Assert.False(eventActivity.Recorded);
            Assert.False(eventActivity.IsAllDataRequested);
            Assert.Empty(eventActivity.TagObjects);
        }
        Assert.Empty(exported);

        // 3. Oversized immutable Activity.OperationName must also fail closed in allowRawPayloads mode.
        using (var opActivity = source.StartActivity(new string('o', 10_000)))
        {
            Assert.NotNull(opActivity);
            opActivity!.DisplayName = "short_display";
            opActivity.Stop();

            Assert.False(opActivity.Recorded);
            Assert.False(opActivity.IsAllDataRequested);
            Assert.Empty(exported);
        }

        // 4. Oversized immutable ActivityLink TraceState must fail closed in allowRawPayloads mode.
        var linkedContext = new ActivityContext(
            ActivityTraceId.CreateRandom(),
            ActivitySpanId.CreateRandom(),
            ActivityTraceFlags.Recorded,
            traceState: new string('l', 10_000));
        using (var linkActivity = source.StartActivity(
                   "scan_started",
                   ActivityKind.Internal,
                   parentContext: default,
                   links: new[] { new ActivityLink(linkedContext) }))
        {
            Assert.NotNull(linkActivity);
            linkActivity!.Stop();

            Assert.False(linkActivity.Recorded);
            Assert.False(linkActivity.IsAllDataRequested);
            Assert.Empty(exported);
        }
    }

    [Fact]
    public async Task BurnServiceAndWait_DrainsGatedExporterCallbackWhenBurnRunsViaTaskRun()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                ["Privacy:BurnEnabled"] = "true",
                ["Privacy:NetworkEgress"] = "allow_otlp",
            })
            .Build();
        var sourceName = "KnowThankYew.EnricherTest.AsyncInherited." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });
        var service = new PrivacyTelemetryService(configuration: config, allowlist: allowlist);

        using var callbackEntered = new ManualResetEventSlim(false);
        using var releaseCallback = new ManualResetEventSlim(false);
        Task? backgroundBurn = null;
        var exportedCountAfterGate = 0;

        var safeStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
            allowlist,
            act =>
            {
                // Launch Burn() via Task.Run inside the active exporter callback so AsyncLocal would
                // have inherited the callback lease. Thread-local ancestry ensures this independent
                // background burn waits until the callback finishes and releases the gate.
                Volatile.Write(ref backgroundBurn, Task.Run(() => service.Burn()));
                callbackEntered.Set();
                Assert.True(releaseCallback.Wait(TimeSpan.FromSeconds(5)));
                Interlocked.Increment(ref exportedCountAfterGate);
            },
            service);

        using var source = new ActivitySource(sourceName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = safeStop,
        };
        ActivitySource.AddActivityListener(listener);

        var stopTask = Task.Run(() =>
        {
            using var act = source.StartActivity("job.accepted");
            Assert.NotNull(act);
        });

        Assert.True(callbackEntered.Wait(TimeSpan.FromSeconds(5)));
        var burnTask = Volatile.Read(ref backgroundBurn);
        Assert.NotNull(burnTask);

        // Wait for Burn() to enter and flip the service tombstone before checking that it waits on the export lease.
        Assert.True(SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));
        var completedEarly = await Task.WhenAny(burnTask!, Task.Delay(200)) == burnTask;
        Assert.False(completedEarly);
        Assert.False(burnTask!.IsCompleted);

        releaseCallback.Set();
        await Task.WhenAll(stopTask, burnTask).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(service.IsBurned);
        Assert.Equal(1, Volatile.Read(ref exportedCountAfterGate));
    }

    [Fact]
    public void SanitizeAndBurnCleanup_RemoveEveryDuplicateLocalBaggageOccurrence()
    {
        var sourceName = "KnowThankYew.EnricherTest.DupBaggage." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });

        using (var source = new ActivitySource(sourceName))
        using (var listener = PrivacyActivityEnricher.CreateSanitizingListener(
                   allowlist,
                   shouldListenTo: src => src.Name == sourceName))
        {
            ActivitySource.AddActivityListener(listener);

            using var act = source.StartActivity("job.accepted");
            Assert.NotNull(act);
            act!.AddBaggage("job_id", "alice@example.com");
            act.AddBaggage("job_id", "bob@example.com");
            act.AddBaggage("patient_email", "alice@example.com");
            act.AddBaggage("patient_email", "carol@example.com");
            act.Stop();

            Assert.DoesNotContain(act.Baggage, kv => kv.Value?.Contains("@example.com", StringComparison.Ordinal) == true);
            Assert.DoesNotContain(act.Baggage, kv => kv.Key == "patient_email");
            Assert.All(act.Baggage, kv =>
            {
                Assert.Equal("job_id", kv.Key);
                Assert.Equal(SafeAllowlist.RedactedSensitiveValue, kv.Value);
            });
            Assert.Single(act.Baggage);
        }

        // Also verify burned-scrub clears every duplicate local occurrence completely.
        using (var burnSource = new ActivitySource(sourceName + ".Burn"))
        {
            var burnAllowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { burnSource.Name });
            var burnFlag = false;
            using var burnListener = PrivacyActivityEnricher.CreateSanitizingListener(
                burnAllowlist,
                allowRawPayloads: false,
                shouldListenTo: src => src.Name == burnSource.Name,
                isBurned: () => burnFlag);
            ActivitySource.AddActivityListener(burnListener);

            using var burnedAct = burnSource.StartActivity("job.accepted");
            Assert.NotNull(burnedAct);
            burnedAct!.AddBaggage("job_id", "alice@example.com");
            burnedAct.AddBaggage("job_id", "bob@example.com");
            burnFlag = true;
            burnedAct.Stop();

            Assert.Empty(burnedAct.Baggage);
        }
    }

    [Fact]
    public void Propagator_SuppressesInheritedParentBaggageOnRejectedOrBurnedChildren_UnlessAllowRawPayloadsEnabled()
    {
        var sourceName = "KnowThankYew.EnricherTest.Propagator." + Guid.NewGuid().ToString("N");
        var allowlist = new SafeAllowlist(additionalKeys: null, additionalActivitySourceNames: new[] { sourceName });

        var previousPropagator = DistributedContextPropagator.Current;
        try
        {
            using var parent = new Activity("ambient-http-in").Start();
            parent.AddBaggage("patient_email", "alice@example.com");

            // 1. Default fail-closed listener rejects child with inherited unsafe baggage and suppresses injection.
            PrivacyActivityEnricher.InstallSanitizingPropagator(allowlist);
            using (var source = new ActivitySource(sourceName))
            using (var listener = PrivacyActivityEnricher.CreateSanitizingListener(
                       allowlist,
                       allowRawPayloads: false,
                       shouldListenTo: src => src.Name == sourceName))
            {
                ActivitySource.AddActivityListener(listener);

                using var child = source.StartActivity("job.accepted");
                Assert.NotNull(child);
                Assert.False(child!.Recorded);
                Assert.False(child.IsAllDataRequested);

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                DistributedContextPropagator.Current.Inject(
                    child,
                    headers,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);

                Assert.False(headers.ContainsKey("baggage"));
                Assert.False(headers.ContainsKey("Correlation-Context"));
                Assert.False(headers.ContainsKey("tracestate"));
                Assert.DoesNotContain(headers.Values, v => v.Contains("alice", StringComparison.OrdinalIgnoreCase));
            }

            // 2. Default memory-only service binds propagator to denied egress (zero headers); OTLP service emits only allowlisted baggage.
            var defaultMemoryService = new PrivacyTelemetryService(allowlist: allowlist);
            PrivacyActivityEnricher.InstallSanitizingPropagator(allowlist, defaultMemoryService);
            using (var noListenerSource = new ActivitySource(sourceName + ".NoListener"))
            using (var activeListener = new ActivityListener
                   {
                       ShouldListenTo = s => s.Name == noListenerSource.Name,
                       Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                   })
            {
                ActivitySource.AddActivityListener(activeListener);
                using var child = noListenerSource.StartActivity("job.accepted");
                Assert.NotNull(child);
                child!.AddBaggage("job_id", "job-123");

                var defaultHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                DistributedContextPropagator.Current.Inject(
                    child,
                    defaultHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);
                Assert.Empty(defaultHeaders);

                var defaultBoundPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
                    allowlist,
                    defaultMemoryService,
                    allowRawPayloads: false);
                defaultBoundPropagator.Inject(
                    child,
                    defaultHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);
                Assert.Empty(defaultHeaders);

                var sanitizingPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(allowlist, allowRawPayloads: false);
                var filteredHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                sanitizingPropagator.Inject(
                    child,
                    filteredHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);

                Assert.DoesNotContain(filteredHeaders.Values, v => v.Contains("alice", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(filteredHeaders.Values, v => v.Contains("patient_email", StringComparison.OrdinalIgnoreCase));
                Assert.Contains("job_id=job-123", filteredHeaders["baggage"]);
            }

            // 3. Burned child suppresses all propagation even when allowRawPayloads is true.
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                    ["Privacy:BurnEnabled"] = "true",
                    ["Privacy:NetworkEgress"] = "allow_otlp",
                })
                .Build();
            var rawAllowlist = new SafeAllowlist(null, new[] { sourceName + ".Raw" });
            var rawService = new PrivacyTelemetryService(configuration: config, allowlist: rawAllowlist);
            PrivacyActivityEnricher.InstallSanitizingPropagator(rawAllowlist, rawService, allowRawPayloads: true);
            using (var rawSource = new ActivitySource(sourceName + ".Raw"))
            using (var rawListener = PrivacyActivityEnricher.CreateSanitizingListener(
                       rawAllowlist,
                       rawService,
                       shouldListenTo: s => s.Name == rawSource.Name,
                       allowRawPayloads: true))
            {
                ActivitySource.AddActivityListener(rawListener);

                using var rawChild = rawSource.StartActivity("job.accepted");
                Assert.NotNull(rawChild);

                var rawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                DistributedContextPropagator.Current.Inject(
                    rawChild,
                    rawHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);

                Assert.True(rawHeaders.ContainsKey("baggage"));
                Assert.Contains("patient_email", rawHeaders["baggage"]);
                Assert.Contains("alice@example.com", rawHeaders["baggage"]);

                rawService.Burn();

                var burnedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                DistributedContextPropagator.Current.Inject(
                    rawChild,
                    burnedHeaders,
                    static (carrier, key, value) => ((Dictionary<string, string>)carrier!)[key] = value);

                Assert.Empty(burnedHeaders);
            }
        }
        finally
        {
            DistributedContextPropagator.Current = previousPropagator;
        }
    }

    [Fact]
    public void Propagator_InjectNull_SanitizesAmbientActivityCurrent_AndDropsBurnedAmbientCurrent()
    {
        var allowlist = new SafeAllowlist();
        const string sourceName = "KnowThankYew.PropagatorNullTests";
        using var source = new ActivitySource(sourceName);
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(listener);

        var burned = false;
        var ambientReadingInner = new AmbientReadingTestPropagator();
        var propagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: false,
            isBurned: () => burned,
            innerPropagator: ambientReadingInner);
        var passThroughPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: false,
            isBurned: () => burned,
            innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());

        using var activity = source.StartActivity("scan_completed");
        Assert.NotNull(activity);
        activity!.AddBaggage("user_email", "alice@example.com");
        activity.AddBaggage("action", "scan_complete");
        Assert.Same(activity, Activity.Current);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        propagator.Inject(null, headers, (carrier, key, value) =>
        {
            if (carrier is Dictionary<string, string> dict && value is not null)
            {
                dict[key] = value;
            }
        });

        Assert.True(headers.ContainsKey("baggage"));
        Assert.DoesNotContain("alice@example.com", headers["baggage"]);
        Assert.DoesNotContain("user_email", headers["baggage"]);
        Assert.Contains("action=scan_complete", headers["baggage"]);
        Assert.DoesNotContain("tracestate", headers.Keys, StringComparer.OrdinalIgnoreCase);

        var passThroughHeaders = new List<(string Key, string? Value)>();
        passThroughPropagator.Inject(null, passThroughHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.All(passThroughHeaders, h => Assert.DoesNotContain("alice@example.com", h.Value ?? string.Empty));

        burned = true;
        var burnedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        propagator.Inject(null, burnedHeaders, (carrier, key, value) =>
        {
            if (carrier is Dictionary<string, string> dict && value is not null)
            {
                dict[key] = value;
            }
        });
        Assert.Empty(burnedHeaders);
    }

    [Fact]
    public void Propagator_ServiceBoundOverload_BlocksTraceparentAndBaggage_WhenNetworkEgressDisallowed()
    {
        var allowlist = new SafeAllowlist();
        var memoryOnlyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "memory_only",
                ["Privacy:NetworkEgress"] = "memory_only",
                ["Privacy:BurnEnabled"] = "true",
            })
            .Build();
        var denyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                ["Privacy:NetworkEgress"] = "deny",
                ["Privacy:BurnEnabled"] = "true",
            })
            .Build();

        var memoryOnlyService = new PrivacyTelemetryService(configuration: memoryOnlyConfig, allowlist: allowlist);
        var denyService = new PrivacyTelemetryService(configuration: denyConfig, allowlist: allowlist);

        var memoryOnlyPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            memoryOnlyService,
            allowRawPayloads: false,
            innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());
        var denyRawPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            denyService,
            allowRawPayloads: true,
            innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());

        using var activity = new Activity("outbound.req").SetIdFormat(ActivityIdFormat.W3C).Start();
        activity.AddBaggage("action", "scan_complete");

        var memoryHeaders = new List<(string Key, string? Value)>();
        memoryOnlyPropagator.Inject(activity, memoryHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.Empty(memoryHeaders);

        var denyHeaders = new List<(string Key, string? Value)>();
        denyRawPropagator.Inject(activity, denyHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.Empty(denyHeaders);
    }

    [Fact]
    public void Propagator_SuppressesPreW3CRequestIdAndTracestateHeaders_FailClosed()
    {
        var allowlist = new SafeAllowlist();
        using (var hierarchicalActivity = new Activity("legacy.req")
            .SetIdFormat(ActivityIdFormat.Hierarchical)
            .SetParentId("|patient@example.invalid.")
            .Start())
        {
            hierarchicalActivity.TraceStateString = "tenant=secret";
            hierarchicalActivity.AddBaggage("service", "care-check");
            hierarchicalActivity.AddBaggage("patient_email", "bob@example.invalid");

            var preW3CPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
                allowlist,
                allowRawPayloads: false,
                innerPropagator: DistributedContextPropagator.CreatePreW3CPropagator());

            var preW3CHeaders = new List<(string Key, string? Value)>();
            preW3CPropagator.Inject(hierarchicalActivity, preW3CHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));

            Assert.DoesNotContain(preW3CHeaders, h => string.Equals(h.Key, "Request-Id", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(preW3CHeaders, h => string.Equals(h.Key, "tracestate", StringComparison.OrdinalIgnoreCase));
            Assert.All(preW3CHeaders, h => Assert.DoesNotContain("patient@example.invalid", h.Value ?? string.Empty));
            Assert.All(preW3CHeaders, h => Assert.DoesNotContain("bob@example.invalid", h.Value ?? string.Empty));
        }

        using var w3cActivity = new Activity("w3c.req").SetIdFormat(ActivityIdFormat.W3C).Start();
        w3cActivity.AddBaggage("service", "care-check");
        var customInner = new TestHeaderInjectingPropagator(new[]
        {
            ("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            ("traceparent", "alice@example.com"),
            ("Request-Id", "|patient@example.invalid."),
            ("tracestate", "tenant=acme"),
            ("X-Custom-Secret", "alice@example.com"),
            ("baggage", "service=care-check"),
        });
        var failClosed = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: false,
            innerPropagator: customInner);
        var filtered = new List<(string Key, string? Value)>();
        failClosed.Inject(w3cActivity, filtered, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));

        Assert.Equal(2, filtered.Count);
        Assert.Contains(filtered, h => h.Key == "traceparent" && h.Value == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        Assert.DoesNotContain(filtered, h => h.Value == "alice@example.com");
        Assert.Contains(filtered, h => h.Key == "baggage" && h.Value == "service=care-check");

        var rawPassThrough = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: true,
            innerPropagator: customInner);
        var unfiltered = new List<(string Key, string? Value)>();
        rawPassThrough.Inject(w3cActivity, unfiltered, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.Contains(unfiltered, h => h.Key == "traceparent" && h.Value == "alice@example.com");
        Assert.Equal(6, unfiltered.Count);
    }

    [Fact]
    public void Propagator_DetachedActivityWithCleanBaggage_DoesNotLeakAmbientBaggageViaPassThroughPropagator()
    {
        var allowlist = new SafeAllowlist();
        using var ambientActivity = new Activity("ambient.req").SetIdFormat(ActivityIdFormat.W3C).Start();
        ambientActivity.AddBaggage("tenant", "Acme");
        ambientActivity.AddBaggage("status", "secret@example.com");

        using var detachedActivity = new Activity("detached.req").SetIdFormat(ActivityIdFormat.W3C);
        detachedActivity.AddBaggage("status", "OK");
        Assert.False(detachedActivity.Recorded);

        var previousCurrent = Activity.Current;
        try
        {
            Assert.Same(ambientActivity, Activity.Current);
            var passThrough = DistributedContextPropagator.CreatePassThroughPropagator();
            var propagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
                allowlist,
                allowRawPayloads: false,
                innerPropagator: passThrough);

            var headers = new List<(string Key, string? Value)>();
            propagator.Inject(
                detachedActivity,
                headers,
                (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));

            var baggageHeaders = headers
                .Where(h => string.Equals(h.Key, "baggage", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(h.Key, "Correlation-Context", StringComparison.OrdinalIgnoreCase))
                .ToList();
            Assert.Single(baggageHeaders);
            Assert.Equal("status=OK", baggageHeaders[0].Value);
            Assert.All(headers, h =>
            {
                Assert.DoesNotContain("Acme", h.Value ?? string.Empty);
                Assert.DoesNotContain("secret@example.com", h.Value ?? string.Empty);
                Assert.DoesNotContain("tenant", h.Value ?? string.Empty);
            });
        }
        finally
        {
            Activity.Current = previousCurrent;
        }
    }

    [Fact]
    public async Task Propagator_ConcurrentBurn_WaitsForInFlightInject_AndAbortsRemainingSetterCallbacks()
    {
        var allowlist = new SafeAllowlist();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                ["Privacy:BurnEnabled"] = "true",
                ["Privacy:NetworkEgress"] = "allow_otlp",
            })
            .Build();
        var service = new PrivacyTelemetryService(configuration: config, allowlist: allowlist);

        using var firstHeaderEmitted = new System.Threading.ManualResetEventSlim(false);
        using var allowSecondHeader = new System.Threading.ManualResetEventSlim(false);
        var pausingInner = new PausingInjectPropagator(
            firstHeaderEmitted,
            allowSecondHeader,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        var propagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            service,
            allowRawPayloads: false,
            innerPropagator: pausingInner);

        using var activity = new Activity("concurrent.inject").SetIdFormat(ActivityIdFormat.W3C).Start();
        activity.AddBaggage("service", "care-check");

        var captured = new List<(string Key, string? Value)>();
        var injectTask = Task.Run(() => propagator.Inject(
            activity,
            captured,
            (c, k, v) => ((List<(string, string?)>)c!).Add((k, v))));

        Assert.True(firstHeaderEmitted.Wait(TimeSpan.FromSeconds(5)));
        var burnTask = Task.Run(() => service.Burn());
        Assert.True(System.Threading.SpinWait.SpinUntil(() => service.IsBurned, TimeSpan.FromSeconds(5)));
        await Task.Delay(50);
        Assert.False(burnTask.IsCompleted);

        allowSecondHeader.Set();
        await Task.WhenAll(injectTask, burnTask).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Single(captured);
        Assert.Equal("traceparent", captured[0].Key);
    }

    private sealed class AmbientReadingTestPropagator : DistributedContextPropagator
    {
        public override IReadOnlyCollection<string> Fields => new[] { "traceparent", "tracestate", "baggage" };

        public override void Inject(Activity? activity, object? carrier, PropagatorSetterCallback? setter)
        {
            if (setter is null) return;
            var target = activity ?? Activity.Current;
            if (target is null) return;
            if (!string.IsNullOrEmpty(target.Id))
            {
                setter(carrier, "traceparent", target.Id);
            }
            setter(carrier, "tracestate", "tenant=leaked");
            var pairs = target.Baggage.Select(kv => $"{kv.Key}={kv.Value}").ToArray();
            if (pairs.Length > 0)
            {
                setter(carrier, "baggage", string.Join(", ", pairs));
            }
        }

        public override void ExtractTraceIdAndState(object? carrier, PropagatorGetterCallback? getter, out string? traceId, out string? traceState)
        {
            traceId = null;
            traceState = null;
        }

        public override IEnumerable<KeyValuePair<string, string?>>? ExtractBaggage(object? carrier, PropagatorGetterCallback? getter) => null;
    }

    private sealed class TestHeaderInjectingPropagator(IEnumerable<(string Key, string Value)> headers)
        : DistributedContextPropagator
    {
        public override IReadOnlyCollection<string> Fields { get; } =
            headers.Select(h => h.Key).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        public override void Inject(Activity? activity, object? carrier, PropagatorSetterCallback? setter)
        {
            if (setter is null) return;
            foreach (var (key, value) in headers)
            {
                setter(carrier, key, value);
            }
        }

        public override void ExtractTraceIdAndState(object? carrier, PropagatorGetterCallback? getter, out string? traceId, out string? traceState)
        {
            traceId = null;
            traceState = null;
        }

        public override IEnumerable<KeyValuePair<string, string?>>? ExtractBaggage(object? carrier, PropagatorGetterCallback? getter) => null;
    }

    private sealed class PausingInjectPropagator(
        System.Threading.ManualResetEventSlim firstHeaderEmitted,
        System.Threading.ManualResetEventSlim allowSecondHeader,
        string validTraceParent) : DistributedContextPropagator
    {
        public override IReadOnlyCollection<string> Fields => new[] { "traceparent", "baggage" };

        public override void Inject(Activity? activity, object? carrier, PropagatorSetterCallback? setter)
        {
            if (setter is null) return;
            setter(carrier, "traceparent", validTraceParent);
            firstHeaderEmitted.Set();
            allowSecondHeader.Wait(TimeSpan.FromSeconds(5));
            setter(carrier, "baggage", "service=care-check");
        }

        public override void ExtractTraceIdAndState(object? carrier, PropagatorGetterCallback? getter, out string? traceId, out string? traceState)
        {
            traceId = null;
            traceState = null;
        }

        public override IEnumerable<KeyValuePair<string, string?>>? ExtractBaggage(object? carrier, PropagatorGetterCallback? getter) => null;
    }

    private static IEnumerable<KeyValuePair<string, object?>> FlipBurnDuringTagEnumeration(Action burn)
    {
        burn();
        yield return new KeyValuePair<string, object?>("action", "scan_complete");
    }

    private static IEnumerable<string> FlipBurnDuringEnumeration(Action flip)
    {
        flip();
        yield return "AR-001";
    }

    [Fact]
    public void Propagator_ThrowingBurnPredicate_FailsClosedWithoutThrowingAndEmitsNoHeaders()
    {
        var allowlist = new SafeAllowlist();
        var strictPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: false,
            isBurned: () => throw new ObjectDisposedException("session"),
            innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());
        var rawPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
            allowlist,
            allowRawPayloads: true,
            isBurned: () => throw new InvalidOperationException("disposed"),
            innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());

        using var activity = new Activity("outbound.req").SetIdFormat(ActivityIdFormat.W3C).Start();
        activity.AddBaggage("action", "scan_complete");

        var strictHeaders = new List<(string Key, string? Value)>();
        strictPropagator.Inject(activity, strictHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.Empty(strictHeaders);

        var rawHeaders = new List<(string Key, string? Value)>();
        rawPropagator.Inject(activity, rawHeaders, (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
        Assert.Empty(rawHeaders);
    }

    [Fact]
    public async Task Propagator_ChildActivity_InheritsAncestorBurnAndDeniedEgressPolicy()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var denySourceName = "KnowThankYew.EnricherTest.ChildDeny." + suffix;
        var burnSourceName = "KnowThankYew.EnricherTest.ChildBurn." + suffix;
        var childSourceName = "KnowThankYew.EnricherTest.ChildOnly." + suffix;
        var allowlist = new SafeAllowlist(
            additionalKeys: null,
            additionalActivitySourceNames: new[] { denySourceName, burnSourceName, childSourceName });

        var denyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Telemetry:Mode"] = "otlp",
                ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                ["Privacy:NetworkEgress"] = "deny",
                ["Privacy:BurnEnabled"] = "true",
            })
            .Build();
        var denyService = new PrivacyTelemetryService(configuration: denyConfig, allowlist: allowlist);

        var prevParent = Activity.Current;
        var prevPropagator = DistributedContextPropagator.Current;
        Activity.Current = null;
        try
        {
            // R48 #3: Constructing services, listeners, or calling TrySanitizeActivity must not replace DistributedContextPropagator.Current implicitly.
            var baselinePropagator = DistributedContextPropagator.CreatePassThroughPropagator();
            DistributedContextPropagator.Current = baselinePropagator;
            _ = new PrivacyTelemetryService(allowlist: allowlist);
            using (var checkListener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist, denyService, src => src.Name == denySourceName))
            {
                Assert.Same(baselinePropagator, DistributedContextPropagator.Current);
            }

            PrivacyActivityEnricher.InstallSanitizingPropagator(allowlist);

            // 1. Child HttpClient-style activity (no own custom properties) under a denied-egress parent activity
            using (var denySource = new ActivitySource(denySourceName))
            using (var denyListener = PrivacyActivityEnricher.CreateSanitizingListener(
                       allowlist,
                       denyService,
                       src => src.Name == denySourceName))
            {
                ActivitySource.AddActivityListener(denyListener);
                using var parent = denySource.StartActivity("job.accepted");
                Assert.NotNull(parent);
                parent!.AddBaggage("job_id", "job-deny-1");

                using var child = new Activity("System.Net.Http.HttpRequestOut")
                    .SetIdFormat(ActivityIdFormat.W3C)
                    .Start();
                Assert.Same(parent, child.Parent);

                var defaultHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    child,
                    defaultHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.Empty(defaultHeaders);

                var explicitPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
                    allowlist,
                    allowRawPayloads: true,
                    innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());
                var explicitHeaders = new List<(string Key, string? Value)>();
                explicitPropagator.Inject(
                    child,
                    explicitHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.Empty(explicitHeaders);
            }

            // 2. Child activity under a burned parent activity
            var activeConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Telemetry:Mode"] = "otlp",
                    ["Telemetry:OtlpEndpoint"] = "http://127.0.0.1:4318/v1/traces",
                    ["Privacy:NetworkEgress"] = "allow_otlp",
                    ["Privacy:BurnEnabled"] = "true",
                })
                .Build();
            var burnService = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);

            using (var burnSource = new ActivitySource(burnSourceName))
            using (var burnListener = PrivacyActivityEnricher.CreateSanitizingListener(
                       allowlist,
                       burnService,
                       src => src.Name == burnSourceName))
            {
                ActivitySource.AddActivityListener(burnListener);
                using var parent = burnSource.StartActivity("job.accepted");
                Assert.NotNull(parent);
                parent!.AddBaggage("job_id", "job-burn-1");

                using var child = new Activity("System.Net.Http.HttpRequestOut")
                    .SetIdFormat(ActivityIdFormat.W3C)
                    .Start();
                Assert.Same(parent, child.Parent);

                burnService.Burn();

                var defaultHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    child,
                    defaultHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.Empty(defaultHeaders);

                var explicitPropagator = PrivacyActivityEnricher.CreateSanitizingPropagator(
                    allowlist,
                    allowRawPayloads: true,
                    innerPropagator: DistributedContextPropagator.CreatePassThroughPropagator());
                var explicitHeaders = new List<(string Key, string? Value)>();
                explicitPropagator.Inject(
                    child,
                    explicitHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.Empty(explicitHeaders);
            }

            // R44 #1: Foreign service listener does not overwrite or strip owning service's allowlist attributes.
            var allowlistWithLineCount = new SafeAllowlist(
                additionalKeys: new[] { "line_count" },
                additionalActivitySourceNames: new[] { burnSourceName });
            var defaultAllowlist = new SafeAllowlist(
                additionalKeys: null,
                additionalActivitySourceNames: new[] { burnSourceName });
            var serviceA = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlistWithLineCount);
            var serviceB = new PrivacyTelemetryService(configuration: activeConfig, allowlist: defaultAllowlist);
            using (var sharedSource = new ActivitySource(burnSourceName))
            using (var listenerA = PrivacyActivityEnricher.CreateSanitizingListener(
                       allowlistWithLineCount,
                       serviceA,
                       src => ReferenceEquals(src, sharedSource)))
            using (var listenerB = PrivacyActivityEnricher.CreateSanitizingListener(
                       defaultAllowlist,
                       serviceB,
                       src => ReferenceEquals(src, sharedSource)))
            {
                ActivitySource.AddActivityListener(listenerA);
                ActivitySource.AddActivityListener(listenerB);
                using var actA = sharedSource.StartActivity("scan_started");
                Assert.NotNull(actA);
                actA!.SetTag("line_count", 42);
                actA.Stop();
                Assert.Equal(42, actA.GetTagItem("line_count"));
            }

            // R44 #2: Child Activity with exporter callback bound to serviceB still drains and purges ancestor owner serviceA.
            var parentService = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
            var childExporterService = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
            var parentPurges = 0;
            parentService.RegisterBurnPurgeHook(() => Interlocked.Increment(ref parentPurges));
            using (var hierarchySource = new ActivitySource(burnSourceName))
            using (var childSource = new ActivitySource(childSourceName))
            using (var childSamplingListener = new ActivityListener
                   {
                       ShouldListenTo = src => ReferenceEquals(src, childSource),
                       Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                   })
            using (var parentListener = PrivacyActivityEnricher.CreateSanitizingListener(
                       allowlist,
                       parentService,
                       src => ReferenceEquals(src, hierarchySource)))
            {
                ActivitySource.AddActivityListener(childSamplingListener);
                ActivitySource.AddActivityListener(parentListener);
                using var parentAct = hierarchySource.StartActivity("job.accepted");
                Assert.NotNull(parentAct);
                using var childAct = childSource.StartActivity("scan_started");
                Assert.NotNull(childAct);
                Assert.Same(parentAct, childAct!.Parent);
                childAct.Stop();

                using var childExportEntered = new ManualResetEventSlim(false);
                using var releaseChildExport = new ManualResetEventSlim(false);
                var safeChildStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    allowlist,
                    _ =>
                    {
                        childExportEntered.Set();
                        Assert.True(releaseChildExport.Wait(TimeSpan.FromSeconds(5)));
                    },
                    childExporterService);

                var childStopTask = Task.Run(() => safeChildStop(childAct));
                Assert.True(childExportEntered.Wait(TimeSpan.FromSeconds(5)));

                var burnParentTask = Task.Run(() => parentService.Burn());
                Assert.True(SpinWait.SpinUntil(() => parentService.IsBurned, TimeSpan.FromSeconds(5)));
                Assert.False(SpinWait.SpinUntil(() => burnParentTask.IsCompleted, 50));

                releaseChildExport.Set();
                await Task.WhenAll(burnParentTask, childStopTask).WaitAsync(TimeSpan.FromSeconds(5));
                Assert.True(Volatile.Read(ref parentPurges) >= 2);
            }

            // R44 #3: Service-bound exporter overload establishes persistent ownership of an external Activity.
            var exporterOwnerService = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
            using (var unownedSource = new ActivitySource(childSourceName))
            using (var unownedSamplingListener = new ActivityListener
                   {
                       ShouldListenTo = src => ReferenceEquals(src, unownedSource),
                       Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                       SampleUsingParentId = (ref ActivityCreationOptions<string> _) => ActivitySamplingResult.AllDataAndRecorded,
                   })
            {
                ActivitySource.AddActivityListener(unownedSamplingListener);
                using var retainedExternal = unownedSource.StartActivity("scan_started")!;
                Assert.NotNull(retainedExternal);
                retainedExternal.SetSanitizedTag("action", "scan_started", allowlist);
                retainedExternal.Stop();

                var ownerBoundStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    allowlist,
                    _ => { },
                    exporterOwnerService);
                ownerBoundStop(retainedExternal);
                Assert.Equal("scan_started", retainedExternal.GetTagItem("action"));

                exporterOwnerService.Burn();

                Assert.Equal(ActivityTraceFlags.None, retainedExternal.ActivityTraceFlags & ActivityTraceFlags.Recorded);
                Assert.Empty(retainedExternal.TagObjects);
                retainedExternal.SetSanitizedTag("action", "scan_started", allowlist);
                Assert.Empty(retainedExternal.TagObjects);

                var retainedHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    retainedExternal,
                    retainedHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.Empty(retainedHeaders);

                // R45 #2: Reject sensitive string parent IDs and hierarchical IDs before export.
                var unburnedExportService = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
                var rejectedParentExportCount = 0;
                var rejectedParentStop = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    allowlist,
                    _ => Interlocked.Increment(ref rejectedParentExportCount),
                    unburnedExportService);
                using var sensitiveParentAct = unownedSource.StartActivity(
                    "parse_document",
                    ActivityKind.Internal,
                    "|tenant-Alice-123-45-6789.");
                Assert.NotNull(sensitiveParentAct);
                Assert.False(PrivacyActivityEnricher.TrySanitizeActivity(sensitiveParentAct!, allowlist, out var parentRejectReason));
                Assert.NotNull(parentRejectReason);
                rejectedParentStop(sensitiveParentAct!);
                Assert.Equal(0, rejectedParentExportCount);
                sensitiveParentAct!.Stop();
                Activity.Current = null;

                // R46 #3: Burned default propagator owner must not scrub an unburned peer service's Activity after Inject.
                var servicePeerUnburned = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
                var serviceDefaultBurned = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlist);
                PrivacyActivityEnricher.InstallSanitizingPropagator(allowlist, serviceDefaultBurned);
                serviceDefaultBurned.Burn();

                using var peerListener = PrivacyActivityEnricher.CreateSanitizingListener(
                    allowlist,
                    servicePeerUnburned,
                    shouldListenTo: src => ReferenceEquals(src, unownedSource));
                ActivitySource.AddActivityListener(peerListener);
                using var peerAct = unownedSource.StartActivity("scan_started")!;
                Assert.NotNull(peerAct);
                peerAct.SetSanitizedTag("action", "scan_started", allowlist);
                var peerInjectedHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    peerAct,
                    peerInjectedHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                Assert.NotEmpty(peerInjectedHeaders);
                Assert.Equal("scan_started", peerAct.GetTagItem("action"));
                Assert.NotEqual(ActivityTraceFlags.None, peerAct.ActivityTraceFlags & ActivityTraceFlags.Recorded);

                // R47 #1: Automatic propagation uses the owning Activity's hierarchy.Allowlist rather than a later service's allowlist.
                var allowlistWithHospital = new SafeAllowlist(
                    additionalKeys: new[] { "hospital_id" },
                    additionalActivitySourceNames: new[] { childSourceName },
                    customValueDomains: new Dictionary<string, IEnumerable<string>>
                    {
                        ["hospital_id"] = new[] { "hmac:1122334455667788" },
                    });
                var serviceWithHospital = new PrivacyTelemetryService(configuration: activeConfig, allowlist: allowlistWithHospital);
                PrivacyActivityEnricher.InstallSanitizingPropagator(allowlistWithHospital, serviceWithHospital);

                peerAct.AddBaggage("hospital_id", "hmac:1122334455667788");
                peerAct.AddBaggage("job_id", "job-47");
                var ownerPolicyHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    peerAct,
                    ownerPolicyHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                var baggageVal = ownerPolicyHeaders
                    .FirstOrDefault(h => string.Equals(h.Key, "baggage", StringComparison.OrdinalIgnoreCase) ||
                                         string.Equals(h.Key, "Correlation-Context", StringComparison.OrdinalIgnoreCase))
                    .Value;
                Assert.NotNull(baggageVal);
                Assert.Contains("job_id=job-47", baggageVal!);
                Assert.DoesNotContain("hospital_id", baggageVal!, StringComparison.OrdinalIgnoreCase);

                // R51 #2: Replacement baggage header is bounded to <= 64 entries and <= 8192 encoded characters.
                for (var idx = 0; idx < 80; idx++)
                {
                    peerAct.AddBaggage("status", "OK");
                }
                var boundedHeaders = new List<(string Key, string? Value)>();
                DistributedContextPropagator.Current.Inject(
                    peerAct,
                    boundedHeaders,
                    (c, k, v) => ((List<(string, string?)>)c!).Add((k, v)));
                var boundedBaggage = boundedHeaders
                    .FirstOrDefault(h => string.Equals(h.Key, "baggage", StringComparison.OrdinalIgnoreCase) ||
                                         string.Equals(h.Key, "Correlation-Context", StringComparison.OrdinalIgnoreCase))
                    .Value;
                Assert.NotNull(boundedBaggage);
                Assert.True(boundedBaggage!.Length <= 8192);
                Assert.True(boundedBaggage.Split(", ").Length <= 64);

                // R54 #4: Throwing onBurnPurge hook throws from Burn(), but never escapes CreateExporterSafeStopCallback cleanup when Burn() occurs during export.
                peerListener.Dispose();
                Activity.Current = null;
                var throwingHookCalls = 0;
                var throwingHookService = new PrivacyTelemetryService(
                    configuration: activeConfig,
                    allowlist: allowlist);
                throwingHookService.RegisterBurnPurgeHook(() =>
                {
                    if (Interlocked.Increment(ref throwingHookCalls) >= 2)
                    {
                        throw new InvalidOperationException("Simulated purge hook failure");
                    }
                });
                using var throwingHookAct = unownedSource.StartActivity("scan_started")!;
                Assert.NotNull(throwingHookAct);
                throwingHookAct.SetSanitizedTag("action", "scan_started", allowlist);
                var postBurnStopCallback = PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                    allowlist,
                    _ =>
                    {
                        // First Burn() call runs hook #1 (succeeds and marks owner burned while lease is active);
                        // post-export finally re-runs owner purge hooks (#2, which throws) and must swallow it so Activity.Stop() never throws.
                        throwingHookService.Burn();
                    },
                    throwingHookService);
                var stopEx = Record.Exception(() => postBurnStopCallback(throwingHookAct));
                Assert.Null(stopEx);
                Assert.True(Volatile.Read(ref throwingHookCalls) >= 2);
                Assert.Empty(throwingHookAct.TagObjects);
            }
        }
        finally
        {
            DistributedContextPropagator.Current = prevPropagator;
            Activity.Current = prevParent;
        }
    }

    private sealed class HandshakeRuleIdsEnumerable : IEnumerable<string>
    {
        private readonly ManualResetEventSlim _entered;
        private readonly ManualResetEventSlim _release;

        public HandshakeRuleIdsEnumerable(ManualResetEventSlim entered, ManualResetEventSlim release)
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
