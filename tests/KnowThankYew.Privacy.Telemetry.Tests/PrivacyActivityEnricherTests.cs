using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Core;
using KnowThankYew.Privacy.Telemetry.OpenTelemetry;
using Xunit;

namespace KnowThankYew.Privacy.Telemetry.Tests;

public sealed class PrivacyActivityEnricherTests
{
    [Fact]
    public void CreateSanitizingListener_SanitizesAndTruncatesTagsWithoutExposingSourceText()
    {
        var allowlist = new SafeAllowlist();
        using var listener = PrivacyActivityEnricher.CreateSanitizingListener(allowlist);
        ActivitySource.AddActivityListener(listener);

        using var source = new ActivitySource("KnowThankYew.EnricherTest");
        using var activity = source.StartActivity("test-activity");
        Assert.NotNull(activity);

        activity.SetTag("unauthorized_key", "secret-value");
        activity.SetTag("rule_id", new string('Z', 300));
        activity.Stop();

        Assert.Equal("[REDACTED_NOT_IN_ALLOWLIST]", activity.GetTagItem("unauthorized_key"));
        var truncatedTag = activity.GetTagItem("rule_id") as string;
        Assert.NotNull(truncatedTag);
        Assert.StartsWith("[TRUNCATED_HASH_", truncatedTag);
        Assert.DoesNotContain("ZZZZ", truncatedTag);
    }
}
