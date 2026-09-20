using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Core;

namespace KnowThankYew.Privacy.Telemetry.OpenTelemetry;

public static class PrivacyActivityEnricher
{
    /// <summary>
    /// Creates an ActivityListener that enforces allowlist compliance on Activity tags.
    /// </summary>
    public static ActivityListener CreateSanitizingListener(SafeAllowlist allowlist, bool allowRawPayloads = false)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("KnowThankYew"),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                if (allowRawPayloads) return;

                // Inspect and redact tags
                var tagsToInspect = activity.Tags.ToList();
                foreach (var tag in tagsToInspect)
                {
                    if (tag.Key != null && !allowlist.IsAllowed(tag.Key))
                    {
                        activity.SetTag(tag.Key, "[REDACTED_NOT_IN_ALLOWLIST]");
                    }
                }
            }
        };

        return listener;
    }
}
