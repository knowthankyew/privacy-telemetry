using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
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
                    else if (tag.Key != null && tag.Value is string s && s.Length > 256)
                    {
                        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(s));
                        var digest = Convert.ToHexString(hashBytes)[..8].ToLowerInvariant();
                        activity.SetTag(tag.Key, $"[TRUNCATED_HASH_{digest}]");
                    }
                }
            }
        };

        return listener;
    }
}
