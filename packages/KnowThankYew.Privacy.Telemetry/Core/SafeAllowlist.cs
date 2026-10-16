using System.Security.Cryptography;
using System.Text;

namespace KnowThankYew.Privacy.Telemetry.Core;

public sealed class SafeAllowlist
{
    private readonly HashSet<string> _allowedKeys;

    public static readonly IReadOnlyCollection<string> DefaultKeys = new[]
    {
        "job_id", "status", "duration_ms", "duration_sec", "base_model", "dataset_hash",
        "dataset_relative_path", "current_step", "total_steps", "progress_pct", "loss",
        "device", "adapter_path", "adapter_size_bytes", "exchange", "routing_key",
        "rule_id", "rule_ids", "statute_code", "jurisdiction", "risk_level",
        "clause_count", "total_clauses", "flagged_clauses", "flagged_count",
        "standard_count", "watch_count", "unenforceable_count", "char_count",
        "matched_violations", "error_code", "service", "action", "step"
    };

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
    {
        _allowedKeys = new HashSet<string>(DefaultKeys, StringComparer.OrdinalIgnoreCase);
        if (additionalKeys != null)
        {
            foreach (var key in additionalKeys)
            {
                _allowedKeys.Add(key);
            }
        }
    }

    public bool IsAllowed(string key) => _allowedKeys.Contains(key);

    public void RegisterKeys(IEnumerable<string> keys)
    {
        foreach (var key in keys)
        {
            _allowedKeys.Add(key);
        }
    }

    public Dictionary<string, object> Sanitize(
        IDictionary<string, object> attributes,
        bool allowRawPayloads = false)
    {
        var sanitized = new Dictionary<string, object>();

        foreach (var kv in attributes)
        {
            if (!_allowedKeys.Contains(kv.Key) && !allowRawPayloads)
            {
                sanitized[kv.Key] = "[REDACTED_NOT_IN_ALLOWLIST]";
                continue;
            }

            if (kv.Value is string s && s.Length > 256 && !allowRawPayloads)
            {
                sanitized[kv.Key] = FormatTruncatedDigest(s);
            }
            else
            {
                sanitized[kv.Key] = kv.Value;
            }
        }

        return sanitized;
    }
}
