using System.Collections.Concurrent;
using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Abstractions;
using KnowThankYew.Privacy.Telemetry.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace KnowThankYew.Privacy.Telemetry.Core;

public sealed class PrivacyTelemetryService : IPrivacyTelemetry
{
    public static readonly ActivitySource ActivitySource = new("KnowThankYew.Privacy.Telemetry", "1.0.0");

    private readonly ConcurrentQueue<PrivacySpanRecord> _spanBuffer = new();
    private const int MaxBufferSize = 500;

    private readonly string _mode;
    private readonly string? _otlpEndpoint;
    private readonly bool _burnEnabled;
    private readonly bool _allowRawPayloads;
    private readonly string _networkEgress;
    private readonly SafeAllowlist _allowlist;
    private volatile bool _isBurned;

    public string Mode => _mode;
    public bool IsBurnEnabled => _burnEnabled;
    public string? OtlpEndpoint => _otlpEndpoint;
    public bool IsLocalOnlyHonest => _mode != "otlp" && string.IsNullOrEmpty(_otlpEndpoint) && _networkEgress == "deny";

    public PrivacyTelemetryService(
        IOptions<PrivacyTelemetryOptions>? options = null,
        IConfiguration? configuration = null,
        SafeAllowlist? allowlist = null)
    {
        var opts = options?.Value ?? new PrivacyTelemetryOptions();

        // Check environment variable fallback
        var envEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")
                          ?? Environment.GetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT")
                          ?? configuration?["Telemetry:OtlpEndpoint"]
                          ?? configuration?["PrivacyTelemetry:Telemetry:OtlpEndpoint"]
                          ?? opts.Telemetry.OtlpEndpoint;

        _otlpEndpoint = envEndpoint;

        var configuredMode = configuration?["Telemetry:Mode"]
                             ?? configuration?["PrivacyTelemetry:Telemetry:Mode"]
                             ?? opts.Telemetry.Mode;

        _mode = !string.IsNullOrEmpty(_otlpEndpoint) ? "otlp" : configuredMode;

        if (bool.TryParse(configuration?["Privacy:BurnEnabled"] ?? configuration?["PrivacyTelemetry:Privacy:BurnEnabled"], out var burn))
        {
            _burnEnabled = burn;
        }
        else
        {
            _burnEnabled = opts.Privacy.BurnEnabled;
        }

        _allowRawPayloads = opts.Telemetry.AllowRawPayloads;
        _networkEgress = _mode == "otlp" ? "allow_otlp" : opts.Privacy.NetworkEgress;

        _allowlist = allowlist ?? new SafeAllowlist();
    }

    public void RecordSpan(
        string name,
        string? entityId = null,
        string status = "OK",
        long durationMs = 0,
        IDictionary<string, object>? attributes = null)
    {
        if (_mode == "disabled" || _isBurned) return;

        using var activity = ActivitySource.StartActivity(name);
        if (entityId != null)
        {
            activity?.SetTag("job_id", entityId);
        }
        activity?.SetTag("status", status);
        if (durationMs > 0)
        {
            activity?.SetTag("duration_ms", durationMs);
        }

        var incomingAttrs = attributes != null
            ? new Dictionary<string, object>(attributes)
            : new Dictionary<string, object>();

        if (entityId != null && !incomingAttrs.ContainsKey("job_id"))
        {
            incomingAttrs["job_id"] = entityId;
        }
        if (!incomingAttrs.ContainsKey("status"))
        {
            incomingAttrs["status"] = status;
        }

        var sanitizedAttrs = _allowlist.Sanitize(incomingAttrs, _allowRawPayloads);

        foreach (var kv in sanitizedAttrs)
        {
            activity?.SetTag(kv.Key, kv.Value);
        }

        var record = new PrivacySpanRecord
        {
            Id = activity?.Id ?? Guid.NewGuid().ToString("N"),
            Name = name,
            Timestamp = DateTimeOffset.UtcNow,
            DurationMs = durationMs,
            Status = status,
            Attributes = sanitizedAttrs
        };

        _spanBuffer.Enqueue(record);

        while (_spanBuffer.Count > MaxBufferSize && _spanBuffer.TryDequeue(out _))
        {
        }
    }

    public IReadOnlyList<PrivacySpanRecord> GetBufferedSpans() => _spanBuffer.ToArray();

    public void Burn()
    {
        if (!_burnEnabled) return;

        _spanBuffer.Clear();
        _isBurned = true;
    }

    public PrivacyAuditReport GetPrivacyAuditReport()
    {
        return new PrivacyAuditReport
        {
            TelemetryMode = _mode,
            NetworkEgress = _networkEgress,
            BurnEnabled = _burnEnabled,
            OtlpEndpoint = _otlpEndpoint,
            AllowRawPayloads = _allowRawPayloads,
            ActiveSpanCount = _spanBuffer.Count,
            IsLocalOnlyHonest = IsLocalOnlyHonest,
            Timestamp = DateTimeOffset.UtcNow
        };
    }
}
