namespace KnowThankYew.Privacy.Telemetry.Configuration;

/// <summary>
/// Configuration options mapping to PRIVACY_TELEMETRY_SCHEMA.md.
/// </summary>
public sealed class PrivacyTelemetryOptions
{
    public const string SectionName = "PrivacyTelemetry";

    public PrivacyOptions Privacy { get; set; } = new();
    public TelemetryOptions Telemetry { get; set; } = new();
    public AuditOptions Audit { get; set; } = new();
}

public sealed class PrivacyOptions
{
    public bool BurnEnabled { get; set; } = true;
    public string NetworkEgress { get; set; } = "deny";
}

public sealed class TelemetryOptions
{
    public string Mode { get; set; } = "memory_only"; // "disabled" | "memory_only" | "otlp"
    public string? OtlpEndpoint { get; set; }
    public bool AllowRawPayloads { get; set; } = false;
}

public sealed class AuditOptions
{
    public bool Durable { get; set; } = false;
}
