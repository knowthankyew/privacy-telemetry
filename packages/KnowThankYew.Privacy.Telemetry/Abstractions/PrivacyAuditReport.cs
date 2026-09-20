namespace KnowThankYew.Privacy.Telemetry.Abstractions;

public sealed class PrivacyAuditReport
{
    public required string TelemetryMode { get; init; }
    public required string NetworkEgress { get; init; }
    public required bool BurnEnabled { get; init; }
    public string? OtlpEndpoint { get; init; }
    public bool AllowRawPayloads { get; init; }
    public int ActiveSpanCount { get; init; }
    public bool IsLocalOnlyHonest { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}
