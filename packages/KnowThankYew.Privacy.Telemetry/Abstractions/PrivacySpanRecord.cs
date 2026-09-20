namespace KnowThankYew.Privacy.Telemetry.Abstractions;

public sealed class PrivacySpanRecord
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public long DurationMs { get; set; }
    public required string Status { get; set; }
    public Dictionary<string, object> Attributes { get; init; } = new();
}
