namespace KnowThankYew.Privacy.Telemetry.Abstractions;

public interface IPrivacyTelemetry
{
    string Mode { get; }
    bool IsBurnEnabled { get; }
    string? OtlpEndpoint { get; }
    bool IsLocalOnlyHonest { get; }

    void RecordSpan(string name, string? entityId = null, string status = "OK", long durationMs = 0, IDictionary<string, object>? attributes = null);
    IReadOnlyList<PrivacySpanRecord> GetBufferedSpans();
    void Burn();
    PrivacyAuditReport GetPrivacyAuditReport();
}
