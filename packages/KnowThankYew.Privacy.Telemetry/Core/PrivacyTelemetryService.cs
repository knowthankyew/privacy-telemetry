using System.Collections.Concurrent;
using System.Diagnostics;
using KnowThankYew.Privacy.Telemetry.Abstractions;
using KnowThankYew.Privacy.Telemetry.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace KnowThankYew.Privacy.Telemetry.Core;

public sealed class PrivacyTelemetryService : IPrivacyTelemetry
{
    public const string ActivitySourceName = "KnowThankYew.Privacy.Telemetry";
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, "1.0.0");

    private readonly ConcurrentQueue<PrivacySpanRecord> _spanBuffer = new();
    private const int MaxBufferSize = 500;

    private readonly string _mode;
    private readonly string? _otlpEndpoint;
    private readonly bool _burnEnabled;
    private readonly bool _allowRawPayloads;
    private readonly string _networkEgress;
    private readonly SafeAllowlist _allowlist;
    private readonly object _burnSync = new();
    private readonly List<Action> _burnPurgeHooks = new();
    private readonly List<Task> _activePurgeTasks = new();
    private static readonly Action<object> InvokeBurnPurgeHooksCallback =
        static owner => ((PrivacyTelemetryService)owner).RunPurgeHooksCore(waitForConcurrentPurges: true);
    private volatile bool _isBurned;

    public string Mode => _mode;
    public bool IsBurnEnabled => _burnEnabled;
    public bool IsBurned => _isBurned;
    public string? OtlpEndpoint => _otlpEndpoint;
    public bool IsLocalOnlyHonest => _mode != "otlp" && string.IsNullOrEmpty(_otlpEndpoint) && _networkEgress == "deny";

    public PrivacyTelemetryService(
        IOptions<PrivacyTelemetryOptions>? options = null,
        IConfiguration? configuration = null,
        SafeAllowlist? allowlist = null)
    {
        var opts = options?.Value ?? new PrivacyTelemetryOptions();

        static string? NullIfWhiteSpace(string? value) =>
            string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        // Check environment variable fallback
        var envEndpoint = NullIfWhiteSpace(Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT"))
                          ?? NullIfWhiteSpace(Environment.GetEnvironmentVariable("KTY_TELEMETRY_OTLP_ENDPOINT"));
        var rawEndpoint = envEndpoint
                          ?? NullIfWhiteSpace(configuration?["Telemetry:OtlpEndpoint"])
                          ?? NullIfWhiteSpace(configuration?["PrivacyTelemetry:Telemetry:OtlpEndpoint"])
                          ?? NullIfWhiteSpace(opts.Telemetry.OtlpEndpoint);

        var envMode = NullIfWhiteSpace(Environment.GetEnvironmentVariable("KTY_TELEMETRY_MODE"));
        var configMode = NullIfWhiteSpace(configuration?["Telemetry:Mode"])
                         ?? NullIfWhiteSpace(configuration?["PrivacyTelemetry:Telemetry:Mode"]);
        var configuredMode = envMode ?? configMode ?? NullIfWhiteSpace(opts.Telemetry.Mode) ?? "memory_only";

        _mode = configuredMode.ToLowerInvariant() switch
        {
            "disabled" => "disabled",
            "otlp" => "otlp",
            _ => "memory_only",
        };

        // Retain _otlpEndpoint only when _mode is explicitly "otlp": portfolio .NET services register zero
        // external OpenTelemetry SDK exporters (AddOtlpExporter/UseOtlpExporter are unused), and both RecordSpan
        // (via AllowsExternalActivityPublication) and CreateExporterSafeActivityListener/CreateExporterSafeStopCallback
        // block all external Activity publication unless _mode == "otlp" with an allowed egress policy.
        // Clearing _otlpEndpoint when _mode != "otlp" ensures inactive ambient endpoints in memory_only/disabled
        // modes are not falsely reported as active OTLP egress in GetPrivacyAuditReport() or IsLocalOnlyHonest.
        _otlpEndpoint = string.Equals(_mode, "otlp", StringComparison.OrdinalIgnoreCase)
            ? rawEndpoint
            : null;

        if (bool.TryParse(configuration?["Privacy:BurnEnabled"] ?? configuration?["PrivacyTelemetry:Privacy:BurnEnabled"], out var burn))
        {
            _burnEnabled = burn;
        }
        else
        {
            _burnEnabled = opts.Privacy.BurnEnabled;
        }

        _allowRawPayloads = opts.Telemetry.AllowRawPayloads;
        var rawEnvEgress = Environment.GetEnvironmentVariable("KTY_PRIVACY_NETWORK_EGRESS");
        var configEgress = configuration?["Privacy:NetworkEgress"]
                           ?? configuration?["PrivacyTelemetry:Privacy:NetworkEgress"];
        var configuredEgress = rawEnvEgress ?? configEgress;
        // Per PRIVACY_TELEMETRY_SCHEMA.md Section 2, consumer default is "deny"; when _mode is explicitly "otlp"
        // with a non-empty _otlpEndpoint and no explicit egress override is configured, default to "allow_otlp".
        _networkEgress = configuredEgress is not null
            ? (string.IsNullOrWhiteSpace(configuredEgress) ? "deny" : configuredEgress.Trim())
            : opts.Privacy.HasExplicitNetworkEgress
                ? opts.Privacy.NetworkEgress
                : (string.Equals(_mode, "otlp", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(_otlpEndpoint)
                    ? "allow_otlp"
                    : opts.Privacy.NetworkEgress);

        _allowlist = allowlist ?? new SafeAllowlist();
    }

    internal bool AllowsExternalActivityPublication =>
        string.Equals(_mode, "otlp", StringComparison.OrdinalIgnoreCase) &&
        !string.IsNullOrWhiteSpace(_otlpEndpoint) &&
        (string.Equals(_networkEgress, "allow_otlp", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(_networkEgress, "allow_all", StringComparison.OrdinalIgnoreCase));

    internal SafeAllowlist Allowlist => _allowlist;

    internal bool AllowRawPayloads => _allowRawPayloads;

    public void RecordSpan(
        string name,
        string? entityId = null,
        string status = "OK",
        long durationMs = 0,
        IDictionary<string, object>? attributes = null)
    {
        if (_mode == "disabled" || _isBurned) return;

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
        // Attach only pre-sanitized tags at Activity creation so ActivityStarted/ActivityStopped listeners
        // never observe raw values even if an exporter listener was registered before CreateSanitizingListener.
        var initialTags = new Dictionary<string, object?>(
            sanitizedAttrs.Count + (durationMs > 0 ? 1 : 0),
            StringComparer.OrdinalIgnoreCase);
        foreach (var kv in sanitizedAttrs)
        {
            if ((_allowRawPayloads || _allowlist.IsAllowed(kv.Key)) &&
                (_allowRawPayloads || !SafeAllowlist.IsCollectorBoundaryExcludedKey(kv.Key)))
            {
                initialTags[kv.Key] = kv.Value is string[] arr ? (string[])arr.Clone() : kv.Value;
            }
        }
        if (durationMs > 0)
        {
            initialTags["duration_ms"] = durationMs;
        }

        var safeName = SafeAllowlist.SanitizeSpanName(name, _allowRawPayloads);
        var safeStatus = _allowlist.SanitizeValue("status", status, _allowRawPayloads) as string
            ?? SafeAllowlist.RedactedSensitiveValue;

        if (_isBurned) return;

        // Invoke ActivitySource listeners and disposal outside _burnSync so listener callbacks that call
        // or wait on Burn() cannot deadlock against the buffer tombstone lock.
        Activity? activity = null;
        IDisposable? publicationScope = null;
        var publishActivity = false;
        var ambientCurrent = Activity.Current;
        var isolatedAmbient = false;
        try
        {
            // Create the Activity only when enterprise OTLP egress is explicitly enabled so consumer default
            // memory_only / deny mode retains spans strictly in volatile buffers with zero external delivery.
            if (AllowsExternalActivityPublication)
            {
                // Acquire the owner publication lease before CreateActivity so synchronous ActivityListener.Sample
                // callbacks participate in burn drain/purge coordination while keeping sampling outside _burnSync.
                if (!OpenTelemetry.PrivacyActivityEnricher.TryBeginActivityPublication(null, this, () => _isBurned, out publicationScope))
                {
                    return;
                }

                var sanitizedParentContext = ambientCurrent != null
                    ? new ActivityContext(
                        ambientCurrent.Context.TraceId,
                        ambientCurrent.Context.SpanId,
                        ambientCurrent.Context.TraceFlags,
                        traceState: null,
                        isRemote: ambientCurrent.Context.IsRemote)
                    : default(ActivityContext);
                isolatedAmbient = true;
                Activity.Current = null;
                activity = ActivitySource.CreateActivity(
                    safeName,
                    ActivityKind.Internal,
                    sanitizedParentContext,
                    initialTags);
                if (activity != null)
                {
                    OpenTelemetry.PrivacyActivityEnricher.AttachBurnCheck(activity, () => _isBurned, this);
                    if (_isBurned ||
                        !OpenTelemetry.PrivacyActivityEnricher.TrySanitizeActivity(activity, _allowlist, out _, _allowRawPayloads))
                    {
                        OpenTelemetry.PrivacyActivityEnricher.MarkBurnedAndScrub(activity);
                        if (_isBurned) return;
                    }
                    else
                    {
                        activity.Start();
                        publishActivity = true;
                    }
                }
            }

            var discardedForBurn = false;
            lock (_burnSync)
            {
                if (_isBurned)
                {
                    discardedForBurn = true;
                }
                else
                {
                    var record = new PrivacySpanRecord
                    {
                        Id = (publishActivity ? activity?.Id : null) ?? Guid.NewGuid().ToString("N"),
                        Name = safeName,
                        Timestamp = DateTimeOffset.UtcNow,
                        DurationMs = durationMs,
                        Status = safeStatus,
                        Attributes = sanitizedAttrs
                    };

                    _spanBuffer.Enqueue(record);

                    while (_spanBuffer.Count > MaxBufferSize && _spanBuffer.TryDequeue(out _))
                    {
                    }
                }
            }

            if ((discardedForBurn || _isBurned) && activity != null)
            {
                OpenTelemetry.PrivacyActivityEnricher.MarkBurnedAndScrub(activity);
            }
        }
        finally
        {
            if (activity != null)
            {
                // Re-sanitize immediately before Dispose()/Stop() so any listener registered before
                // CreateSanitizingListener (including an ActivityStarted callback mutating tags) never
                // observes unsanitized attributes during ActivityStopped.
                if (_isBurned ||
                    !OpenTelemetry.PrivacyActivityEnricher.TrySanitizeActivity(activity, _allowlist, out _, _allowRawPayloads))
                {
                    OpenTelemetry.PrivacyActivityEnricher.MarkBurnedAndScrub(activity);
                }
            }
            try
            {
                try
                {
                    activity?.Dispose();
                }
                finally
                {
                    if (isolatedAmbient)
                    {
                        Activity.Current = ambientCurrent;
                    }
                }
            }
            finally
            {
                OpenTelemetry.PrivacyActivityEnricher.EndActivityPublication(publicationScope);
                if (publicationScope is not null && _isBurned)
                {
                    try
                    {
                        RunPurgeHooksCore(waitForConcurrentPurges: true);
                    }
                    catch
                    {
                        // Do not allow post-burn purge hook failures to escape RecordSpan cleanup;
                        // explicit Burn() invocations surface hook exceptions to the burn caller.
                    }
                }
            }
        }
    }

    public IReadOnlyList<PrivacySpanRecord> GetBufferedSpans() => _spanBuffer.ToArray();

    public void RegisterBurnPurgeHook(Action purgeHook)
    {
        ArgumentNullException.ThrowIfNull(purgeHook);

        OpenTelemetry.PrivacyActivityEnricher.RegisterOwnerPurgeAction(this, InvokeBurnPurgeHooksCallback);

        var invokeImmediately = false;
        lock (_burnSync)
        {
            if (!_burnPurgeHooks.Contains(purgeHook))
            {
                _burnPurgeHooks.Add(purgeHook);
            }
            if (_isBurned)
            {
                invokeImmediately = true;
            }
        }

        if (invokeImmediately)
        {
            purgeHook();
        }
    }

    public void Burn()
    {
        if (!_burnEnabled) return;

        OpenTelemetry.PrivacyActivityEnricher.BurnServiceAndWait(this, _burnSync, () =>
        {
            _isBurned = true;
            _spanBuffer.Clear();
        });

        RunPurgeHooksCore(waitForConcurrentPurges: true);
    }

    private void RunPurgeHooksCore(bool waitForConcurrentPurges)
    {
        List<Action> hooks;
        List<Task>? priorPurges = null;
        List<object>? waitHolders = null;
        var myPurgeTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ancestorPurges = OpenTelemetry.PrivacyActivityEnricher.CurrentPurgeScope;
        if (ancestorPurges is not null && ancestorPurges.ContainsOwner(this))
        {
            return;
        }

        lock (_burnSync)
        {
            if (waitForConcurrentPurges && _activePurgeTasks.Count > 0)
            {
                waitHolders = OpenTelemetry.PrivacyActivityEnricher.CaptureCurrentWaitHolders(myPurgeTcs.Task);
                priorPurges = OpenTelemetry.PrivacyActivityEnricher.SelectNonCyclicPriorPurges(
                    _activePurgeTasks,
                    ancestorPurges,
                    waitHolders);
            }

            if (_burnPurgeHooks.Count == 0 && priorPurges is null)
            {
                return;
            }

            hooks = new List<Action>(_burnPurgeHooks);
            _activePurgeTasks.Add(myPurgeTcs.Task);
        }

        List<Exception>? hookErrors = null;
        try
        {
            OpenTelemetry.PrivacyActivityEnricher.CurrentPurgeScope =
                new OpenTelemetry.PrivacyActivityEnricher.PurgeWaitNode(myPurgeTcs.Task, this, ancestorPurges);
            try
            {
                foreach (var hook in hooks)
                {
                    try
                    {
                        hook();
                    }
                    catch (Exception ex)
                    {
                        hookErrors ??= new List<Exception>();
                        hookErrors.Add(ex);
                    }
                }
            }
            finally
            {
                OpenTelemetry.PrivacyActivityEnricher.CurrentPurgeScope = ancestorPurges;
                lock (_burnSync)
                {
                    _activePurgeTasks.Remove(myPurgeTcs.Task);
                }
                myPurgeTcs.TrySetResult();
            }

            if (priorPurges is not null)
            {
                Task.WhenAll(priorPurges).GetAwaiter().GetResult();
            }
        }
        finally
        {
            OpenTelemetry.PrivacyActivityEnricher.EndWaitMany(waitHolders, priorPurges);
        }

        if (hookErrors is { Count: 1 })
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(hookErrors[0]).Throw();
        }
        if (hookErrors is { Count: > 1 })
        {
            throw new AggregateException("One or more burn purge hooks failed during telemetry burn.", hookErrors);
        }
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
