using KnowThankYew.Privacy.Telemetry.Abstractions;
using KnowThankYew.Privacy.Telemetry.Configuration;
using KnowThankYew.Privacy.Telemetry.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace KnowThankYew.Privacy.Telemetry.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddPrivacyTelemetry(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<SafeAllowlist>? configureAllowlist = null)
    {
        if (configuration != null)
        {
            var section = configuration.GetSection(PrivacyTelemetryOptions.SectionName);
            if (section.Exists())
            {
                services.Configure<PrivacyTelemetryOptions>(section);
            }
            else
            {
                // Fallback to separate Privacy and Telemetry sections
                services.Configure<PrivacyTelemetryOptions>(opts =>
                {
                    var privSection = configuration.GetSection("Privacy");
                    if (privSection.Exists()) privSection.Bind(opts.Privacy);

                    var telSection = configuration.GetSection("Telemetry");
                    if (telSection.Exists()) telSection.Bind(opts.Telemetry);

                    var auditSection = configuration.GetSection("Audit");
                    if (auditSection.Exists()) auditSection.Bind(opts.Audit);
                });
            }
        }

        var allowlist = new SafeAllowlist();
        configureAllowlist?.Invoke(allowlist);

        services.AddSingleton(allowlist);
        services.AddSingleton<PrivacyTelemetryService>(sp => new PrivacyTelemetryService(
            sp.GetService<Microsoft.Extensions.Options.IOptions<PrivacyTelemetryOptions>>(),
            configuration ?? sp.GetService<IConfiguration>(),
            sp.GetRequiredService<SafeAllowlist>()));
        services.AddSingleton<IPrivacyTelemetry>(sp => sp.GetRequiredService<PrivacyTelemetryService>());

        return services;
    }

    /// <summary>
    /// Explicitly installs a process-wide <see cref="System.Diagnostics.DistributedContextPropagator.Current"/>
    /// bound to the DI singleton <see cref="PrivacyTelemetryService"/> and <see cref="SafeAllowlist"/>.
    /// Call this at application startup when opting into process-global outbound trace/baggage sanitization.
    /// </summary>
    public static IServiceProvider UsePrivacySafePropagator(this IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var allowlist = services.GetRequiredService<SafeAllowlist>();
        var telemetryService = services.GetRequiredService<PrivacyTelemetryService>();
        OpenTelemetry.PrivacyActivityEnricher.InstallSanitizingPropagator(
            allowlist,
            telemetryService,
            telemetryService.AllowRawPayloads);
        return services;
    }

    /// <summary>
    /// Creates an exporter <see cref="System.Diagnostics.ActivityListener"/> bound to the DI singleton
    /// <see cref="SafeAllowlist"/> and <see cref="PrivacyTelemetryService"/> via
    /// <see cref="OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(SafeAllowlist, Action{System.Diagnostics.Activity}, PrivacyTelemetryService, bool, Action?)"/>
    /// so sanitation and burn/egress policy run before <paramref name="exporterOnStop"/> regardless of listener registration order.
    /// </summary>
    public static System.Diagnostics.ActivityListener CreateExporterSafeActivityListener(
        this IServiceProvider services,
        Action<System.Diagnostics.Activity> exporterOnStop,
        Func<System.Diagnostics.ActivitySource, bool>? shouldListenTo = null,
        Action? onBurnPurge = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(exporterOnStop);
        var allowlist = services.GetRequiredService<SafeAllowlist>();
        var telemetryService = services.GetRequiredService<PrivacyTelemetryService>();
        return new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = shouldListenTo ?? (source => source.Name.StartsWith("KnowThankYew", StringComparison.Ordinal)),
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            SampleUsingParentId = (ref System.Diagnostics.ActivityCreationOptions<string> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = OpenTelemetry.PrivacyActivityEnricher.CreateExporterSafeStopCallback(
                allowlist,
                exporterOnStop,
                telemetryService,
                telemetryService.AllowRawPayloads,
                onBurnPurge)
        };
    }
}
