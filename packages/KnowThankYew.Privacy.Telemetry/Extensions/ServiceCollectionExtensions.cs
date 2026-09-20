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
        services.AddSingleton<IPrivacyTelemetry, PrivacyTelemetryService>();

        return services;
    }
}
