using KnowThankYew.Privacy.Telemetry.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace KnowThankYew.Privacy.Telemetry.Extensions;

public static class EndpointRouteBuilderExtensions
{
    public static RouteGroupBuilder MapPrivacyTelemetryEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/api/v1/telemetry")
    {
        var group = endpoints.MapGroup(prefix);

        group.MapGet("/privacy-audit", (IPrivacyTelemetry telemetry) =>
        {
            return Results.Ok(telemetry.GetPrivacyAuditReport());
        });

        group.MapGet("/spans", (IPrivacyTelemetry telemetry) =>
        {
            var buffered = telemetry.GetBufferedSpans();
            return Results.Ok(new
            {
                mode = telemetry.Mode,
                count = buffered.Count,
                spans = buffered
            });
        });

        group.MapPost("/burn", (IPrivacyTelemetry telemetry) =>
        {
            telemetry.Burn();
            return Results.Ok(new
            {
                message = "Telemetry buffer successfully wiped from memory.",
                remainingSpans = telemetry.GetBufferedSpans().Count
            });
        });

        return group;
    }
}
