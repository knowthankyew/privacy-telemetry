import { TelemetryManager } from '../manager.js';
import { PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding, SpanRecord } from '../types.js';
export declare function usePrivacyTelemetry(telemetry: TelemetryManager, branding?: PrivacyClaimsBranding): {
    report: PrivacyAuditReport;
    claims: PrivacyClaims;
    spans: readonly SpanRecord[];
    spanCount: number;
    burn: () => void;
    refresh: () => void;
};
export declare function usePrivacyClaims(telemetry: TelemetryManager, branding?: PrivacyClaimsBranding): PrivacyClaims;
//# sourceMappingURL=usePrivacyTelemetry.d.ts.map