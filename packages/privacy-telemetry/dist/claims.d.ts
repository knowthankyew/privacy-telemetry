/**
 * Dynamic Privacy Claims Single Source of Truth
 *
 * Invariant: UI privacy claims, badges, disclaimers, and footers must be derived
 * dynamically from runtime telemetry state. If an external exporter is configured,
 * claims stating "100% Local" or "Zero Network" are never displayed.
 */
import { PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding } from './types.js';
export declare function getPrivacyClaims(report: PrivacyAuditReport, branding?: PrivacyClaimsBranding): PrivacyClaims;
//# sourceMappingURL=claims.d.ts.map