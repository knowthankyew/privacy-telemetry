/**
 * KnowThankYew Structured Handoff Protocol Specification
 * Types, Constants & Schema Validator
 */
export type DestinationToolId = 'bill-of-rights-bot' | 'lease-audit' | 'care-check' | 'warranty-watch' | 'paystub-check';
export type TrapCategory = 'AUTO_RENEWAL' | 'ARBITRATION' | 'UNILATERAL_CHANGE' | 'SURVEILLANCE' | 'WARRANTY_DISCLAIMER';
export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';
export interface DiscoveredLegalLink {
    url: string;
    title: string;
    category: 'TERMS' | 'PRIVACY' | 'BILLING' | 'ARBITRATION';
    source?: 'DOM_ANCHOR' | 'WELL_KNOWN';
}
export interface KtyHandoffFinding {
    ruleId: string;
    title: string;
    category: TrapCategory;
    severity: Severity;
    statuteCode: string;
    statuteTitle: string;
    matchedSnippet: string;
    explanation: string;
    recommendation: string;
}
export interface KtyHandoffPayload {
    version: '1.0';
    originApp: 'knowthankyew-extension';
    domain: string;
    scanTimestamp: string;
    riskScore: number;
    summary: {
        critical: number;
        warning: number;
        info: number;
    };
    findings: KtyHandoffFinding[];
    primaryLegalLink: DiscoveredLegalLink | null;
    targetTool: DestinationToolId;
}
export declare const KTY_HANDOFF_SESSION_KEY = "kty_handoff";
/**
 * Fail-closed runtime validator for incoming KtyHandoffPayload envelopes.
 */
export declare function validateHandoffPayload(payload: unknown): payload is KtyHandoffPayload;
//# sourceMappingURL=handoff.d.ts.map