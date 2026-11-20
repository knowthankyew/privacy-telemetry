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
export declare const KTY_HANDOFF_HASH_PARAM = "kty_handoff";
/**
 * Encodes a validated KTY handoff payload into a URL-safe base64url token
 * for zero-egress URL fragment delivery (#kty_handoff=...).
 */
export declare function encodeHandoffFragmentValue(payload: KtyHandoffPayload): string | null;
/**
 * Decodes and validates a base64url-encoded KTY handoff fragment token.
 * Fails closed on malformed encoding, JSON syntax errors, or schema violations.
 */
export declare function decodeHandoffFragmentValue(encoded: string): KtyHandoffPayload | null;
/**
 * Extracts and validates a KTY handoff payload from a URL hash string (e.g. #kty_handoff=...).
 */
export declare function extractHandoffFromHash(hash: string, expectedTargetTool?: string): {
    payload: KtyHandoffPayload | null;
    hasHandoffParam: boolean;
    remainingHash: string;
};
/**
 * Fail-closed runtime validator for incoming KtyHandoffPayload envelopes.
 */
export declare function validateHandoffPayload(payload: unknown): payload is KtyHandoffPayload;
//# sourceMappingURL=handoff.d.ts.map