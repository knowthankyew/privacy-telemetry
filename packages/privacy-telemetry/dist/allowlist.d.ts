/**
 * Strict Attribute Allowlist & Fail-Closed Sanitizer
 *
 * Invariant: To prevent short clause leaks or sensitive snippets from slipping
 * through under unanticipated key names (e.g., matchedText, snippet, excerpt, clause_text),
 * attribute sanitizers operate on a strict allowlist, not a denylist.
 */
export declare const DEFAULT_SAFE_ALLOWLIST_KEYS: ReadonlySet<string>;
export declare const REDACTED_NOT_ALLOWLISTED = "[REDACTED_BY_DEFAULT_ALLOWLIST]";
export declare const REDACTED_SENSITIVE_VALUE = "[REDACTED_SENSITIVE_VALUE]";
export declare const REDACTED_UNALLOWLISTED_KEY = "[REDACTED_KEY]";
export declare const COLLECTOR_BOUNDARY_EXCLUDED_KEYS: ReadonlySet<string>;
export declare function isCollectorBoundaryExcludedKey(key: string): boolean;
export declare function isProhibitedCustomDomainKey(key: string): boolean;
export type CustomValueDomains = Readonly<Record<string, Iterable<string>>> | ReadonlyMap<string, Iterable<string>>;
export declare function normalizeCustomValueDomains(customValueDomains?: CustomValueDomains): ReadonlyMap<string, ReadonlySet<string>> | undefined;
/**
 * Checks whether an allowlisted string value contains control chars, PII, secrets, or local user paths.
 */
export declare function containsSensitivePattern(value: string, options?: {
    skipSsn?: boolean;
}): boolean;
export declare function isSafeEventName(name: string): boolean;
/**
 * Validates span and event names at the export boundary so arbitrary free text or PII
 * cannot leak via span names when raw payloads are disabled.
 */
export declare function sanitizeSpanName(name: string, allowRawPayloads?: boolean): string;
/**
 * Validates and sanitizes string values even when their attribute key is allowlisted.
 */
export declare function sanitizeAllowlistedStringValue(key: string, value: string): string;
/**
 * Computes an 8-character lowercase hexadecimal SHA-256 digest marker for oversized attributes.
 * Does not expose any source text.
 */
export declare function formatTruncatedDigest(value: string): string;
/**
 * Creates an allowlist attribute sanitizer combining default safe keys with domain-specific extensions.
 */
export declare function createAllowlistSanitizer(additionalKeys?: Iterable<string>, customValueDomains?: CustomValueDomains): {
    allowlist: ReadonlySet<string>;
    sanitize: (attrs: Record<string, unknown>, allowRawPayloads?: boolean) => Record<string, string | number | boolean>;
};
//# sourceMappingURL=allowlist.d.ts.map