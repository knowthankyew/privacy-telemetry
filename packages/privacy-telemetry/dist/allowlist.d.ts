/**
 * Strict Attribute Allowlist & Fail-Closed Sanitizer
 *
 * Invariant: To prevent short clause leaks or sensitive snippets from slipping
 * through under unanticipated key names (e.g., matchedText, snippet, excerpt, clause_text),
 * attribute sanitizers operate on a strict allowlist, not a denylist.
 */
export declare const DEFAULT_SAFE_ALLOWLIST_KEYS: ReadonlySet<string>;
/**
 * Creates an allowlist attribute sanitizer combining default safe keys with domain-specific extensions.
 */
export declare function createAllowlistSanitizer(additionalKeys?: Iterable<string>): {
    allowlist: ReadonlySet<string>;
    sanitize: (attrs: Record<string, unknown>, allowRawPayloads?: boolean) => Record<string, string | number | boolean>;
};
//# sourceMappingURL=allowlist.d.ts.map