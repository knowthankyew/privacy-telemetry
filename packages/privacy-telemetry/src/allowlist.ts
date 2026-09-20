/**
 * Strict Attribute Allowlist & Fail-Closed Sanitizer
 * 
 * Invariant: To prevent short clause leaks or sensitive snippets from slipping
 * through under unanticipated key names (e.g., matchedText, snippet, excerpt, clause_text),
 * attribute sanitizers operate on a strict allowlist, not a denylist.
 */

export const DEFAULT_SAFE_ALLOWLIST_KEYS: ReadonlySet<string> = new Set([
  'rule_id',
  'rule_ids',
  'statute_code',
  'jurisdiction',
  'status',
  'risk_level',
  'duration_ms',
  'duration_sec',
  'clause_count',
  'total_clauses',
  'flagged_clauses',
  'flagged_count',
  'standard_count',
  'watch_count',
  'unenforceable_count',
  'char_count',
  'matched_violations',
  'error_code',
  'job_id',
  'service',
  'action',
  'step',
  'current_step',
  'total_steps',
  'progress_pct',
  'loss',
  'device',
  'adapter_size_bytes',
  'dataset_hash',
  'exchange',
  'routing_key',
]);

/**
 * Creates an allowlist attribute sanitizer combining default safe keys with domain-specific extensions.
 */
export function createAllowlistSanitizer(additionalKeys?: Iterable<string>): {
  allowlist: ReadonlySet<string>;
  sanitize: (
    attrs: Record<string, unknown>,
    allowRawPayloads?: boolean
  ) => Record<string, string | number | boolean>;
} {
  const allowlist = new Set<string>(DEFAULT_SAFE_ALLOWLIST_KEYS);
  if (additionalKeys) {
    for (const key of additionalKeys) {
      allowlist.add(key.toLowerCase());
    }
  }

  const sanitize = (
    attrs: Record<string, unknown>,
    allowRawPayloads = false
  ): Record<string, string | number | boolean> => {
    const sanitized: Record<string, string | number | boolean> = {};

    for (const [key, val] of Object.entries(attrs)) {
      const lowerKey = key.toLowerCase();
      const isAllowlisted = allowlist.has(lowerKey);

      if (!isAllowlisted && !allowRawPayloads) {
        sanitized[key] = '[REDACTED_BY_DEFAULT_ALLOWLIST]';
        continue;
      }

      if (typeof val === 'string') {
        // Length safety backstop: truncate long strings even on allowlisted keys
        if (val.length > 256 && !allowRawPayloads) {
          sanitized[key] = `[TRUNCATED_HASH_${val.slice(0, 8)}...]`;
        } else {
          sanitized[key] = val;
        }
      } else if (typeof val === 'number' || typeof val === 'boolean') {
        sanitized[key] = val;
      }
    }

    return sanitized;
  };

  return { allowlist, sanitize };
}
