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
  'adapter_path',
  'adapter_size_bytes',
  'base_model',
  'dataset_hash',
  'dataset_relative_path',
  'exchange',
  'routing_key',
]);

/**
 * Computes an 8-character lowercase hexadecimal SHA-256 digest marker for oversized attributes.
 * Does not expose any source text.
 */
export function formatTruncatedDigest(value: string): string {
  function rightRotate(val: number, amount: number): number {
    return (val >>> amount) | (val << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let i: number, j: number;
  let result = '';
  const words: number[] = [];
  const asciiBitLength = value.length * 8;
  let hash: number[] = [];
  const k: number[] = [];
  let primeCounter = 0;
  const isComposite: Record<number, boolean> = {};

  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) isComposite[i] = true;
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  let ascii = value + '\x80';
  while ((ascii.length % 64) - 56) ascii += '\x00';
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;

  for (j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);
    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15],
        w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      const s1_ch =
        rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const temp1 = (hash[7] + s1_ch + ch + k[i] + w[i]) | 0;
      const s0_maj =
        rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp2 = (s0_maj + maj) | 0;
      hash = [
        (temp1 + temp2) | 0,
        hash[0],
        hash[1],
        hash[2],
        (hash[3] + temp1) | 0,
        hash[4],
        hash[5],
        hash[6],
      ];
    }
    for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      const b = (hash[i] >> (8 * j)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }

  return `[TRUNCATED_HASH_${result.slice(0, 8)}]`;
}

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
          sanitized[key] = formatTruncatedDigest(val);
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
