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
  'base_model',
  'dataset_hash',
  'exchange',
  'routing_key',
]);

import { sha256Hex } from './sha256.js';

export const REDACTED_NOT_ALLOWLISTED = '[REDACTED_BY_DEFAULT_ALLOWLIST]';
export const REDACTED_SENSITIVE_VALUE = '[REDACTED_SENSITIVE_VALUE]';

const MAX_STRING_LENGTH = 256;
const MAX_PATTERN_CHECK_LENGTH = 4096;
const MAX_RULE_IDS = 50;
// Up to 50 items, max 71 chars each (full sha256:<64hex>), separated by commas.
const MAX_RULE_IDS_CSV_LENGTH = MAX_RULE_IDS * 72;

const CONTROL_OR_MULTILINE_REGEX = /[\r\n\x00-\x1f\x7f]/;
const EMAIL_REGEX = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,24}/;
const SSN_REGEX = /(?:^|\D)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)/;
const DELIMITED_CARD_REGEX =
  /(?:^|\D)(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{1,4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})(?!\d)/;
const CONTIGUOUS_CARD_IIN_REGEX =
  /(?:^|\D)(4\d{12}(?:\d{3})?(?:\d{3})?|(?:5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))\d{12}|3[47]\d{13}|(?:6011|65\d{2}|64[4-9]\d)\d{12}(?:\d{3})?)(?!\d)/g;
const SECRET_TOKEN_REGEX =
  /\bBearer\s+[A-Za-z0-9\-._~+/]{1,200}={0,4}|(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,128}|ghp_[A-Za-z0-9]{20,128}|eyJ[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128})\b/i;
const LOCAL_PATH_REGEX =
  /(?:^|[\s"'(=]|file:(?:\/\/(?:localhost)?)?)(?:\/(?:Users|home|tmp|var|private)\/[^\s"')]{1,200}|\/?[A-Za-z]:[\\/]Users[\\/][^\s"')]{1,200})/i;

const JOB_ID_REGEX =
  /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|(?:job|test-job|run|task|j)[-_](?:[0-9]{1,8}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))$/;
const OPAQUE_JOB_IDENTIFIER_REGEX =
  /^(?:(?:job|test-job|run|task|j)[-_])?(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/;
const OPAQUE_DIGEST_REGEX = /^(?:hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/;
const KEYED_HMAC_DIGEST_REGEX = /^hmac:[a-f0-9]{16,64}$/;
const SERVICE_INSTANCE_ID_REGEX =
  /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{12,64}|(?:hmac|sha256):[a-f0-9]{16,64})$/;
export const REDACTED_UNALLOWLISTED_KEY = '[REDACTED_KEY]';

const US_STATE_CODES = [
  'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'DC', 'FL',
  'GA', 'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME',
  'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH',
  'NJ', 'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI',
  'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY',
] as const;

const REGISTERED_RULE_IDS: ReadonlySet<string> = new Set([
  // Extension policy pack IDs
  'AR-001', 'AR-002', 'AR-003',
  'ARB-001', 'ARB-002', 'ARB-003',
  'UNI-001', 'UNI-002',
  'SURV-001', 'SURV-002',
  'US-CO-001', 'US-IL-001', 'US-OR-001',
  'EU-AR-001', 'EU-AR-002', 'EU-SURV-001',
  'UK-AR-001', 'UK-AR-002', 'UK-CONS-001',
  // Lease-audit statute pack IDs
  'CA-SEC-DEP-CAP-01', 'CA-SEC-DEP-RET-02', 'CA-ENTRY-NOT-03', 'CA-EVICT-SLF-04', 'CA-HABIT-REP-05', 'CA-LATE-FEE-06',
  'FL-SEC-DEP-RET-01', 'FL-ENTRY-NOT-02', 'FL-PROHIB-PRAC-03', 'FL-HABIT-REP-04',
  'IL-SEC-DEP-RET-01', 'IL-EVICT-SLF-02', 'IL-RETALIAT-03', 'IL-DEP-INT-04',
  'NY-SEC-DEP-CAP-01', 'NY-SEC-DEP-RET-02', 'NY-ENTRY-NOT-06', 'NY-LATE-FEE-03', 'NY-EVICT-SLF-04', 'NY-HABIT-WAR-05', 'NY-OCCUP-ROOM-07',
  'TX-SEC-DEP-RET-01', 'TX-LATE-FEE-02', 'TX-LOCKOUT-SLF-03', 'TX-UTIL-SHUT-04', 'TX-HABIT-REP-05',
  'FED-FHA-FAM-01', 'FED-FHA-DIS-02', 'FED-SCRA-MIL-03', 'FED-LEAD-DISC-04',
  // Paystub-check rule IDs
  'illegal_register_shortage_deduction',
  'illegal_uniform_equipment_deduction',
  'salaried_under_exemption_threshold',
  'missing_overtime_multiplier',
  'unexplained_mandatory_fee',
  'salaried_under_threshold',
  'fica_math_mismatch',
  // Warranty-watch rule & handoff IDs
  'KTY-WARRANTY-EXCL-001',
  'KTY-WARRANTY-DISCLAIM-001',
  'WARRANTY_VOID_IF_REMOVED',
  // Canonical statutory identifiers verified across compliance test suites
  'CA_CIV_1950_5',
  'FLSA_EXEMPT_541',
  'implied_warranty_disclaimer',
  ...US_STATE_CODES.map((abbr) => `state_daily_overtime_${abbr}`),
  ...US_STATE_CODES.map((abbr) => `state_implied_override_${abbr}`),
]);

const REGISTERED_BASE_MODELS: ReadonlySet<string> = new Set([
  'HuggingFaceTB/SmolLM2-135M',
  'google/gemma-2-2b-it',
  'microsoft/BitNet-b1.58-2B-4T',
]);

function isSafeRuleId(value: string): boolean {
  return REGISTERED_RULE_IDS.has(value) || OPAQUE_DIGEST_REGEX.test(value);
}

function isSafeBaseModel(value: string): boolean {
  return REGISTERED_BASE_MODELS.has(value) || OPAQUE_DIGEST_REGEX.test(value);
}
const HTTP_ERROR_CODE_REGEX = /^(?:HTTP_)?[45]\d{2}$/;
const REGISTERED_ERROR_CODES: ReadonlySet<string> = new Set([
  'edge_inference_notice',
  'unknown_error',
  'internal_error',
  'validation_error',
  'invalid_request',
  'invalid_payload',
  'invalid_argument',
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'rate_limited',
  'timeout',
  'gateway_timeout',
  'service_unavailable',
  'network_error',
  'network_denied',
  'parse_error',
  'parse_failed',
  'ocr_failed',
  'pdf_extract_failed',
  'model_load_failed',
  'inference_failed',
  'inference_timeout',
  'burn_activated',
  'telemetry_disabled',
  'handoff_rejected',
  'handoff_expired',
  'handoff_invalid',
  'worker_failed',
  'queue_timeout',
  'broker_unavailable',
  'storage_unavailable',
  'ERR_TIMEOUT',
  'ERR_NETWORK',
  'ERR_VALIDATION',
  'ERR_PARSE',
  'ERR_OCR',
  'ERR_PDF',
  'ERR_INFERENCE',
  'ERR_UNAUTHORIZED',
  'ERR_FORBIDDEN',
  'ERR_NOT_FOUND',
  'ERR_RATE_LIMITED',
  'ERR_INTERNAL',
  'ERR_UNAVAILABLE',
  'ERR_CONFLICT',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENOTFOUND',
  'ECONNRESET',
  'EPIPE',
  'ENOENT',
  'TimeoutException',
  'TimeoutError',
  'ValidationException',
  'ValidationError',
  'ArgumentException',
  'ArgumentNullException',
  'InvalidOperationException',
  'HttpRequestException',
  'OperationCanceledException',
  'TaskCanceledException',
  'IOException',
  'JsonException',
  'FormatException',
  'KeyNotFoundException',
  'UnauthorizedAccessException',
  'TypeError',
  'ValueError',
  'RuntimeError',
  'KeyError',
  'OSError',
  'NetworkError',
  'AbortError',
  'SyntaxError',
]);

function isSafeErrorCode(value: string): boolean {
  return (
    REGISTERED_ERROR_CODES.has(value) ||
    HTTP_ERROR_CODE_REGEX.test(value) ||
    OPAQUE_DIGEST_REGEX.test(value)
  );
}
const APP_VERSION_REGEX =
  /^v?\d{1,4}\.\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:-(?:alpha|beta|rc|preview|nightly|dev|canary)(?:\.\d{1,4})?)?(?:\+(?:[0-9a-f]{7,40}|\d{1,12}))?$/;
const HOSPITAL_ID_REGEX =
  /^(?:cleveland-clinic-main|mayo-clinic-rochester|ascension-health-national|kaiser-foundation-hospitals|HOSP-\d{1,6}|(?:hosp_|hmac:)[a-f0-9]{16,64})$/;
const CPT_CODE_REGEX = /^(?:\d{4}[A-Z0-9]|hmac:[a-f0-9]{16})$/;
const PROHIBITED_CUSTOM_DOMAIN_KEY_REGEX =
  /(?:^|[._-])(?:tenant|ssn|social_security|email|phone|telephone|mobile|address|street|dob|birth|patient|diagnosis|prognosis|symptom|condition|disease|disorder|hiv|aids|pregnant|pregnancy|cancer|diabetes|medical|clinical|medication|prescription|treatment|mrn|phi|claimant|employee|employer|landlord|wage|salary|income|pay_rate|hourly_rate|annual_salary|gross_pay|net_pay|pay_amount|excerpt|snippet|prompt|raw_text|raw_payload|raw_content|clause_text|document_text|agreement_text|matched_text|matched_clause|matched_snippet|client|customer|victim|plaintiff|defendant|username|full_name|first_name|last_name|company|holdings|corp|corporation|llc|inc|ltd|vendor|merchant|creditor|organization|org|firm|business)(?:\d{0,6})?(?:$|[._-])|(?:^|[._-])name$/;
const CUSTOM_DOMAIN_KEY_REGEX =
  /^(?:[a-z][a-z0-9._-]{0,63}|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+){1,3})$/;
const CUSTOM_DOMAIN_SCHEMA_SUFFIX_REGEX =
  /^(?:(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|dataset_relative|arbitrary|arbitrary_custom|matched|redflag|domain_custom|safe_custom|safe_registered|unkeyed_cleartext)[._-]?(?:count|cnt|pct|percent|percentage|ms|sec|bytes|score|status|level|tier|channel|path|code|type|key|field)|(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|matched|redflag)(?:Count|Cnt|Pct|Percent|Percentage|Ms|Sec|Bytes|Score|Status|Level|Tier|Channel|Path|Code|Type|Key|Field)|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/;
// Section 8.1 Collector Boundary Exclusions: app-local keys permitted only in isolated in-memory
// evaluation buffers (never exported over external OTLP pipelines when allowRawPayloads is false,
// and never permitted as a combined hospital_id + household_size + fpl_percentage patient quasi-identifier triad).
export const COLLECTOR_BOUNDARY_EXCLUDED_KEYS: ReadonlySet<string> = new Set([
  'agreement_title',
  'hospital_id',
  'household_size',
  'fpl_percentage',
]);

export function isCollectorBoundaryExcludedKey(key: string): boolean {
  return typeof key === 'string' && COLLECTOR_BOUNDARY_EXCLUDED_KEYS.has(key.toLowerCase());
}

function redactPatientQuasiIdentifierTriad(
  sanitized: Record<string, string | number | boolean>
): void {
  let hasHospital = false;
  let hasHousehold = false;
  let hasFpl = false;
  const matchedKeys: string[] = [];
  for (const k of Object.keys(sanitized)) {
    const lower = k.toLowerCase();
    if (lower === 'hospital_id') {
      hasHospital = true;
      matchedKeys.push(k);
    } else if (lower === 'household_size') {
      hasHousehold = true;
      matchedKeys.push(k);
    } else if (lower === 'fpl_percentage') {
      hasFpl = true;
      matchedKeys.push(k);
    }
  }
  if (hasHospital && hasHousehold && hasFpl) {
    for (const k of matchedKeys) {
      sanitized[k] = REDACTED_SENSITIVE_VALUE;
    }
  }
}

const REVIEWED_DOMAIN_EXTENSION_KEYS: ReadonlySet<string> = new Set([
  'hospital_id',
  'cpt_code',
  'statute_code',
  'household_size',
  'fpl_percentage',
  'charity_eligible',
  'unconditional_gift_triggered',
  'line_count',
  'has_itemized_breakdown',
  'discrepancy_count',
  'discount_percent',
  'has_income_verified',
  'has_balance_due',
  'unlawful_count',
  'score_percentage',
  'sidecar_active',
  'agreement_title',
  'ocr_used',
  'state',
  'overtime_hours',
  'regular_hours',
  'redflag_count',
  'is_compliant',
  'parsed_line_count',
  'has_overtime',
  'has_deductions',
  'product_type',
  'product_category',
  'warranty_type',
  'protection_score',
  'violations_count',
  'findings_count',
  'risk_score',
  'has_illegal_tie_in',
  'has_implied_disclaimer',
  'extension.action',
  'extension.rule_category',
  'extension.rule_id',
  'extension.severity',
  'extension.scan_duration_ms',
  'extension.traps_found',
  'extension.critical_count',
  'extension.warning_count',
  'app.version',
  'app.environment',
  'service.instance.id',
  'base_model',
  'dataset_hash',
  'adapter_size_bytes',
  'current_step',
  'total_steps',
  'progress_pct',
  'loss',
  'device',
  'exchange',
  'routing_key',
  'surprisal.preflight.enabled',
  'surprisal.preflight.status',
  'surprisal.preflight.duration_ms',
  'surprisal.cases.original_count',
  'surprisal.cases.ablated_count',
  'surprisal.cases.anomalous_count',
  'howso.preflight.enabled',
  'howso.preflight.status',
  'howso.preflight.duration_ms',
  'howso.cases.original_count',
  'howso.cases.ablated_count',
  'howso.cases.anomalous_count',
  'audit.allowlist_enforced',
  'audit.collector_verified',
]);

function isBuiltInSafeSchemaKey(lowerKey: string): boolean {
  return (
    DEFAULT_SAFE_ALLOWLIST_KEYS.has(lowerKey) ||
    REGISTERED_NUMERIC_KEYS.has(lowerKey) ||
    BOOLEAN_ONLY_KEYS.has(lowerKey) ||
    STRICT_TOKEN_KEYS.has(lowerKey)
  );
}

function normalizeKeyForProhibitedCheck(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase();
}

export function isProhibitedCustomDomainKey(key: string): boolean {
  return PROHIBITED_CUSTOM_DOMAIN_KEY_REGEX.test(normalizeKeyForProhibitedCheck(key));
}

function isSafeAttributeKey(key: string): boolean {
  return (
    typeof key === 'string' &&
    CUSTOM_DOMAIN_KEY_REGEX.test(key) &&
    !containsSensitivePattern(key)
  );
}

function isSafeCustomDomainKey(key: string): boolean {
  if (!isSafeAttributeKey(key) || isProhibitedCustomDomainKey(key)) {
    return false;
  }
  const lowerKey = key.toLowerCase();
  return (
    isBuiltInSafeSchemaKey(lowerKey) ||
    REVIEWED_DOMAIN_EXTENSION_KEYS.has(lowerKey) ||
    CUSTOM_DOMAIN_SCHEMA_SUFFIX_REGEX.test(key)
  );
}

export type CustomValueDomains =
  | Readonly<Record<string, Iterable<string>>>
  | ReadonlyMap<string, Iterable<string>>;

const NORMALIZED_DOMAIN_MAPS = new WeakSet<ReadonlyMap<string, ReadonlySet<string>>>();

export function normalizeCustomValueDomains(
  customValueDomains?: CustomValueDomains
): ReadonlyMap<string, ReadonlySet<string>> | undefined {
  if (!customValueDomains) return undefined;
  if (
    customValueDomains instanceof Map &&
    NORMALIZED_DOMAIN_MAPS.has(customValueDomains as ReadonlyMap<string, ReadonlySet<string>>)
  ) {
    return customValueDomains as ReadonlyMap<string, ReadonlySet<string>>;
  }
  const normalized = new Map<string, ReadonlySet<string>>();
  const isMapLike =
    customValueDomains instanceof Map ||
    (typeof (customValueDomains as Map<string, Iterable<string>>).entries === 'function' &&
      typeof (customValueDomains as Map<string, Iterable<string>>).forEach === 'function');
  const entries = isMapLike
    ? (customValueDomains as Map<string, Iterable<string>>).entries()
    : Object.entries(customValueDomains);
  for (const [key, values] of entries) {
    if (!key || !values) continue;
    // Detect camelCase, separator word boundaries, invalid structure, and embedded PII before lowercasing.
    if (!isSafeCustomDomainKey(key)) continue;
    const lowerKey = key.toLowerCase();
    const set = new Set<string>();
    for (const v of values) {
      // Custom domains cannot authorize arbitrary cleartext strings (e.g., tenant tokens under neutral keys)
      // when allowRawPayloads is false; only opaque cryptographic digests may pass without raw permission.
      if (typeof v === 'string' && OPAQUE_DIGEST_REGEX.test(v)) {
        set.add(v);
      }
    }
    // Preserve explicit empty/cleartext-only domains so callers fail closed rather than falling back to digest-any.
    normalized.set(lowerKey, set);
  }
  if (normalized.size === 0) return undefined;
  NORMALIZED_DOMAIN_MAPS.add(normalized);
  return normalized;
}
const DATASET_HASH_REGEX = /^(?:sha256:)?(?:[0-9a-f]{12,64}|[0-9A-F]{12,64})$/;
const OPAQUE_UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const OPAQUE_HEX_ID_REGEX = /^(?:[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16})$/;
const REGISTERED_EVENT_NAMES: ReadonlySet<string> = new Set([
  // Canonical lifecycle actions (aligned with ACTION_VALUES)
  'scan_started',
  'scan_complete',
  'scan_completed',
  'document_ingested',
  'rules_evaluated',
  'audit_performed',
  'handoff_sent',
  'handoff_received',
  'handoff_rejected',
  'edge_inference_started',
  'edge_inference_completed',
  'edge_inference_failed',
  'edge_export',
  'ocr_started',
  'ocr_completed',
  'pdf_extracted',
  'burn',
  'hard_burn',
  'export',
  'dispute_generated',
  // Registered extension & consumer-app operational span/event names
  'extension.page_scan',
  'evaluate_subscription_agreement',
  'parse_agreement',
  'parse_contract',
  'evaluate_charity_care',
  'audit_medical_bill',
  'parse_bill',
  'evaluate_lease_rules',
  'evaluate_edge_semantic_lora',
  'segment_clauses',
  'audit_evaluation',
  'parse_document',
  'enterprise_job',
  'analyze_paystub',
  'parse_paystub',
  'parse_wage_statement',
  'analyze_warranty',
  'parse_warranty',
  'parse_warranty_card',
  // Registered ML FTaaS & OTel operational span/event names
  'job.accepted',
  'job.publish_failed',
  'job.published',
  'job.edge_export_requested',
  'job.edge_exported',
  'job.consumed',
  'job.registered',
  'job.completed',
  'job.failed',
  'job.training.started',
  'job.training.finished',
  'job.transition',
  'job.transition.pending',
  'job.transition.queued',
  'job.transition.training',
  'job.transition.succeeded',
  'job.transition.failed',
  'job.transition.cancelled',
  'job.transition.canceled',
  'surprisal.preflight',
  'howso.preflight',
  'rule.evaluated',
]);
const HMAC_PATH_REGEX = /^hmac:[a-f0-9]{16}$/;
const TRUNCATED_HASH_REGEX = /^\[TRUNCATED_HASH_[a-f0-9]{8}\]$/;
const FEDERAL_STATUTE_REGEX =
  /^\d{1,3}\s+(?:U\.?S\.?C\.?|C\.?F\.?R\.?|Stat\.)\s+(?:(?:§§?|Part)\s*)?\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?$/;
const CHAPTER_ACT_STATUTE_REGEX =
  /^\d{1,4}\s+ILCS\s+\d{1,4}[A-Za-z]?(?:-(?:\d{1,4}|[A-Za-z]))?(?:\/|\/\d{1,4}(?:-\d{1,4})?[A-Za-z]?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?$/;
const JURISDICTION_SECTION_STATUTE_REGEX =
  /^(?:Cal\.|N\.Y\.|Mass\.|Tex\.|Fla\.|Ill\.|Wash\.|Colo\.|Or\.|Pa\.|N\.J\.|Va\.|Md\.|Ga\.|N\.C\.|S\.C\.|Minn\.|Wis\.|Ariz\.|Nev\.|Mich\.|Conn\.|Ind\.|Ohio|Iowa|Utah|Tenn\.|Ky\.|La\.|Ala\.|Ark\.|Kan\.|Mo\.|Neb\.|Mont\.|Idaho|Wyo\.|Me\.|Vt\.|N\.H\.|R\.I\.|Del\.|Alaska|Hawaii|D\.C\.|UCC|FDCPA|FCRA|FLSA|TILA|SCRA|FHA|HIPAA|ROSCA|CCPA|CPRA|BIPA|FTC)(?:\s+(?:Rev\.|Gen\.|Bus\.|Prof\.|Civ\.|Lab\.|Prop\.|Penal|Ins\.|Health|Educ\.|Fin\.|Gov\.|Com\.|Code|Laws?|Stat\.|Act|Ann\.|ch\.|c\.|Part|Title|&|GBL|RPL|Art\.|\d{1,4}[A-Za-z]?)){0,5}(?:,\s*|\s*)(?:§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?|Ch\.\s*\d{1,4}(?:\s*§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?)?)$/;
const EU_STATUTE_REGEX =
  /^(?:EU\s+)?(?:GDPR(?:\s+Art\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?|Directive\s+\d{4}\/\d{1,4}\/[A-Z]{2,4}(?:,?\s+Art(?:icle)?\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?)$/;
const UK_STATUTE_REGEX =
  /^UK\s+(?:Consumer\s+Rights|DMCC|Data\s+Protection|Employment\s+Rights)\s+Act\s+\d{4}(?:,?\s+(?:Part|Chapter|Section|Sec\.|§)\s*\d{1,4}(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3}){0,3}$/;

const REGISTERED_NUMERIC_KEYS: ReadonlySet<string> = new Set([
  // Default numeric schema keys
  'step',
  'current_step',
  'total_steps',
  'loss',
  'http.status_code',
  'duration_ms',
  'duration_sec',
  'progress_pct',
  'adapter_size_bytes',
  'clause_count',
  'total_clauses',
  'flagged_clauses',
  'flagged_count',
  'standard_count',
  'watch_count',
  'unenforceable_count',
  'char_count',
  'matched_violations',
  // Reviewed portfolio numeric schema keys
  'extension.scan_duration_ms',
  'extension.traps_found',
  'extension.critical_count',
  'extension.warning_count',
  'household_size',
  'fpl_percentage',
  'line_count',
  'discrepancy_count',
  'discount_percent',
  'parsed_line_count',
  'unlawful_count',
  'score_percentage',
  'overtime_hours',
  'regular_hours',
  'redflag_count',
  'protection_score',
  'violations_count',
  'findings_count',
  'surprisal.preflight.duration_ms',
  'surprisal.cases.original_count',
  'surprisal.cases.ablated_count',
  'surprisal.cases.anomalous_count',
  'howso.preflight.duration_ms',
  'howso.cases.original_count',
  'howso.cases.ablated_count',
  'howso.cases.anomalous_count',
]);

const BOOLEAN_ONLY_KEYS: ReadonlySet<string> = new Set([
  'ocr_used',
  'sidecar_active',
  'charity_eligible',
  'unconditional_gift_triggered',
  'has_income_verified',
  'has_balance_due',
  'has_itemized_breakdown',
  'has_deductions',
  'has_overtime',
  'has_illegal_tie_in',
  'has_implied_disclaimer',
  'is_compliant',
  'surprisal.preflight.enabled',
  'howso.preflight.enabled',
  'audit.allowlist_enforced',
  'audit.collector_verified',
]);

const STRICT_TOKEN_KEYS: ReadonlySet<string> = new Set([
  'rule_id',
  'error_code',
  'device',
  'http.method',
  'job_id',
  'service',
  'service.name',
  'action',
  'status',
  'audit_status',
  'risk_level',
  'exchange',
  'routing_key',
  'error_type',
  'extension.action',
  'extension.rule_category',
  'extension.rule_id',
  'extension.severity',
  'app.version',
  'app.environment',
  'howso.preflight.status',
  'surprisal.preflight.status',
]);

const STATUS_VALUES: ReadonlySet<string> = new Set([
  'OK', 'ERROR', 'UNSET', 'Pending', 'Queued', 'Training', 'TrainingFinished',
  'Succeeded', 'Failed', 'Completed', 'Cancelled', 'Canceled', 'Timeout', 'Unknown',
  'ok', 'error', 'unset', 'pending', 'queued', 'training', 'training_finished',
  'succeeded', 'failed', 'completed', 'cancelled', 'canceled', 'timeout', 'unknown',
  'degraded', 'burned', 'Standard', 'Watch', 'Flagged', 'LikelyUnenforceable',
  'Unenforceable', 'Compliant', 'NonCompliant', 'Disabled', 'disabled',
  'Skipped', 'skipped', 'FellBack',
]);

const AUDIT_STATUS_VALUES: ReadonlySet<string> = new Set([
  'Standard', 'Watch', 'Flagged', 'LikelyUnenforceable', 'Unenforceable',
  'Compliant', 'NonCompliant', 'Passed', 'Failed', 'Completed', 'Pending',
  'OK', 'ERROR', 'Unknown', 'standard', 'watch', 'flagged',
  'likely_unenforceable', 'unenforceable', 'compliant', 'non_compliant',
  'passed', 'failed', 'completed', 'pending', 'ok', 'error', 'unknown',
]);

const RISK_SEVERITY_VALUES: ReadonlySet<string> = new Set([
  'Critical', 'High', 'Medium', 'Moderate', 'Low', 'Info', 'Warning', 'None', 'Minimal', 'Elevated', 'Severe',
  'CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW', 'INFO', 'WARNING', 'NONE',
  'critical', 'high', 'medium', 'moderate', 'low', 'info', 'warning', 'none',
]);

const PREFLIGHT_STATUS_VALUES: ReadonlySet<string> = new Set([
  'Disabled', 'Skipped', 'Completed', 'FellBack', 'Passed', 'Failed', 'Error', 'OK',
  'disabled', 'skipped', 'completed', 'fell_back', 'passed', 'failed', 'error', 'ok',
]);

const HTTP_METHOD_VALUES: ReadonlySet<string> = new Set([
  'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE',
]);

const DEVICE_VALUES: ReadonlySet<string> = new Set([
  'cpu', 'cuda', 'cuda:0', 'cuda:1', 'cuda:2', 'cuda:3', 'cuda:4', 'cuda:5', 'cuda:6', 'cuda:7',
  'mps', 'webgpu', 'wasm', 'gpu', 'npu', 'ane', 'xpu', 'rocm', 'directml', 'auto', 'none', 'unknown', 'x64', 'arm64',
]);

const ACTION_VALUES: ReadonlySet<string> = new Set([
  'scan_started', 'scan_complete', 'scan_completed', 'document_ingested',
  'rules_evaluated', 'audit_performed', 'handoff_sent', 'handoff_received', 'handoff_rejected',
  'edge_inference_started', 'edge_inference_completed', 'edge_inference_failed', 'edge_export',
  'ocr_started', 'ocr_completed', 'pdf_extracted', 'burn', 'hard_burn', 'export', 'dispute_generated',
]);

const EXTENSION_RULE_CATEGORY_VALUES: ReadonlySet<string> = new Set([
  'AUTO_RENEWAL', 'ARBITRATION', 'UNILATERAL_CHANGE', 'SURVEILLANCE',
  'WARRANTY_DISCLAIMER', 'WAGE_THEFT', 'TERMS', 'BILLING', 'PRIVACY', 'DARK_PATTERN',
]);

const SERVICE_NAME_VALUES: ReadonlySet<string> = new Set([
  'knowthankyew-app', 'privacy-telemetry', 'knowthankyew-extension', 'lease-audit', 'care-check', 'careCheck',
  'paystub-check', 'bill-of-rights-bot', 'warranty-watch', 'ftaas-api', 'ftaas-worker',
  'ftaas-inference', 'surprisal-service', 'howso-preflight', 'mail-stripper',
  'mail-stripper-imap', 'unsubscribe-shield-ext', 'gradcast', 'genesis',
  'mac-screen-record', 'kty-ntfs', 'enterprise-self-host', 'test-svc', 'unknown',
]);

const APP_ENVIRONMENT_VALUES: ReadonlySet<string> = new Set([
  'development', 'dev', 'staging', 'stage', 'production', 'prod',
  'test', 'testing', 'ci', 'local', 'sandbox', 'preview',
  'Development', 'Staging', 'Production',
]);

const EXCHANGE_VALUES: ReadonlySet<string> = new Set([
  'ftaas.direct', 'ftaas.dlx', 'ftaas.events', 'ftaas.topic', 'default', 'direct',
]);

const ROUTING_KEY_VALUES: ReadonlySet<string> = new Set([
  'job.requested', 'job.updated', 'job.status', 'job.completed', 'job.failed',
  'job.dlq', 'job.cancelled', 'job.canceled', 'job.progress', 'job.edge_export',
]);

const CLOSED_TOKEN_DOMAIN_MAP: Readonly<Record<string, ReadonlySet<string>>> = {
  status: STATUS_VALUES,
  audit_status: AUDIT_STATUS_VALUES,
  risk_level: RISK_SEVERITY_VALUES,
  'extension.severity': RISK_SEVERITY_VALUES,
  'howso.preflight.status': PREFLIGHT_STATUS_VALUES,
  'surprisal.preflight.status': PREFLIGHT_STATUS_VALUES,
  'http.method': HTTP_METHOD_VALUES,
  device: DEVICE_VALUES,
  action: ACTION_VALUES,
  'extension.action': ACTION_VALUES,
  'extension.rule_category': EXTENSION_RULE_CATEGORY_VALUES,
  service: SERVICE_NAME_VALUES,
  'service.name': SERVICE_NAME_VALUES,
  'app.environment': APP_ENVIRONMENT_VALUES,
  exchange: EXCHANGE_VALUES,
  routing_key: ROUTING_KEY_VALUES,
};

const JURISDICTION_VALUES: ReadonlySet<string> = new Set([
  'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'DC', 'FL', 'GA', 'HI', 'ID', 'IL', 'IN', 'IA',
  'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM',
  'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA',
  'WV', 'WI', 'WY', 'AS', 'GU', 'MP', 'PR', 'VI',
  'FED', 'FEDERAL', 'FTC', 'DEFAULT', 'US', 'UK', 'EU', 'EU_CRD', 'UK_DMCC', 'CA-ON',
  'Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado', 'Connecticut', 'Delaware',
  'District of Columbia', 'Florida', 'Georgia', 'Hawaii', 'Idaho', 'Illinois', 'Indiana', 'Iowa',
  'Kansas', 'Kentucky', 'Louisiana', 'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota',
  'Mississippi', 'Missouri', 'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey',
  'New Mexico', 'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon',
  'Pennsylvania', 'Rhode Island', 'South Carolina', 'South Dakota', 'Tennessee', 'Texas', 'Utah',
  'Vermont', 'Virginia', 'Washington', 'West Virginia', 'Wisconsin', 'Wyoming',
  'Puerto Rico', 'American Samoa', 'Virgin Islands', 'Guam', 'Northern Mariana Islands',
  'United States', 'US Federal', 'Federal', 'United Kingdom', 'European Union',
]);

const WARRANTY_TYPE_VALUES: ReadonlySet<string> = new Set([
  'Full',
  'Limited',
  'Disclaimed / As-Is',
  'Unspecified',
]);

const PRODUCT_TYPE_VALUES: ReadonlySet<string> = new Set([
  'Electronics & Laptops',
  'Electronics & Computers',
  'Automotive & EV Accessories',
  'Automotive / EV',
  'Home Appliances',
  'Tools & Hardware',
  'Tools & Equipment',
  'Smart Home Devices',
  'Furniture & Home Goods',
  'General Consumer Product',
  'Consumer Electronics',
  'Automotive Vehicle',
  'Home Appliance',
  'General',
  'Electronics',
  'Automotive',
  'Appliances',
  'Tools',
]);

type KeySchemaKind =
  | 'adapter_hmac_path'
  | 'dataset_jsonl_path'
  | 'path'
  | 'rule_ids'
  | 'numeric'
  | 'boolean'
  | 'base_model'
  | 'dataset_hash'
  | 'jurisdiction'
  | 'warranty_type'
  | 'product_type'
  | 'statute_code'
  | 'hospital_id'
  | 'cpt_code'
  | 'service_instance_id'
  | 'strict_token'
  | 'custom';

function classifyKeyKind(lowerKey: string, rawKey?: string): KeySchemaKind {
  if (lowerKey === 'service.instance.id') return 'service_instance_id';
  const normalizedPathKey = rawKey ? normalizeKeyForProhibitedCheck(rawKey) : lowerKey;
  if (normalizedPathKey.endsWith('_path')) {
    if (normalizedPathKey.startsWith('adapter')) return 'adapter_hmac_path';
    if (normalizedPathKey.startsWith('dataset_')) return 'dataset_jsonl_path';
    return 'path';
  }
  if (lowerKey === 'rule_ids') return 'rule_ids';
  if (lowerKey === 'base_model') return 'base_model';
  if (lowerKey === 'dataset_hash') return 'dataset_hash';
  if (lowerKey === 'jurisdiction' || lowerKey === 'state') return 'jurisdiction';
  if (lowerKey === 'warranty_type') return 'warranty_type';
  if (lowerKey === 'product_type' || lowerKey === 'product_category') return 'product_type';
  if (lowerKey === 'statute_code') return 'statute_code';
  if (lowerKey === 'hospital_id') return 'hospital_id';
  if (lowerKey === 'cpt_code') return 'cpt_code';
  if (REGISTERED_NUMERIC_KEYS.has(lowerKey)) {
    return 'numeric';
  }
  if (
    BOOLEAN_ONLY_KEYS.has(lowerKey) ||
    lowerKey.startsWith('is_') ||
    lowerKey.startsWith('has_') ||
    lowerKey.endsWith('.enabled') ||
    lowerKey.endsWith('_enabled')
  ) {
    return 'boolean';
  }
  if (STRICT_TOKEN_KEYS.has(lowerKey)) return 'strict_token';
  return 'custom';
}

function sanitizeStatuteCode(value: string): string {
  if (
    value.length <= 64 &&
    (FEDERAL_STATUTE_REGEX.test(value) ||
      CHAPTER_ACT_STATUTE_REGEX.test(value) ||
      JURISDICTION_SECTION_STATUTE_REGEX.test(value) ||
      EU_STATUTE_REGEX.test(value) ||
      UK_STATUTE_REGEX.test(value))
  ) {
    return value;
  }
  return REDACTED_SENSITIVE_VALUE;
}

function sanitizePathValue(
  rawKey: string,
  lowerKey: string,
  kind: 'adapter_hmac_path' | 'dataset_jsonl_path' | 'path',
  value: string,
  allowRawPayloads: boolean,
  customDomains?: ReadonlyMap<string, ReadonlySet<string>>
): string {
  if (value === REDACTED_SENSITIVE_VALUE) {
    return value;
  }
  const hasExplicitDomain = customDomains?.has(lowerKey) ?? false;
  if (
    !allowRawPayloads &&
    hasExplicitDomain &&
    (isProhibitedCustomDomainKey(rawKey) ||
      isProhibitedCustomDomainKey(lowerKey) ||
      !(customDomains?.get(lowerKey)?.has(value) ?? false))
  ) {
    return REDACTED_SENSITIVE_VALUE;
  }
  if (value === '') {
    return value;
  }
  // Enforce path schemas before any digest fallback or marker preservation (Section 8.2).
  if (kind === 'adapter_hmac_path') {
    return value.length === 21 && HMAC_PATH_REGEX.test(value)
      ? value
      : REDACTED_SENSITIVE_VALUE;
  }
  if (kind === 'dataset_jsonl_path') {
    if (value.length > 128 || !value.endsWith('.jsonl')) {
      return REDACTED_SENSITIVE_VALUE;
    }
    const stem = value.slice(0, -'.jsonl'.length);
    const isOpaqueStem = OPAQUE_JOB_IDENTIFIER_REGEX.test(stem);
    if (containsSensitivePattern(value, { skipSsn: isOpaqueStem })) {
      return REDACTED_SENSITIVE_VALUE;
    }
    return JOB_ID_REGEX.test(stem) ? value : REDACTED_SENSITIVE_VALUE;
  }
  const isKeyedHmacDigest = KEYED_HMAC_DIGEST_REGEX.test(value);
  if (value.length > 128 || containsSensitivePattern(value, { skipSsn: isKeyedHmacDigest })) {
    return REDACTED_SENSITIVE_VALUE;
  }
  if (allowRawPayloads && !TRUNCATED_HASH_REGEX.test(value)) {
    return value;
  }
  return isKeyedHmacDigest ? value : REDACTED_SENSITIVE_VALUE;
}

function sanitizeRuleIdsCsv(value: string): string {
  if (value === '') return '';
  const parts = value.split(',');
  if (parts.length > MAX_RULE_IDS) return REDACTED_SENSITIVE_VALUE;
  for (const part of parts) {
    if (!isSafeRuleId(part)) return REDACTED_SENSITIVE_VALUE;
  }
  return value;
}

function sanitizeStrictToken(lowerKey: string, value: string): string {
  const allowedSet = CLOSED_TOKEN_DOMAIN_MAP[lowerKey];
  if (allowedSet) {
    const candidate = lowerKey === 'device' ? value.toLowerCase() : value;
    return allowedSet.has(candidate) ? value : REDACTED_SENSITIVE_VALUE;
  }
  if (lowerKey === 'job_id') {
    return JOB_ID_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
  }
  if (lowerKey === 'rule_id' || lowerKey === 'extension.rule_id') {
    return isSafeRuleId(value) ? value : REDACTED_SENSITIVE_VALUE;
  }
  if (lowerKey === 'error_code' || lowerKey === 'error_type') {
    return isSafeErrorCode(value) ? value : REDACTED_SENSITIVE_VALUE;
  }
  if (lowerKey === 'app.version') {
    return APP_VERSION_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
  }
  return REDACTED_SENSITIVE_VALUE;
}

function sanitizeRuleIdsArray(
  items: unknown[],
  allowRawPayloads: boolean,
  customDomains?: ReadonlyMap<string, ReadonlySet<string>>
): string {
  const hasExplicitRuleDomain = !allowRawPayloads && (customDomains?.has('rule_ids') ?? false);
  if (hasExplicitRuleDomain && isProhibitedCustomDomainKey('rule_ids')) {
    return REDACTED_SENSITIVE_VALUE;
  }
  const registeredRuleDomain = hasExplicitRuleDomain ? customDomains?.get('rule_ids') : undefined;
  if (items.length === 0) return hasExplicitRuleDomain ? REDACTED_SENSITIVE_VALUE : '';
  if (items.length > MAX_RULE_IDS) return REDACTED_SENSITIVE_VALUE;

  const cleaned: string[] = [];
  for (const item of items) {
    if (typeof item !== 'string') return REDACTED_SENSITIVE_VALUE;
    if (hasExplicitRuleDomain && !(registeredRuleDomain?.has(item) ?? false)) {
      return REDACTED_SENSITIVE_VALUE;
    }
    const sanitizedItem = allowRawPayloads
      ? item.length > MAX_STRING_LENGTH
        ? formatTruncatedDigest(item)
        : item
      : sanitizeAllowlistedStringValue('rule_id', item);
    if (sanitizedItem === REDACTED_SENSITIVE_VALUE) {
      return REDACTED_SENSITIVE_VALUE;
    }
    cleaned.push(sanitizedItem);
  }
  const joined = cleaned.join(',');
  if (joined.length > MAX_RULE_IDS_CSV_LENGTH) {
    return allowRawPayloads ? formatTruncatedDigest(joined) : REDACTED_SENSITIVE_VALUE;
  }
  return joined;
}

function sanitizeStringForSchema(
  rawKey: string,
  value: string,
  allowRawPayloads: boolean,
  customDomains?: ReadonlyMap<string, ReadonlySet<string>>
): string {
  const lowerKey = rawKey.toLowerCase();
  const kind = classifyKeyKind(lowerKey, rawKey);
  if (kind === 'adapter_hmac_path' || kind === 'dataset_jsonl_path' || kind === 'path') {
    return sanitizePathValue(rawKey, lowerKey, kind, value, allowRawPayloads, customDomains);
  }
  if (value === REDACTED_SENSITIVE_VALUE || TRUNCATED_HASH_REGEX.test(value)) {
    return value;
  }
  if (!allowRawPayloads && (customDomains?.has(lowerKey) ?? false)) {
    const registeredDomain = customDomains?.get(lowerKey);
    if (isProhibitedCustomDomainKey(rawKey) || isProhibitedCustomDomainKey(lowerKey)) {
      return REDACTED_SENSITIVE_VALUE;
    }
    if (kind === 'rule_ids') {
      if (value === '') {
        return REDACTED_SENSITIVE_VALUE;
      }
      if (value.length > MAX_RULE_IDS_CSV_LENGTH) {
        return formatTruncatedDigest(value);
      }
      const domainParts = value.split(',');
      if (
        domainParts.length > MAX_RULE_IDS ||
        !domainParts.every((part) => registeredDomain?.has(part) ?? false)
      ) {
        return REDACTED_SENSITIVE_VALUE;
      }
    } else if (!(registeredDomain?.has(value) ?? false)) {
      return REDACTED_SENSITIVE_VALUE;
    }
  }
  // Valid rule_ids CSV (<= 50 items, max 71 chars each) stays intact across repeated sanitization passes.
  if (kind === 'rule_ids' && value.length <= MAX_RULE_IDS_CSV_LENGTH) {
    if (allowRawPayloads) {
      return value;
    }
    const csv = sanitizeRuleIdsCsv(value);
    if (csv !== REDACTED_SENSITIVE_VALUE) {
      const parts = csv === '' ? [] : csv.split(',');
      const hasSensitive = parts.some((part) =>
        containsSensitivePattern(part, { skipSsn: OPAQUE_DIGEST_REGEX.test(part) })
      );
      if (!hasSensitive) {
        return csv;
      }
    }
  }
  // Check length before regex evaluation so oversized inputs short-circuit to a hash.
  if (value.length > MAX_STRING_LENGTH) {
    return formatTruncatedDigest(value);
  }
  if (allowRawPayloads) {
    return value;
  }
  const isConstrainedOpaque =
    (kind === 'dataset_hash' && DATASET_HASH_REGEX.test(value)) ||
    (lowerKey === 'job_id' && OPAQUE_JOB_IDENTIFIER_REGEX.test(value)) ||
    (kind === 'service_instance_id' && SERVICE_INSTANCE_ID_REGEX.test(value)) ||
    ((kind === 'base_model' ||
      lowerKey === 'rule_id' ||
      lowerKey === 'extension.rule_id' ||
      lowerKey === 'error_code' ||
      lowerKey === 'error_type') &&
      OPAQUE_DIGEST_REGEX.test(value)) ||
    (kind === 'hospital_id' && /^(?:hosp_|hmac:)[a-f0-9]{16,64}$/.test(value)) ||
    (kind === 'cpt_code' && HMAC_PATH_REGEX.test(value)) ||
    (kind === 'custom' && /^(?:hmac|sha256):[a-f0-9]{16,64}$/.test(value));
  if (containsSensitivePattern(value, { skipSsn: isConstrainedOpaque })) {
    return REDACTED_SENSITIVE_VALUE;
  }

  switch (kind) {
    case 'numeric':
    case 'boolean':
      return REDACTED_SENSITIVE_VALUE;
    case 'base_model':
      return isSafeBaseModel(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'dataset_hash':
      return DATASET_HASH_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'jurisdiction':
      return JURISDICTION_VALUES.has(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'warranty_type':
      return WARRANTY_TYPE_VALUES.has(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'product_type':
      return PRODUCT_TYPE_VALUES.has(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'statute_code':
      return sanitizeStatuteCode(value);
    case 'hospital_id':
      return HOSPITAL_ID_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'cpt_code':
      return CPT_CODE_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'service_instance_id':
      return SERVICE_INSTANCE_ID_REGEX.test(value) ? value : REDACTED_SENSITIVE_VALUE;
    case 'rule_ids':
      return sanitizeRuleIdsCsv(value);
    case 'strict_token':
      return sanitizeStrictToken(lowerKey, value);
    case 'custom': {
      const hasExplicitDomain = customDomains?.has(lowerKey) ?? false;
      return OPAQUE_DIGEST_REGEX.test(value) &&
        (!hasExplicitDomain ||
          (!(isProhibitedCustomDomainKey(rawKey) || isProhibitedCustomDomainKey(lowerKey)) &&
            (customDomains?.get(lowerKey)?.has(value) ?? false)))
        ? value
        : REDACTED_SENSITIVE_VALUE;
    }
  }
}

function passesLuhn(digits: string): boolean {
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * Checks whether an allowlisted string value contains control chars, PII, secrets, or local user paths.
 */
export function containsSensitivePattern(
  value: string,
  options?: { skipSsn?: boolean }
): boolean {
  if (value.length > MAX_PATTERN_CHECK_LENGTH) {
    return true;
  }
  if (
    CONTROL_OR_MULTILINE_REGEX.test(value) ||
    EMAIL_REGEX.test(value) ||
    (!options?.skipSsn && SSN_REGEX.test(value)) ||
    DELIMITED_CARD_REGEX.test(value) ||
    SECRET_TOKEN_REGEX.test(value) ||
    LOCAL_PATH_REGEX.test(value)
  ) {
    return true;
  }
  for (const match of value.matchAll(CONTIGUOUS_CARD_IIN_REGEX)) {
    if (passesLuhn(match[1])) {
      return true;
    }
  }
  return false;
}

export function isSafeEventName(name: string): boolean {
  return (
    typeof name === 'string' &&
    name.length > 0 &&
    name.length <= 128 &&
    REGISTERED_EVENT_NAMES.has(name) &&
    !containsSensitivePattern(name)
  );
}

/**
 * Validates span and event names at the export boundary so arbitrary free text or PII
 * cannot leak via span names when raw payloads are disabled.
 */
export function sanitizeSpanName(name: string, allowRawPayloads = false): string {
  if (!name) return '[REDACTED_SPAN_NAME]';
  if (allowRawPayloads) {
    return name.length > MAX_STRING_LENGTH ? formatTruncatedDigest(name) : name;
  }
  return isSafeEventName(name) && !containsSensitivePattern(name)
    ? name
    : '[REDACTED_SPAN_NAME]';
}

/**
 * Validates and sanitizes string values even when their attribute key is allowlisted.
 */
export function sanitizeAllowlistedStringValue(key: string, value: string): string {
  return sanitizeStringForSchema(key, value, false);
}

/**
 * Computes an 8-character lowercase hexadecimal SHA-256 digest marker for oversized attributes.
 * Does not expose any source text.
 */
export function formatTruncatedDigest(value: string): string {
  const hex = sha256Hex(value);
  return `[TRUNCATED_HASH_${hex.slice(0, 8)}]`;
}

/**
 * Creates an allowlist attribute sanitizer combining default safe keys with domain-specific extensions.
 */
export function createAllowlistSanitizer(
  additionalKeys?: Iterable<string>,
  customValueDomains?: CustomValueDomains
): {
  allowlist: ReadonlySet<string>;
  sanitize: (
    attrs: Record<string, unknown>,
    allowRawPayloads?: boolean
  ) => Record<string, string | number | boolean>;
} {
  const normalizedCustomDomains = normalizeCustomValueDomains(customValueDomains);
  const allowlist = new Set<string>(DEFAULT_SAFE_ALLOWLIST_KEYS);
  if (additionalKeys) {
    for (const key of additionalKeys) {
      if (typeof key !== 'string') continue;
      const lowerKey = key.toLowerCase();
      if (isBuiltInSafeSchemaKey(lowerKey) || isSafeCustomDomainKey(key)) {
        allowlist.add(lowerKey);
      }
    }
  }
  if (normalizedCustomDomains) {
    for (const [key, domainSet] of normalizedCustomDomains.entries()) {
      if (domainSet.size > 0) {
        allowlist.add(key);
      }
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
      const isBuiltIn = isBuiltInSafeSchemaKey(lowerKey);

      if (
        !allowRawPayloads &&
        (!isAllowlisted || (!isBuiltIn && !isSafeCustomDomainKey(key)))
      ) {
        sanitized[REDACTED_UNALLOWLISTED_KEY] = REDACTED_NOT_ALLOWLISTED;
        continue;
      }

      const outputKey =
        allowRawPayloads && key.length > MAX_STRING_LENGTH
          ? formatTruncatedDigest(key)
          : key;

      if (typeof val === 'string') {
        sanitized[outputKey] = sanitizeStringForSchema(
          key,
          val,
          allowRawPayloads,
          normalizedCustomDomains
        );
        continue;
      }

      const isExplicitSafePrimitiveKey =
        DEFAULT_SAFE_ALLOWLIST_KEYS.has(lowerKey) ||
        REGISTERED_NUMERIC_KEYS.has(lowerKey) ||
        BOOLEAN_ONLY_KEYS.has(lowerKey);
      if (
        !allowRawPayloads &&
        !isExplicitSafePrimitiveKey &&
        (isProhibitedCustomDomainKey(key) ||
          isProhibitedCustomDomainKey(lowerKey) ||
          containsSensitivePattern(key))
      ) {
        sanitized[outputKey] = REDACTED_SENSITIVE_VALUE;
        continue;
      }

      const hasRegisteredDomain = normalizedCustomDomains?.has(lowerKey) ?? false;

      if (typeof val === 'number') {
        if (!Number.isFinite(val)) {
          sanitized[outputKey] = REDACTED_SENSITIVE_VALUE;
          continue;
        }
        if (hasRegisteredDomain && !allowRawPayloads) {
          sanitized[outputKey] = REDACTED_SENSITIVE_VALUE;
          continue;
        }
        const kind = classifyKeyKind(lowerKey);
        sanitized[outputKey] =
          allowRawPayloads || kind === 'numeric'
            ? val
            : REDACTED_SENSITIVE_VALUE;
        continue;
      }

      if (typeof val === 'boolean') {
        if (hasRegisteredDomain && !allowRawPayloads) {
          sanitized[outputKey] = REDACTED_SENSITIVE_VALUE;
          continue;
        }
        const kind = classifyKeyKind(lowerKey);
        sanitized[outputKey] =
          allowRawPayloads || kind === 'boolean' || kind === 'custom'
            ? val
            : REDACTED_SENSITIVE_VALUE;
        continue;
      }

      if (Array.isArray(val) && lowerKey === 'rule_ids') {
        sanitized[outputKey] = sanitizeRuleIdsArray(val, allowRawPayloads, normalizedCustomDomains);
        continue;
      }

      sanitized[outputKey] = REDACTED_SENSITIVE_VALUE;
    }

    if (!allowRawPayloads) {
      redactPatientQuasiIdentifierTriad(sanitized);
    }

    return sanitized;
  };

  return { allowlist, sanitize };
}
