/**
 * TelemetryManager - Lifecycle coordinator for in-memory and enterprise telemetry
 */

import {
  TelemetryConfig,
  TelemetryMode,
  SpanRecord,
  SessionAuditEvent,
  PrivacyAuditReport,
  PrivacyClaims,
  PrivacyClaimsBranding,
} from './types.js';
import {
  CustomValueDomains,
  createAllowlistSanitizer,
  formatTruncatedDigest,
  normalizeCustomValueDomains,
  sanitizeSpanName,
} from './allowlist.js';
import {
  MemoryExporter,
  ScrubResult,
  exportToOtlp,
  replaceAccessorWithDataProperty,
  scrubObjectField,
  scrubRecordEntries,
} from './exporter.js';
import { getPrivacyClaims } from './claims.js';
import {
  EXPORT_OWNED_SPAN_SYMBOL,
  createWeakRef,
  getRealmState,
  isHardBurned,
  recordRealmHardBurn,
  registerRetainedAlias,
  unregisterRetainedAlias,
  wipeLiveExporters,
  wipeRetainedAliases,
  wipeWeakTargetRegistry,
} from './tombstone.js';

export { isHardBurned };

const MAX_AUDIT_LOG_CAPACITY = 500;

const AUDIT_EVENT_SUMMARY_CATALOG: Readonly<Record<string, string>> = {
  document_ingested: 'Local document ingested for analysis',
  rules_evaluated: 'Compliance rules evaluated locally',
  letter_generated: 'Local dispute or response letter generated',
  burn_invoked: 'Volatile telemetry burn invoked',
  audit_performed: 'Local privacy or compliance audit completed',
  edge_inference_started: 'In-browser edge inference started',
  edge_inference_completed: 'In-browser edge inference completed',
  edge_inference_failed: 'In-browser edge inference failed',
  handoff_received: 'Cross-engine handoff received',
  handoff_rejected: 'Cross-engine handoff rejected',
  handoff_sent: 'Cross-engine handoff dispatched',
  scan_started: 'Local compliance scan started',
  scan_complete: 'Local compliance scan completed',
  scan_completed: 'Local compliance scan completed',
  ocr_started: 'Local OCR processing started',
  ocr_completed: 'Local OCR processing completed',
  pdf_extracted: 'Local PDF text extraction completed',
  burn: 'Volatile telemetry burned',
  hard_burn: 'Hard burn teardown executed',
  export: 'Local export generated',
  dispute_generated: 'Local dispute draft generated',
};

function scrubAuditEventRecord(entry: SessionAuditEvent): ScrubResult {
  let ok = true;
  let firstError: unknown;
  try {
    const details = entry.details;
    if (details && typeof details === 'object') {
      if (!scrubRecordEntries(details as Record<string, unknown>)) {
        ok = false;
      }
    }
    if (!replaceAccessorWithDataProperty(entry, 'details', undefined)) {
      ok = false;
    }
  } catch (err) {
    ok = false;
    firstError = err;
  }
  if (!scrubObjectField(entry, 'summary', '[REDACTED_AUDIT_SUMMARY]')) {
    ok = false;
  }
  if (!scrubObjectField(entry, 'action', '[REDACTED_ACTION]')) {
    ok = false;
  }
  if (!scrubObjectField(entry, 'id', '[REDACTED]')) {
    ok = false;
  }
  if (!scrubObjectField(entry, 'timestamp', '')) {
    ok = false;
  }
  return firstError !== undefined ? { ok: false, error: firstError } : { ok };
}

function wipeRetainedAuditEntry(target: object): void {
  const res = scrubAuditEventRecord(target as SessionAuditEvent);
  if (res.ok && res.error === undefined) {
    unregisterRetainedAlias(target);
  }
  if (res.error !== undefined) {
    throw res.error;
  }
  if (!res.ok) {
    throw new Error('Telemetry burn could not scrub immutable retained audit record.');
  }
}

function wipeRetainedAuditDetails(target: object): void {
  if (scrubRecordEntries(target as Record<string, unknown>)) {
    unregisterRetainedAlias(target);
    return;
  }
  throw new Error('Telemetry burn could not scrub immutable retained audit record.');
}

function notifyHardBurnListeners(): void {
  const { hardBurnListeners } = getRealmState();
  for (const listener of [...hardBurnListeners]) {
    try {
      listener();
    } catch {
      // Non-fatal listener failure must not abort burn cleanup
    }
  }
}

let isHardBurnActive = false;

function executeHardBurn(skipManager?: unknown, localCleanup?: () => void): void {
  const wasBurned = recordRealmHardBurn();
  if (isHardBurnActive) {
    return;
  }
  isHardBurnActive = true;
  let firstError: unknown;
  let hasError = false;
  try {
    if (localCleanup) {
      try {
        localCleanup();
      } catch (err) {
        firstError = err;
        hasError = true;
      }
    }
    const { liveManagerRefs, liveManagerWipers } = getRealmState();
    const managerWipe = wipeWeakTargetRegistry(liveManagerRefs, liveManagerWipers, skipManager);
    if (managerWipe.hasError && !hasError) {
      firstError = managerWipe.firstError;
      hasError = true;
    }
    const exporterWipe = wipeLiveExporters();
    if (exporterWipe.hasError && !hasError) {
      firstError = exporterWipe.firstError;
      hasError = true;
    }
    const aliasWipe = wipeRetainedAliases();
    if (aliasWipe.hasError && !hasError) {
      firstError = aliasWipe.firstError;
      hasError = true;
    }
  } finally {
    isHardBurnActive = false;
  }
  if (!wasBurned) {
    notifyHardBurnListeners();
  }
  if (hasError) {
    throw firstError;
  }
}

/**
 * Records an irreversible process-realm hard-burn tombstone and notifies active hooks.
 */
export function markHardBurned(): void {
  executeHardBurn();
}

/**
 * Registers a synchronous listener notified whenever a TelemetryManager executes burn().
 * Returns an unsubscribe callback.
 */
export function onHardBurn(listener: () => void): () => void {
  const { hardBurnListeners } = getRealmState();
  hardBurnListeners.add(listener);
  return () => {
    hardBurnListeners.delete(listener);
  };
}

interface PendingSpanCapture {
  safeName: string;
  sanitizedAttrs: Record<string, string | number | boolean> | null;
  cleared: boolean;
  ref?: WeakRef<PendingSpanCapture>;
}

export class TelemetryManager {
  private config: TelemetryConfig;
  private readonly otlpProvisionedAtInit: boolean;
  private memoryExporter: MemoryExporter;
  private auditLog: SessionAuditEvent[] = [];
  private isBurned = false;
  private sanitizer: (
    attrs: Record<string, unknown>,
    allowRawPayloads?: boolean
  ) => Record<string, string | number | boolean>;
  private readonly normalizedCustomDomains?: ReadonlyMap<string, ReadonlySet<string>>;
  private readonly issuedAuditRecordRefs = new Set<WeakRef<SessionAuditEvent>>();
  private readonly issuedAuditRecordFinalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<SessionAuditEvent>>((ref) => {
          this.issuedAuditRecordRefs.delete(ref);
        })
      : undefined;
  private readonly issuedAuditDetailsRefs = new Set<WeakRef<Record<string, unknown>>>();
  private readonly issuedAuditDetailsFinalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<Record<string, unknown>>>((ref) => {
          this.issuedAuditDetailsRefs.delete(ref);
        })
      : undefined;
  private readonly pendingSpanCaptureRefs = new Set<WeakRef<PendingSpanCapture>>();
  private readonly pendingSpanCaptureFinalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<PendingSpanCapture>>((ref) => {
          this.pendingSpanCaptureRefs.delete(ref);
        })
      : undefined;
  public readonly allowlist: ReadonlySet<string>;

  constructor(
    customConfig?: Partial<TelemetryConfig>,
    additionalAllowlistKeys?: Iterable<string>,
    customValueDomains?: CustomValueDomains
  ) {
    let envEndpoint: string | undefined;
    try {
      // Direct literal AST expression allows bundlers (Vite/Rollup) to perform compile-time dead-code elimination
      envEndpoint = import.meta.env.VITE_OTEL_EXPORTER_OTLP_ENDPOINT;
    } catch {
      // Fallback for non-ESM runtimes
    }

    if (!envEndpoint) {
      const globalObj =
        typeof globalThis !== 'undefined'
          ? (globalThis as unknown as { process?: { env?: Record<string, string> } })
          : undefined;
      envEndpoint = globalObj?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;
    }

    const defaultMode: TelemetryMode = envEndpoint ? 'otlp' : 'memory_only';

    const merged: TelemetryConfig = {
      mode: defaultMode,
      otlpEndpoint: envEndpoint || null,
      allowRawPayloads: false,
      burnEnabled: true,
      auditDurable: false,
      networkEgress: defaultMode === 'otlp' ? 'allow_otlp' : 'deny',
      serviceName: 'knowthankyew-app',
      ...customConfig,
    };
    if (customConfig?.networkEgress === undefined) {
      merged.networkEgress =
        merged.mode === 'otlp' && merged.otlpEndpoint ? 'allow_otlp' : 'deny';
    }
    this.config = merged;
    this.otlpProvisionedAtInit = Boolean(
      merged.mode === 'otlp' && merged.otlpEndpoint && merged.networkEgress === 'allow_otlp'
    );

    // Snapshot caller customValueDomains once so export-time serialization never re-reads untrusted getters/iterators.
    this.normalizedCustomDomains = normalizeCustomValueDomains(customValueDomains);
    const { allowlist, sanitize } = createAllowlistSanitizer(
      additionalAllowlistKeys,
      this.normalizedCustomDomains
    );
    this.allowlist = allowlist;
    this.sanitizer = sanitize;
    this.memoryExporter = new MemoryExporter();
    if (isHardBurned()) {
      this.isBurned = true;
    }
    const { liveManagerRefs, liveManagerFinalizer, liveManagerWipers } = getRealmState();
    const ref = createWeakRef<object>(this);
    liveManagerRefs.add(ref);
    liveManagerFinalizer?.register(this, ref);
    liveManagerWipers.set(this, TelemetryManager.wipeInstance);
  }

  private static wipeInstance(target: object): void {
    if (target instanceof TelemetryManager) {
      target.isBurned = true;
      target.scrubAllStorage();
    }
  }

  private isScrubbingStorage = false;

  private scrubAllStorage(): void {
    if (this.isScrubbingStorage) {
      return;
    }
    this.isScrubbingStorage = true;
    let firstError: unknown;
    let hasError = false;
    try {
      try {
        this.clearPendingSpanCaptures();
      } catch (err) {
        if (!hasError) {
          firstError = err;
          hasError = true;
        }
      }
      try {
        this.clearAuditLogStorage();
      } catch (err) {
        if (!hasError) {
          firstError = err;
          hasError = true;
        }
      }
      try {
        this.memoryExporter.clear();
      } catch (err) {
        if (!hasError) {
          firstError = err;
          hasError = true;
        }
      }
      if (hasError) {
        throw firstError;
      }
    } finally {
      this.isScrubbingStorage = false;
    }
  }

  private clearAuditLogStorage(): void {
    const previous = this.auditLog;
    this.auditLog = [];
    let allScrubbed = true;
    let firstError: unknown;
    let hasError = false;
    const recordError = (err: unknown) => {
      allScrubbed = false;
      if (!hasError) {
        firstError = err;
        hasError = true;
      }
    };

    for (const entry of previous) {
      try {
        const res = scrubAuditEventRecord(entry);
        if (!res.ok) {
          allScrubbed = false;
        }
        if (res.error !== undefined) {
          recordError(res.error);
        }
      } catch (err) {
        recordError(err);
      }
    }
    try {
      previous.length = 0;
    } catch {
      // Defensive guard if any alias is non-writable/frozen.
    }
    for (const ref of [...this.issuedAuditRecordRefs]) {
      const copy = ref.deref();
      if (!copy) {
        this.issuedAuditRecordRefs.delete(ref);
        continue;
      }
      try {
        const res = scrubAuditEventRecord(copy);
        if (res.ok && res.error === undefined) {
          this.issuedAuditRecordRefs.delete(ref);
          this.issuedAuditRecordFinalizer?.unregister(copy);
          unregisterRetainedAlias(copy);
        } else {
          allScrubbed = false;
          if (res.error !== undefined) {
            recordError(res.error);
          }
        }
      } catch (err) {
        recordError(err);
      }
    }
    for (const ref of [...this.issuedAuditDetailsRefs]) {
      const details = ref.deref();
      if (!details) {
        this.issuedAuditDetailsRefs.delete(ref);
        continue;
      }
      try {
        if (scrubRecordEntries(details)) {
          this.issuedAuditDetailsRefs.delete(ref);
          this.issuedAuditDetailsFinalizer?.unregister(details);
          unregisterRetainedAlias(details);
        } else {
          allScrubbed = false;
        }
      } catch (err) {
        recordError(err);
      }
    }
    if (hasError) {
      throw firstError;
    }
    if (!allScrubbed) {
      throw new Error('Telemetry burn could not scrub immutable retained audit record.');
    }
  }

  private scrubPendingSpanCapture(capture: PendingSpanCapture): void {
    if (capture.ref) {
      this.pendingSpanCaptureRefs.delete(capture.ref);
      capture.ref = undefined;
    }
    this.pendingSpanCaptureFinalizer?.unregister(capture);
    if (capture.cleared) return;
    capture.cleared = true;
    capture.safeName = '[REDACTED_SPAN_NAME]';
    const attrsToScrub = capture.sanitizedAttrs;
    capture.sanitizedAttrs = null;
    if (attrsToScrub && !scrubRecordEntries(attrsToScrub)) {
      throw new Error('Telemetry burn could not scrub immutable pending span attributes.');
    }
  }

  private clearPendingSpanCaptures(): void {
    let firstError: unknown;
    let hasError = false;
    for (const ref of [...this.pendingSpanCaptureRefs]) {
      const capture = ref.deref();
      if (!capture) {
        this.pendingSpanCaptureRefs.delete(ref);
        continue;
      }
      try {
        this.scrubPendingSpanCapture(capture);
      } catch (err) {
        if (!hasError) {
          firstError = err;
          hasError = true;
        }
      }
    }
    if (hasError) {
      throw firstError;
    }
  }

  private createPendingSpanHandle(
    spanId: string,
    startTime: number,
    capture: PendingSpanCapture,
    clearCapture: () => void
  ): {
    spanId: string;
    end: (status?: 'OK' | 'ERROR', extraAttrs?: Record<string, unknown>) => void;
  } {
    return {
      spanId,
      end: (status: 'OK' | 'ERROR' = 'OK', extraAttrs: Record<string, unknown> = {}) => {
        try {
          if (this.isDisabledOrTombstoned() || capture.cleared) return;

          const endTime = Date.now();
          const safeStatus: SpanRecord['status'] =
            status === 'OK' || status === 'ERROR' || status === 'UNSET' ? status : 'UNSET';
          // Evaluate extraAttrs before resolving activeSafeName because an attribute getter can narrow
          // allowRawPayloads to false (re-sanitizing start-time name and attrs under the active policy).
          const finalAttrs = this.sanitizeAttributes({
            ...(capture.sanitizedAttrs ?? {}),
            ...this.sanitizeAttributes(extraAttrs),
          });
          // Recheck disabled mode and tombstone after sanitizing extraAttrs in case an attribute getter
          // called updateConfig({ mode: 'disabled' }), burn(), or markHardBurned().
          if (this.isDisabledOrTombstoned() || capture.cleared) return;
          const activeSafeName = sanitizeSpanName(capture.safeName, this.config.allowRawPayloads);

          const spanRecord: SpanRecord = {
            id: spanId,
            name: activeSafeName,
            startTime,
            endTime,
            durationMs: endTime - startTime,
            status: safeStatus,
            attributes: finalAttrs,
            events: [],
          };

          (
            this.memoryExporter as unknown as {
              [EXPORT_OWNED_SPAN_SYMBOL](span: SpanRecord): void;
            }
          )[EXPORT_OWNED_SPAN_SYMBOL](spanRecord);

          if (
            this.otlpProvisionedAtInit &&
            this.config.mode === 'otlp' &&
            this.config.otlpEndpoint &&
            this.config.networkEgress === 'allow_otlp'
          ) {
            exportToOtlp(
              this.config.otlpEndpoint,
              spanRecord,
              this.config.serviceName,
              (attrs) => this.sanitizeAttributes(attrs),
              this.config.allowRawPayloads,
              this.allowlist,
              this.normalizedCustomDomains,
              () =>
                this.isTombstoned() ||
                this.config.mode !== 'otlp' ||
                !this.config.otlpEndpoint ||
                this.config.networkEgress !== 'allow_otlp'
            );
          }
        } finally {
          clearCapture();
        }
      },
    };
  }

  private isTombstoned(): boolean {
    return this.isBurned || isHardBurned();
  }

  private isDisabledOrTombstoned(): boolean {
    return this.config.mode === 'disabled' || this.isTombstoned() || this.isScrubbingStorage;
  }

  public getConfig(): Readonly<TelemetryConfig> {
    return this.config;
  }

  public updateConfig(newConfig: Partial<TelemetryConfig>): void {
    this.config = { ...this.config, ...newConfig };
    if (this.config.otlpEndpoint && this.config.mode === 'memory_only') {
      this.config.mode = 'otlp';
      if (newConfig.networkEgress === 'allow_otlp') {
        this.config.networkEgress = 'allow_otlp';
      }
    }
  }

  public sanitizeAttributes(
    attrs: Record<string, unknown>
  ): Record<string, string | number | boolean> {
    return this.sanitizer(attrs, this.config.allowRawPayloads);
  }

  public startSpan(
    name: string,
    attributes: Record<string, unknown> = {}
  ): {
    spanId: string;
    end: (status?: 'OK' | 'ERROR', extraAttrs?: Record<string, unknown>) => void;
  } {
    if (this.isDisabledOrTombstoned()) {
      return {
        spanId: 'noop',
        end: () => {},
      };
    }

    const spanId = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const startTime = Date.now();
    const initialAllowRawPayloads = this.config.allowRawPayloads;
    let safeName = sanitizeSpanName(name, initialAllowRawPayloads);
    let sanitizedAttrs = this.sanitizeAttributes(attributes);
    if (this.isDisabledOrTombstoned()) {
      scrubRecordEntries(sanitizedAttrs);
      return {
        spanId: 'noop',
        end: () => {},
      };
    }
    if (this.config.allowRawPayloads !== initialAllowRawPayloads) {
      safeName = sanitizeSpanName(name, this.config.allowRawPayloads);
      sanitizedAttrs = this.sanitizeAttributes(sanitizedAttrs);
      if (this.isDisabledOrTombstoned()) {
        scrubRecordEntries(sanitizedAttrs);
        return {
          spanId: 'noop',
          end: () => {},
        };
      }
    }

    const capture: PendingSpanCapture = {
      safeName,
      sanitizedAttrs,
      cleared: false,
    };
    const captureRef = createWeakRef(capture);
    capture.ref = captureRef;
    this.pendingSpanCaptureRefs.add(captureRef);
    this.pendingSpanCaptureFinalizer?.register(capture, captureRef, capture);
    const clearCapture = () => {
      this.scrubPendingSpanCapture(capture);
    };

    return this.createPendingSpanHandle(spanId, startTime, capture, clearCapture);
  }

  public recordAuditEvent(
    action: SessionAuditEvent['action'],
    summary: string,
    details?: Record<string, unknown>
  ): void {
    if (this.isTombstoned() || this.isScrubbingStorage) return;

    const initialAllowRawPayloads = this.config.allowRawPayloads;
    let sanitizedDetails = details ? this.sanitizeAttributes(details) : undefined;
    // Recheck after sanitizing untrusted inputs in case an attribute getter invoked burn(),
    // reset(), markHardBurned(), or updateConfig({ allowRawPayloads: false }).
    if (this.isTombstoned() || this.isScrubbingStorage) {
      if (sanitizedDetails) {
        scrubRecordEntries(sanitizedDetails);
      }
      return;
    }
    if (sanitizedDetails && this.config.allowRawPayloads !== initialAllowRawPayloads) {
      sanitizedDetails = this.sanitizeAttributes(sanitizedDetails);
      if (this.isTombstoned() || this.isScrubbingStorage) {
        scrubRecordEntries(sanitizedDetails);
        return;
      }
    }

    const hasCatalogAction = Object.prototype.hasOwnProperty.call(
      AUDIT_EVENT_SUMMARY_CATALOG,
      action
    );
    const safeAction = this.config.allowRawPayloads
      ? action.length > 128
        ? formatTruncatedDigest(action)
        : action
      : hasCatalogAction
        ? action
        : '[REDACTED_ACTION]';
    const safeSummary = this.config.allowRawPayloads
      ? summary.length > 256
        ? formatTruncatedDigest(summary)
        : summary
      : hasCatalogAction
        ? AUDIT_EVENT_SUMMARY_CATALOG[action]
        : '[REDACTED_AUDIT_SUMMARY]';

    this.auditLog.push({
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      action: safeAction,
      summary: safeSummary,
      details: sanitizedDetails,
    });
    while (this.auditLog.length > MAX_AUDIT_LOG_CAPACITY) {
      this.auditLog.shift();
    }
  }

  public getBufferedSpans(): readonly SpanRecord[] {
    return this.memoryExporter.getSpans();
  }

  public getMemorySpans(): readonly SpanRecord[] {
    return this.memoryExporter.getSpans();
  }

  public getAuditLog(): readonly SessionAuditEvent[] {
    if (this.isTombstoned() || this.isScrubbingStorage) {
      return [];
    }
    return this.auditLog.map((entry) => {
      const detailsCopy = entry.details ? { ...entry.details } : undefined;
      if (detailsCopy) {
        const detailsRef = createWeakRef(detailsCopy as Record<string, unknown>);
        this.issuedAuditDetailsRefs.add(detailsRef);
        this.issuedAuditDetailsFinalizer?.register(detailsCopy, detailsRef, detailsCopy);
        registerRetainedAlias(detailsCopy, wipeRetainedAuditDetails);
      }
      const copy: SessionAuditEvent = {
        ...entry,
        ...(detailsCopy ? { details: detailsCopy } : {}),
      };
      const ref = createWeakRef(copy);
      this.issuedAuditRecordRefs.add(ref);
      this.issuedAuditRecordFinalizer?.register(copy, ref, copy);
      registerRetainedAlias(copy, wipeRetainedAuditEntry);
      return copy;
    });
  }

  public downloadSessionAuditJson(): string {
    const events = this.isTombstoned() || this.isScrubbingStorage ? [] : this.auditLog;
    const exportData = {
      generatedAt: new Date().toISOString(),
      service: this.config.serviceName || 'knowthankyew-app',
      telemetryMode: this.config.mode,
      eventCount: events.length,
      events,
    };
    return JSON.stringify(exportData, null, 2);
  }

  public getPrivacyAuditReport(): PrivacyAuditReport {
    const isHonestLocal =
      this.config.mode !== 'otlp' &&
      !this.config.otlpEndpoint &&
      this.config.networkEgress === 'deny';

    return {
      telemetryMode: this.config.mode,
      networkEgress: this.config.networkEgress,
      burnEnabled: this.config.burnEnabled,
      durableAudit: this.config.auditDurable,
      otlpEndpoint: this.config.otlpEndpoint || null,
      allowRawPayloads: this.config.allowRawPayloads,
      activeSpanCount: this.memoryExporter.count(),
      sessionAuditCount: this.auditLog.length,
      isLocalOnlyHonest: isHonestLocal,
    };
  }

  public getPrivacyClaims(branding?: PrivacyClaimsBranding): PrivacyClaims {
    return getPrivacyClaims(this.getPrivacyAuditReport(), branding);
  }

  public burn(): void {
    if (!this.config.burnEnabled) return;

    this.isBurned = true;
    executeHardBurn(this, () => this.scrubAllStorage());
  }

  public reset(): void {
    try {
      this.scrubAllStorage();
    } finally {
      this.isBurned = this.isBurned || isHardBurned();
    }
  }

  public restartSession(): void {
    this.reset();
  }
}
