/**
 * TelemetryManager - Lifecycle coordinator for in-memory and enterprise telemetry
 */
import { TelemetryConfig, SpanRecord, SessionAuditEvent, PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding } from './types.js';
import { CustomValueDomains } from './allowlist.js';
import { isHardBurned } from './tombstone.js';
export { isHardBurned };
/**
 * Records an irreversible process-realm hard-burn tombstone and notifies active hooks.
 */
export declare function markHardBurned(): void;
/**
 * Registers a synchronous listener notified whenever a TelemetryManager executes burn().
 * Returns an unsubscribe callback.
 */
export declare function onHardBurn(listener: () => void): () => void;
export declare class TelemetryManager {
    private config;
    private readonly otlpProvisionedAtInit;
    private memoryExporter;
    private auditLog;
    private isBurned;
    private sanitizer;
    private readonly normalizedCustomDomains?;
    private readonly issuedAuditRecordRefs;
    private readonly issuedAuditRecordFinalizer;
    private readonly issuedAuditDetailsRefs;
    private readonly issuedAuditDetailsFinalizer;
    private readonly pendingSpanCaptureRefs;
    private readonly pendingSpanCaptureFinalizer;
    readonly allowlist: ReadonlySet<string>;
    constructor(customConfig?: Partial<TelemetryConfig>, additionalAllowlistKeys?: Iterable<string>, customValueDomains?: CustomValueDomains);
    private static wipeInstance;
    private isScrubbingStorage;
    private scrubAllStorage;
    private clearAuditLogStorage;
    private scrubPendingSpanCapture;
    private clearPendingSpanCaptures;
    private createPendingSpanHandle;
    private isTombstoned;
    private isDisabledOrTombstoned;
    getConfig(): Readonly<TelemetryConfig>;
    updateConfig(newConfig: Partial<TelemetryConfig>): void;
    sanitizeAttributes(attrs: Record<string, unknown>): Record<string, string | number | boolean>;
    startSpan(name: string, attributes?: Record<string, unknown>): {
        spanId: string;
        end: (status?: 'OK' | 'ERROR', extraAttrs?: Record<string, unknown>) => void;
    };
    recordAuditEvent(action: SessionAuditEvent['action'], summary: string, details?: Record<string, unknown>): void;
    getBufferedSpans(): readonly SpanRecord[];
    getMemorySpans(): readonly SpanRecord[];
    getAuditLog(): readonly SessionAuditEvent[];
    downloadSessionAuditJson(): string;
    getPrivacyAuditReport(): PrivacyAuditReport;
    getPrivacyClaims(branding?: PrivacyClaimsBranding): PrivacyClaims;
    burn(): void;
    reset(): void;
    restartSession(): void;
}
//# sourceMappingURL=manager.d.ts.map