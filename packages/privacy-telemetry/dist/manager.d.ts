/**
 * TelemetryManager - Lifecycle coordinator for in-memory and enterprise telemetry
 */
import { TelemetryConfig, SpanRecord, SessionAuditEvent, PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding } from './types.js';
export declare class TelemetryManager {
    private config;
    private memoryExporter;
    private auditLog;
    private isBurned;
    private sanitizer;
    readonly allowlist: ReadonlySet<string>;
    constructor(customConfig?: Partial<TelemetryConfig>, additionalAllowlistKeys?: Iterable<string>);
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