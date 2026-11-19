/**
 * Exporters for Privacy Telemetry
 *
 * 1. MemoryExporter: Retains spans purely in volatile in-memory storage.
 * 2. exportToOtlp: Sends scrubbed spans to configured OTLP endpoints in enterprise mode.
 */
import { SpanRecord } from './types.js';
import { CustomValueDomains } from './allowlist.js';
import { EXPORT_OWNED_SPAN_SYMBOL } from './tombstone.js';
export declare function scrubRecordEntries(record: Record<string, unknown>): boolean;
export declare function scrubObjectField<T extends object, K extends keyof T>(target: T, key: K, redactedValue: T[K]): boolean;
export declare function replaceAccessorWithDataProperty<T extends object, K extends keyof T>(target: T, key: K, replacement: T[K]): boolean;
export interface ScrubResult {
    ok: boolean;
    error?: unknown;
}
export interface MemoryExporterOptions {
    allowRawPayloads?: boolean;
    additionalKeys?: Iterable<string>;
    customValueDomains?: CustomValueDomains;
}
export declare class MemoryExporter {
    private spans;
    private readonly maxCapacity;
    private readonly allowRawPayloads;
    private readonly sanitizer;
    private isClearing;
    private readonly spanArrayTracker;
    private readonly spanTracker;
    private readonly eventArrayTracker;
    private readonly eventTracker;
    private readonly childRecordTracker;
    constructor(maxCapacity?: number, options?: MemoryExporterOptions);
    private hasRetainedState;
    private trackSpanChildren;
    private trackSpanRecord;
    private enqueueSpan;
    private sanitizeStandaloneSpan;
    export(span: SpanRecord, options?: {
        allowRawPayloads?: boolean;
    }): void;
    [EXPORT_OWNED_SPAN_SYMBOL](span: SpanRecord): void;
    getSpans(): readonly SpanRecord[];
    clear(): void;
    count(): number;
}
export declare function exportToOtlp(endpoint: string, span: SpanRecord, serviceName?: string, sanitizeAttributes?: (attrs: Record<string, unknown>) => Record<string, string | number | boolean>, allowRawPayloads?: boolean, allowedKeys?: Iterable<string>, customValueDomains?: CustomValueDomains, shouldAbort?: () => boolean): Promise<void>;
//# sourceMappingURL=exporter.d.ts.map