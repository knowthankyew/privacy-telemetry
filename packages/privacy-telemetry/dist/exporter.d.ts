/**
 * Exporters for Privacy Telemetry
 *
 * 1. MemoryExporter: Retains spans purely in volatile in-memory storage.
 * 2. exportToOtlp: Sends scrubbed spans to configured OTLP endpoints in enterprise mode.
 */
import { SpanRecord } from './types.js';
export declare class MemoryExporter {
    private spans;
    private readonly maxCapacity;
    constructor(maxCapacity?: number);
    export(span: SpanRecord): void;
    getSpans(): readonly SpanRecord[];
    clear(): void;
    count(): number;
}
export declare function exportToOtlp(endpoint: string, span: SpanRecord, serviceName?: string): Promise<void>;
//# sourceMappingURL=exporter.d.ts.map