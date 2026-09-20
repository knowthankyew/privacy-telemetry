/**
 * Exporters for Privacy Telemetry
 * 
 * 1. MemoryExporter: Retains spans purely in volatile in-memory storage.
 * 2. exportToOtlp: Sends scrubbed spans to configured OTLP endpoints in enterprise mode.
 */

import { SpanRecord } from './types.js';

export class MemoryExporter {
  private spans: SpanRecord[] = [];
  private readonly maxCapacity: number;

  constructor(maxCapacity = 500) {
    this.maxCapacity = maxCapacity;
  }

  export(span: SpanRecord): void {
    this.spans.push(span);
    if (this.spans.length > this.maxCapacity) {
      this.spans.shift();
    }
  }

  getSpans(): readonly SpanRecord[] {
    return this.spans;
  }

  clear(): void {
    this.spans = [];
  }

  count(): number {
    return this.spans.length;
  }
}

export async function exportToOtlp(
  endpoint: string,
  span: SpanRecord,
  serviceName = 'knowthankyew-app'
): Promise<void> {
  if (typeof fetch === 'undefined') return;

  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        resourceSpans: [
          {
            resource: {
              attributes: [{ key: 'service.name', value: { stringValue: serviceName } }],
            },
            scopeSpans: [
              {
                spans: [
                  {
                    traceId: span.id,
                    spanId: span.id,
                    name: span.name,
                    startTimeUnixNano: span.startTime * 1_000_000,
                    endTimeUnixNano: (span.endTime || span.startTime) * 1_000_000,
                    attributes: Object.entries(span.attributes).map(([key, val]) => ({
                      key,
                      value:
                        typeof val === 'string'
                          ? { stringValue: val }
                          : typeof val === 'number'
                          ? { intValue: val }
                          : { boolValue: val },
                    })),
                    status: {
                      code: span.status === 'OK' ? 1 : span.status === 'ERROR' ? 2 : 0,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    });
  } catch {
    // Fail-safe: silently swallow telemetry transmission errors to preserve app continuity
  }
}
