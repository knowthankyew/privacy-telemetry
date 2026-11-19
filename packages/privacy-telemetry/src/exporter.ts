/**
 * Exporters for Privacy Telemetry
 * 
 * 1. MemoryExporter: Retains spans purely in volatile in-memory storage.
 * 2. exportToOtlp: Sends scrubbed spans to configured OTLP endpoints in enterprise mode.
 */

import { SpanRecord } from './types.js';
import {
  CustomValueDomains,
  DEFAULT_SAFE_ALLOWLIST_KEYS,
  REDACTED_NOT_ALLOWLISTED,
  REDACTED_SENSITIVE_VALUE,
  REDACTED_UNALLOWLISTED_KEY,
  createAllowlistSanitizer,
  formatTruncatedDigest,
  isCollectorBoundaryExcludedKey,
  sanitizeAllowlistedStringValue,
  sanitizeSpanName,
} from './allowlist.js';
import {
  EXPORT_OWNED_SPAN_SYMBOL,
  isHardBurned,
  registerLiveExporter,
  registerRetainedAlias,
  unregisterRetainedAlias,
} from './tombstone.js';
import { sha256Hex } from './sha256.js';

const TRACE_ID_HEX_REGEX = /^[0-9a-f]{32}$/;
const SPAN_ID_HEX_REGEX = /^[0-9a-f]{16}$/;
const ALL_ZERO_TRACE_ID = '00000000000000000000000000000000';
const ALL_ZERO_SPAN_ID = '0000000000000000';

function toOtlpIdentifiers(rawId: string): { traceId: string; spanId: string } {
  const trimmed = typeof rawId === 'string' ? rawId.trim() : '';
  const lower = trimmed.toLowerCase();
  let traceId =
    TRACE_ID_HEX_REGEX.test(lower) && lower !== ALL_ZERO_TRACE_ID
      ? lower
      : sha256Hex(`kty:trace:${trimmed || 'fallback'}`).slice(0, 32);
  if (traceId === ALL_ZERO_TRACE_ID) {
    traceId = '00000000000000000000000000000001';
  }

  let spanId =
    SPAN_ID_HEX_REGEX.test(lower) && lower !== ALL_ZERO_SPAN_ID
      ? lower
      : sha256Hex(`kty:span:${trimmed || 'fallback'}`).slice(0, 16);
  if (spanId === ALL_ZERO_SPAN_ID) {
    spanId = '0000000000000001';
  }

  if (
    !TRACE_ID_HEX_REGEX.test(traceId) ||
    traceId === ALL_ZERO_TRACE_ID ||
    !SPAN_ID_HEX_REGEX.test(spanId) ||
    spanId === ALL_ZERO_SPAN_ID
  ) {
    throw new Error('Invalid OTLP trace or span identifier');
  }

  return { traceId, spanId };
}

function toOtlpAttributeValue(val: unknown): Record<string, unknown> {
  if (typeof val === 'string') return { stringValue: val };
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return { stringValue: REDACTED_SENSITIVE_VALUE };
    return Number.isSafeInteger(val) ? { intValue: val } : { doubleValue: val };
  }
  if (typeof val === 'boolean') return { boolValue: val };
  if (Array.isArray(val)) {
    return {
      arrayValue: {
        values: val.map((item) => toOtlpAttributeValue(item)),
      },
    };
  }
  return { stringValue: REDACTED_SENSITIVE_VALUE };
}

const defaultSanitizerPair = createAllowlistSanitizer();

export function scrubRecordEntries(record: Record<string, unknown>): boolean {
  let allCleared = true;
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch {
    return false;
  }
  const recordView = record as Record<PropertyKey, unknown>;
  for (const key of keys) {
    try {
      const desc = Object.getOwnPropertyDescriptor(record, key);
      if (!desc) {
        continue;
      }
      let deleted = false;
      if (desc.configurable) {
        try {
          deleted = Reflect.deleteProperty(record, key);
        } catch {
          deleted = false;
        }
      }
      if (!deleted) {
        const isAlreadyMarker =
          'value' in desc &&
          (desc.value === REDACTED_SENSITIVE_VALUE ||
            desc.value === REDACTED_NOT_ALLOWLISTED);
        if (!isAlreadyMarker) {
          try {
            recordView[key] = REDACTED_SENSITIVE_VALUE;
          } catch {
            allCleared = false;
          }
        }
      }
      const afterDesc = Object.getOwnPropertyDescriptor(record, key);
      if (afterDesc) {
        const hasRedactedValue =
          'value' in afterDesc &&
          (afterDesc.value === REDACTED_SENSITIVE_VALUE ||
            afterDesc.value === REDACTED_NOT_ALLOWLISTED);
        const hasSafeRetainedKey =
          typeof key === 'string' &&
          (key === REDACTED_UNALLOWLISTED_KEY ||
            DEFAULT_SAFE_ALLOWLIST_KEYS.has(key));
        if (!hasRedactedValue || !hasSafeRetainedKey) {
          allCleared = false;
        }
      }
    } catch {
      allCleared = false;
    }
  }
  return allCleared;
}

export function scrubObjectField<T extends object, K extends keyof T>(
  target: T,
  key: K,
  redactedValue: T[K]
): boolean {
  try {
    const desc = Object.getOwnPropertyDescriptor(target, key);
    if (desc && 'value' in desc && desc.value === redactedValue) {
      return true;
    }
    if (desc && ('get' in desc || 'set' in desc)) {
      if (desc.configurable && replaceAccessorWithDataProperty(target, key, redactedValue)) {
        return true;
      }
      if (typeof desc.get === 'function') {
        void target[key];
      }
      if (typeof desc.set === 'function') {
        target[key] = redactedValue;
      }
      return replaceAccessorWithDataProperty(target, key, redactedValue);
    }
    target[key] = redactedValue;
    const afterDesc = Object.getOwnPropertyDescriptor(target, key);
    if (afterDesc && 'value' in afterDesc) {
      return afterDesc.value === redactedValue;
    }
    if (!replaceAccessorWithDataProperty(target, key, redactedValue)) {
      return false;
    }
    return target[key] === redactedValue;
  } catch {
    return false;
  }
}

export function replaceAccessorWithDataProperty<T extends object, K extends keyof T>(
  target: T,
  key: K,
  replacement: T[K]
): boolean {
  try {
    const desc = Object.getOwnPropertyDescriptor(target, key);
    const isOwnAccessor = Boolean(desc && ('get' in desc || 'set' in desc));
    const isInherited = !desc && key in target;
    if (!isOwnAccessor && !isInherited) {
      return true;
    }
    Object.defineProperty(target, key, {
      value: replacement,
      writable: true,
      enumerable: desc ? (desc.enumerable ?? true) : true,
      configurable: true,
    });
    const afterDesc = Object.getOwnPropertyDescriptor(target, key);
    return Boolean(
      afterDesc &&
        'value' in afterDesc &&
        afterDesc.value === replacement
    );
  } catch {
    return false;
  }
}

export interface ScrubResult {
  ok: boolean;
  error?: unknown;
}

type SpanEventRecord = SpanRecord['events'][number];

function scrubSpanEvent(
  evt: SpanEventRecord,
  onError?: (err: unknown) => void
): boolean {
  if (!evt || typeof evt !== 'object') {
    return true;
  }
  let ok = true;
  try {
    const evtAttrs = evt.attributes;
    if (evtAttrs && typeof evtAttrs === 'object') {
      if (!scrubRecordEntries(evtAttrs)) {
        ok = false;
      }
    }
    if (!replaceAccessorWithDataProperty(evt, 'attributes', {})) {
      ok = false;
    }
  } catch (err) {
    ok = false;
    onError?.(err);
  }
  if (!scrubObjectField(evt, 'name', '[REDACTED]')) {
    ok = false;
  }
  if (!scrubObjectField(evt, 'timestamp', 0)) {
    ok = false;
  }
  return ok;
}

function scrubEventArray(
  events: SpanEventRecord[],
  onError?: (err: unknown) => void
): boolean {
  let ok = true;
  let len = 0;
  try {
    len = events.length;
  } catch (err) {
    onError?.(err);
    return false;
  }
  for (let i = 0; i < len; i++) {
    try {
      const evt = events[i];
      if (!scrubSpanEvent(evt, onError)) {
        ok = false;
      }
    } catch (err) {
      ok = false;
      onError?.(err);
    }
  }
  try {
    events.length = 0;
  } catch {
    try {
      if (events.length > 0 && !ok) {
        ok = false;
      }
    } catch (err) {
      ok = false;
      onError?.(err);
    }
  }
  return ok;
}

function scrubSpanRecord(span: SpanRecord): ScrubResult {
  let ok = true;
  let firstError: unknown;
  const recordError = (err: unknown) => {
    ok = false;
    if (firstError === undefined) {
      firstError = err;
    }
  };

  try {
    const attrs = span.attributes;
    if (attrs && typeof attrs === 'object') {
      if (!scrubRecordEntries(attrs as Record<string, unknown>)) {
        ok = false;
      }
    }
    if (!replaceAccessorWithDataProperty(span, 'attributes', {})) {
      ok = false;
    }
  } catch (err) {
    recordError(err);
  }

  try {
    const events = span.events;
    if (Array.isArray(events) && !scrubEventArray(events, recordError)) {
      ok = false;
    }
    if (!replaceAccessorWithDataProperty(span, 'events', [])) {
      ok = false;
    }
  } catch (err) {
    recordError(err);
  }

  if (!scrubObjectField(span, 'name', '[REDACTED_SPAN_NAME]')) {
    ok = false;
  }
  if (!scrubObjectField(span, 'id', '[REDACTED]')) {
    ok = false;
  }
  if (!scrubObjectField(span, 'status', 'UNSET')) {
    ok = false;
  }
  if (!scrubObjectField(span, 'startTime', 0)) {
    ok = false;
  }
  try {
    const hasEndTime =
      Boolean(Object.getOwnPropertyDescriptor(span, 'endTime')) ||
      'endTime' in span ||
      span.endTime !== undefined;
    if (hasEndTime && !scrubObjectField(span, 'endTime', 0)) {
      ok = false;
    }
  } catch (err) {
    ok = false;
    recordError(err);
  }
  try {
    const hasDurationMs =
      Boolean(Object.getOwnPropertyDescriptor(span, 'durationMs')) ||
      'durationMs' in span ||
      span.durationMs !== undefined;
    if (hasDurationMs && !scrubObjectField(span, 'durationMs', 0)) {
      ok = false;
    }
  } catch (err) {
    ok = false;
    recordError(err);
  }

  return firstError !== undefined ? { ok: false, error: firstError } : { ok };
}

function scrubSpanArrayElements(
  arr: SpanRecord[],
  scrubSingleSpan: (span: SpanRecord) => boolean,
  recordError: (err: unknown) => void
): boolean {
  let arrClean = true;
  let len = 0;
  try {
    len = arr.length;
  } catch (err) {
    recordError(err);
    return false;
  }
  for (let i = 0; i < len; i++) {
    try {
      const span = arr[i];
      if (!scrubSingleSpan(span)) {
        arrClean = false;
      }
    } catch (err) {
      arrClean = false;
      recordError(err);
    }
  }
  try {
    arr.length = 0;
  } catch {
    // Frozen external array aliases keep element slots; rely on per-span scrubbing above.
  }
  return arrClean;
}

function wipeRetainedSpanArray(target: object): void {
  if (!Array.isArray(target)) return;
  let allScrubbed = true;
  let firstError: unknown;
  const recordError = (err: unknown) => {
    allScrubbed = false;
    if (firstError === undefined) {
      firstError = err;
    }
  };
  const clean = scrubSpanArrayElements(
    target as SpanRecord[],
    (span) => {
      const res = scrubSpanRecord(span);
      if (!res.ok) {
        allScrubbed = false;
      }
      if (res.error !== undefined && firstError === undefined) {
        firstError = res.error;
      }
      return res.ok;
    },
    recordError
  );
  if (!clean) {
    allScrubbed = false;
  }
  let remaining = -1;
  try {
    remaining = target.length;
  } catch (err) {
    recordError(err);
  }
  if (allScrubbed && remaining === 0) {
    unregisterRetainedAlias(target);
  }
  if (firstError !== undefined) {
    throw firstError;
  }
  if (!allScrubbed) {
    throw new Error('Telemetry burn could not scrub immutable retained span data.');
  }
}

function wipeRetainedSpan(target: object): void {
  const res = scrubSpanRecord(target as SpanRecord);
  if (res.ok && res.error === undefined) {
    unregisterRetainedAlias(target);
  }
  if (res.error !== undefined) {
    throw res.error;
  }
  if (!res.ok) {
    throw new Error('Telemetry burn could not scrub immutable retained span data.');
  }
}

function wipeRetainedEventArray(target: object): void {
  if (!Array.isArray(target)) return;
  let firstError: unknown;
  const recordError = (err: unknown) => {
    if (firstError === undefined) {
      firstError = err;
    }
  };
  const clean = scrubEventArray(target as SpanEventRecord[], recordError);
  let remaining = -1;
  try {
    remaining = target.length;
  } catch (err) {
    recordError(err);
  }
  if (clean && firstError === undefined && remaining === 0) {
    unregisterRetainedAlias(target);
  }
  if (firstError !== undefined) {
    throw firstError;
  }
  if (!clean) {
    throw new Error('Telemetry burn could not scrub immutable retained span data.');
  }
}

function wipeRetainedEvent(target: object): void {
  let firstError: unknown;
  const clean = scrubSpanEvent(target as SpanEventRecord, (err) => {
    if (firstError === undefined) {
      firstError = err;
    }
  });
  if (clean && firstError === undefined) {
    unregisterRetainedAlias(target);
  }
  if (firstError !== undefined) {
    throw firstError;
  }
  if (!clean) {
    throw new Error('Telemetry burn could not scrub immutable retained span data.');
  }
}

function wipeRetainedRecord(target: object): void {
  const clean = scrubRecordEntries(target as Record<string, unknown>);
  if (clean) {
    unregisterRetainedAlias(target);
    return;
  }
  throw new Error('Telemetry burn could not scrub immutable retained span data.');
}

class WeakObjectTracker<T extends object> {
  private readonly tracked = new WeakSet<T>();
  readonly refs = new Set<WeakRef<T>>();
  private readonly finalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<T>>((ref) => {
          this.refs.delete(ref);
        })
      : undefined;

  constructor(private readonly aliasWiper?: (target: object) => void) {}

  track(item: T | null | undefined): boolean {
    if (!item || typeof item !== 'object' || this.tracked.has(item)) {
      return false;
    }
    this.tracked.add(item);
    const ref = new WeakRef(item);
    this.refs.add(ref);
    this.finalizer?.register(item, ref, item);
    if (this.aliasWiper) {
      registerRetainedAlias(item, this.aliasWiper);
    }
    return true;
  }

  untrack(ref: WeakRef<T>, item?: T): void {
    this.refs.delete(ref);
    if (item) {
      this.finalizer?.unregister(item);
      this.tracked.delete(item);
      if (this.aliasWiper) {
        unregisterRetainedAlias(item);
      }
    }
  }
}

function wipeRegisteredExporter(target: object): void {
  if (target instanceof MemoryExporter) {
    target.clear();
  }
}

export interface MemoryExporterOptions {
  allowRawPayloads?: boolean;
  additionalKeys?: Iterable<string>;
  customValueDomains?: CustomValueDomains;
}

function syncSanitizedAttributesInPlace(
  target: Record<string, unknown>,
  sanitized: Record<string, string | number | boolean>
): boolean {
  const existingKeys = Reflect.ownKeys(target);
  const sanitizedEntries = Object.entries(sanitized);
  if (
    existingKeys.length === sanitizedEntries.length &&
    existingKeys.every((k) => {
      if (typeof k !== 'string' || !Object.prototype.hasOwnProperty.call(sanitized, k)) {
        return false;
      }
      const desc = Object.getOwnPropertyDescriptor(target, k);
      return Boolean(
        desc &&
          !('get' in desc) &&
          !('set' in desc) &&
          Object.is(desc.value, sanitized[k])
      );
    })
  ) {
    return true;
  }
  try {
    for (const key of existingKeys) {
      if (typeof key !== 'string' || !Object.prototype.hasOwnProperty.call(sanitized, key)) {
        if (!Reflect.deleteProperty(target, key)) {
          return false;
        }
      }
    }
    for (const [k, v] of sanitizedEntries) {
      const existingDesc = Object.getOwnPropertyDescriptor(target, k);
      if ((existingDesc && ('get' in existingDesc || 'set' in existingDesc)) || (!existingDesc && k in target)) {
        if (existingDesc && !existingDesc.configurable) {
          return false;
        }
        Object.defineProperty(target, k, {
          value: v,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      } else {
        target[k] = v;
      }
      const afterDesc = Object.getOwnPropertyDescriptor(target, k);
      if (
        !afterDesc ||
        'get' in afterDesc ||
        'set' in afterDesc ||
        !Object.is(afterDesc.value, v)
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export class MemoryExporter {
  private spans: SpanRecord[] = [];
  private readonly maxCapacity: number;
  private readonly allowRawPayloads: boolean;
  private readonly sanitizer: ReturnType<typeof createAllowlistSanitizer>;
  private isClearing = false;
  private readonly spanArrayTracker = new WeakObjectTracker<SpanRecord[]>(wipeRetainedSpanArray);
  private readonly spanTracker = new WeakObjectTracker<SpanRecord>(wipeRetainedSpan);
  private readonly eventArrayTracker = new WeakObjectTracker<SpanEventRecord[]>(wipeRetainedEventArray);
  private readonly eventTracker = new WeakObjectTracker<SpanEventRecord>(wipeRetainedEvent);
  private readonly childRecordTracker = new WeakObjectTracker<Record<string, unknown>>(wipeRetainedRecord);

  constructor(maxCapacity = 500, options?: MemoryExporterOptions) {
    this.maxCapacity = maxCapacity;
    this.allowRawPayloads = options?.allowRawPayloads === true;
    this.sanitizer = createAllowlistSanitizer(
      options?.additionalKeys,
      options?.customValueDomains
    );
    registerLiveExporter(this, wipeRegisteredExporter);
  }

  private hasRetainedState(): boolean {
    return (
      this.spans.length > 0 ||
      this.spanArrayTracker.refs.size > 0 ||
      this.spanTracker.refs.size > 0 ||
      this.eventArrayTracker.refs.size > 0 ||
      this.eventTracker.refs.size > 0 ||
      this.childRecordTracker.refs.size > 0
    );
  }

  private trackSpanChildren(span: SpanRecord): void {
    try {
      const attrs = span.attributes;
      if (attrs && typeof attrs === 'object') {
        this.childRecordTracker.track(attrs as Record<string, unknown>);
      }
    } catch {
      // Ignore throwing getters at export time; clear() will handle error propagation on burn.
    }

    try {
      const events = span.events;
      if (Array.isArray(events)) {
        this.eventArrayTracker.track(events);
        for (const evt of events) {
          if (evt && typeof evt === 'object') {
            this.eventTracker.track(evt);
            try {
              const evtAttrs = evt.attributes;
              if (evtAttrs && typeof evtAttrs === 'object') {
                this.childRecordTracker.track(evtAttrs);
              }
            } catch {
              // Ignore throwing getters at export time; clear() will handle error propagation on burn.
            }
          }
        }
      }
    } catch {
      // Ignore throwing getters at export time; clear() will handle error propagation on burn.
    }
  }

  private trackSpanRecord(span: SpanRecord): void {
    if (!span || typeof span !== 'object') {
      return;
    }
    this.spanTracker.track(span);
    this.trackSpanChildren(span);
  }

  private enqueueSpan(span: SpanRecord, trackExternalAlias: boolean): void {
    if (this.isClearing || isHardBurned()) {
      return;
    }
    if (trackExternalAlias) {
      this.trackSpanRecord(span);
      if (isHardBurned()) {
        if (this.hasRetainedState()) {
          this.clear();
        }
        return;
      }
    }
    if (!Object.isExtensible(this.spans)) {
      this.spanArrayTracker.track(this.spans);
      const copiedSpans = [...this.spans];
      if (isHardBurned()) {
        for (const copied of copiedSpans) {
          try {
            scrubSpanRecord(copied);
          } catch {
            // Best-effort cleanup of copied records if a getter triggered burn() on an immutable span.
          }
        }
        try {
          scrubSpanRecord(span);
        } catch {
          // Best-effort cleanup of incoming span after post-copy tombstone recheck.
        }
        if (this.hasRetainedState()) {
          this.clear();
        }
        return;
      }
      this.spans = copiedSpans;
    }
    this.spans.push(span);
    if (this.spans.length > this.maxCapacity) {
      this.spans.shift();
    }
  }

  private sanitizeStandaloneSpan(span: SpanRecord, allowRawPayloads: boolean): SpanRecord {
    let targetSpan = span;
    const readSafe = <T>(reader: () => T, fallback: T): T => {
      try {
        return reader();
      } catch {
        return fallback;
      }
    };
    let resolvedAttrs: Record<string, string | number | boolean> = {};
    let resolvedEvents: SpanEventRecord[] = [];
    const ensureClonedSpan = (): SpanRecord => {
      if (targetSpan === span) {
        const rawId = readSafe(() => span.id, '[REDACTED]');
        const rawName = readSafe(() => span.name, '');
        const rawStart = readSafe(() => span.startTime, 0);
        const rawEnd = readSafe(() => span.endTime, undefined);
        const rawDur = readSafe(() => span.durationMs, undefined);
        const rawStatus = readSafe(() => span.status, 'UNSET');
        targetSpan = {
          id: typeof rawId === 'string' ? rawId : '[REDACTED]',
          name: sanitizeSpanName(typeof rawName === 'string' ? rawName : '', allowRawPayloads),
          startTime: typeof rawStart === 'number' && Number.isFinite(rawStart) ? rawStart : 0,
          endTime: typeof rawEnd === 'number' && Number.isFinite(rawEnd) ? rawEnd : undefined,
          durationMs: typeof rawDur === 'number' && Number.isFinite(rawDur) ? rawDur : undefined,
          status: rawStatus === 'OK' || rawStatus === 'ERROR' || rawStatus === 'UNSET' ? rawStatus : 'UNSET',
          attributes: resolvedAttrs,
          events: resolvedEvents,
        };
        this.spanTracker.track(targetSpan);
      }
      return targetSpan;
    };

    if (allowRawPayloads) {
      try {
        const rawName = span.name;
        if (typeof rawName === 'string' && rawName.length > 256) {
          const safeRawName = sanitizeSpanName(rawName, true);
          try {
            span.name = safeRawName;
            const afterNameDesc = Object.getOwnPropertyDescriptor(span, 'name');
            if (!afterNameDesc || 'get' in afterNameDesc || afterNameDesc.value !== safeRawName) {
              ensureClonedSpan().name = safeRawName;
            }
          } catch {
            ensureClonedSpan().name = safeRawName;
          }
        }
      } catch {
        // Leave throwing name getter for clear()/burn() error handling in raw mode.
      }

      try {
        const attrDesc = Object.getOwnPropertyDescriptor(span, 'attributes');
        if (typeof attrDesc?.get !== 'function') {
          const rawAttrs = span.attributes as Record<string, unknown> | undefined;
          if (rawAttrs && typeof rawAttrs === 'object') {
            resolvedAttrs = rawAttrs as Record<string, string | number | boolean>;
            const ownKeys = Object.keys(rawAttrs);
            const hasOversizedEntry = ownKeys.some((key) => {
              const propDesc = Object.getOwnPropertyDescriptor(rawAttrs, key);
              if (typeof propDesc?.get === 'function') return false;
              const val = propDesc?.value;
              return key.length > 256 || (typeof val === 'string' && val.length > 256);
            });
            if (hasOversizedEntry) {
              const sanitizedRawAttrs = this.sanitizer.sanitize(rawAttrs, true);
              resolvedAttrs = sanitizedRawAttrs;
              if (!syncSanitizedAttributesInPlace(rawAttrs, sanitizedRawAttrs) || targetSpan !== span) {
                this.childRecordTracker.track(sanitizedRawAttrs);
                try {
                  targetSpan.attributes = sanitizedRawAttrs;
                  if (targetSpan.attributes !== sanitizedRawAttrs) {
                    ensureClonedSpan().attributes = sanitizedRawAttrs;
                  }
                } catch {
                  ensureClonedSpan().attributes = sanitizedRawAttrs;
                }
              }
            } else if (targetSpan !== span) {
              targetSpan.attributes = resolvedAttrs;
            }
          }
        }
      } catch {
        // Leave throwing attributes getter for clear()/burn() error handling in raw mode.
      }

      try {
        const eventsDesc = Object.getOwnPropertyDescriptor(span, 'events');
        if (typeof eventsDesc?.get !== 'function') {
          const rawEvents = span.events;
          if (Array.isArray(rawEvents)) {
            resolvedEvents = rawEvents;
            let needsRawEventsReplacement = false;
            const updatedRawEvents: SpanEventRecord[] = [];
            for (let i = 0; i < rawEvents.length; i++) {
              const evt = rawEvents[i];
              if (!evt || typeof evt !== 'object') {
                updatedRawEvents.push(evt);
                continue;
              }
              let evtNeedsClone = false;
              let nextEvtName = evt.name;
              if (typeof nextEvtName === 'string' && nextEvtName.length > 256) {
                nextEvtName = sanitizeSpanName(nextEvtName, true);
                try {
                  evt.name = nextEvtName;
                  const afterEvtNameDesc = Object.getOwnPropertyDescriptor(evt, 'name');
                  if (!afterEvtNameDesc || 'get' in afterEvtNameDesc || afterEvtNameDesc.value !== nextEvtName) {
                    evtNeedsClone = true;
                  }
                } catch {
                  evtNeedsClone = true;
                }
              }
              let nextEvtAttrs = evt.attributes;
              const evtAttrDesc = Object.getOwnPropertyDescriptor(evt, 'attributes');
              if (typeof evtAttrDesc?.get !== 'function' && nextEvtAttrs && typeof nextEvtAttrs === 'object') {
                const evtAttrs = nextEvtAttrs as Record<string, unknown>;
                const hasOversizedEvtAttr = Object.keys(evtAttrs).some((key) => {
                  const propDesc = Object.getOwnPropertyDescriptor(evtAttrs, key);
                  if (typeof propDesc?.get === 'function') return false;
                  const val = propDesc?.value;
                  return key.length > 256 || (typeof val === 'string' && val.length > 256);
                });
                if (hasOversizedEvtAttr) {
                  const sanitizedEvtAttrs = this.sanitizer.sanitize(evtAttrs, true);
                  nextEvtAttrs = sanitizedEvtAttrs;
                  if (!syncSanitizedAttributesInPlace(evtAttrs, sanitizedEvtAttrs)) {
                    this.childRecordTracker.track(sanitizedEvtAttrs);
                    try {
                      evt.attributes = sanitizedEvtAttrs;
                      if (evt.attributes !== sanitizedEvtAttrs) {
                        evtNeedsClone = true;
                      }
                    } catch {
                      evtNeedsClone = true;
                    }
                  }
                }
              }
              if (evtNeedsClone) {
                const clonedRawEvt: SpanEventRecord = {
                  name: typeof nextEvtName === 'string' ? nextEvtName : '[REDACTED_SPAN_NAME]',
                  timestamp: typeof evt.timestamp === 'number' && Number.isFinite(evt.timestamp) ? evt.timestamp : 0,
                  attributes:
                    nextEvtAttrs && typeof nextEvtAttrs === 'object'
                      ? (nextEvtAttrs as Record<string, string | number | boolean>)
                      : {},
                };
                this.eventTracker.track(clonedRawEvt);
                updatedRawEvents.push(clonedRawEvt);
                needsRawEventsReplacement = true;
              } else {
                updatedRawEvents.push(evt);
              }
            }
            if (needsRawEventsReplacement) {
              resolvedEvents = updatedRawEvents;
              this.eventArrayTracker.track(updatedRawEvents);
              try {
                targetSpan.events = updatedRawEvents;
                if (targetSpan.events !== updatedRawEvents) {
                  ensureClonedSpan().events = updatedRawEvents;
                }
              } catch {
                ensureClonedSpan().events = updatedRawEvents;
              }
            } else if (targetSpan !== span) {
              targetSpan.events = resolvedEvents;
            }
          }
        }
      } catch {
        // Leave throwing events getter for clear()/burn() error handling in raw mode.
      }

      return targetSpan;
    }

    try {
      const nameDesc = Object.getOwnPropertyDescriptor(span, 'name');
      const hasNameGetter =
        typeof nameDesc?.get === 'function' ||
        typeof nameDesc?.set === 'function' ||
        (!nameDesc && 'name' in span);
      const rawNameVal = span.name;
      const safeName = sanitizeSpanName(typeof rawNameVal === 'string' ? rawNameVal : '', false);
      if (hasNameGetter || rawNameVal !== safeName) {
        try {
          if (hasNameGetter && nameDesc?.configurable && targetSpan === span) {
            Object.defineProperty(targetSpan, 'name', {
              value: safeName,
              writable: true,
              enumerable: true,
              configurable: true,
            });
          } else {
            targetSpan.name = safeName;
          }
          const afterNameDesc = Object.getOwnPropertyDescriptor(targetSpan, 'name');
          if (
            !afterNameDesc ||
            'get' in afterNameDesc ||
            'set' in afterNameDesc ||
            afterNameDesc.value !== safeName
          ) {
            ensureClonedSpan().name = safeName;
          }
        } catch {
          ensureClonedSpan().name = safeName;
        }
      }
    } catch {
      ensureClonedSpan().name = '[REDACTED_SPAN_NAME]';
    }

    try {
      const rawAttrs = span.attributes;
      if (rawAttrs && typeof rawAttrs === 'object') {
        const sanitizedAttrs = this.sanitizer.sanitize(rawAttrs as Record<string, unknown>, false);
        const attrDesc = Object.getOwnPropertyDescriptor(span, 'attributes');
        const hasGetter =
          typeof attrDesc?.get === 'function' ||
          typeof attrDesc?.set === 'function' ||
          (!attrDesc && 'attributes' in span);
        const syncedInPlace = syncSanitizedAttributesInPlace(
          rawAttrs as Record<string, unknown>,
          sanitizedAttrs
        );
        resolvedAttrs =
          !hasGetter && syncedInPlace
            ? (rawAttrs as Record<string, string | number | boolean>)
            : sanitizedAttrs;
        if (hasGetter || !syncedInPlace || targetSpan !== span) {
          this.childRecordTracker.track(resolvedAttrs);
          try {
            if (hasGetter && attrDesc?.configurable && targetSpan === span) {
              Object.defineProperty(targetSpan, 'attributes', {
                value: resolvedAttrs,
                writable: true,
                enumerable: true,
                configurable: true,
              });
            } else {
              targetSpan.attributes = resolvedAttrs;
            }
            const afterAttrDesc = Object.getOwnPropertyDescriptor(targetSpan, 'attributes');
            if (
              !afterAttrDesc ||
              'get' in afterAttrDesc ||
              'set' in afterAttrDesc ||
              afterAttrDesc.value !== resolvedAttrs
            ) {
              ensureClonedSpan().attributes = resolvedAttrs;
            }
          } catch {
            ensureClonedSpan().attributes = resolvedAttrs;
          }
        }
      } else {
        this.childRecordTracker.track(resolvedAttrs);
        ensureClonedSpan().attributes = resolvedAttrs;
      }
    } catch {
      const fallbackAttrs: Record<string, string | number | boolean> = {};
      resolvedAttrs = fallbackAttrs;
      this.childRecordTracker.track(fallbackAttrs);
      ensureClonedSpan().attributes = fallbackAttrs;
    }

    try {
      const eventsDesc = Object.getOwnPropertyDescriptor(span, 'events');
      const hasEventsGetter =
        typeof eventsDesc?.get === 'function' ||
        typeof eventsDesc?.set === 'function' ||
        (!eventsDesc && 'events' in span);
      const rawEvents = span.events;
      if (Array.isArray(rawEvents)) {
        let needsEventsReplacement = hasEventsGetter;
        const safeEvents: SpanEventRecord[] = [];
        for (let i = 0; i < rawEvents.length; i++) {
          const evt = rawEvents[i];
          if (!evt || typeof evt !== 'object') {
            needsEventsReplacement = true;
            continue;
          }
          const evtNameDesc = Object.getOwnPropertyDescriptor(evt, 'name');
          const hasEvtNameAccessor =
            typeof evtNameDesc?.get === 'function' ||
            typeof evtNameDesc?.set === 'function' ||
            (!evtNameDesc && 'name' in evt);
          const rawEvtName = evt.name;
          const safeEvtName = sanitizeSpanName(typeof rawEvtName === 'string' ? rawEvtName : '', false);
          let evtNeedsClone = hasEventsGetter || hasEvtNameAccessor;
          if (!evtNeedsClone && rawEvtName !== safeEvtName) {
            try {
              evt.name = safeEvtName;
              const afterEvtNameDesc = Object.getOwnPropertyDescriptor(evt, 'name');
              if (
                !afterEvtNameDesc ||
                'get' in afterEvtNameDesc ||
                'set' in afterEvtNameDesc ||
                afterEvtNameDesc.value !== safeEvtName
              ) {
                evtNeedsClone = true;
              }
            } catch {
              evtNeedsClone = true;
            }
          }

          let finalEvtAttrs: Record<string, string | number | boolean> = {};
          const evtAttrDesc = Object.getOwnPropertyDescriptor(evt, 'attributes');
          const hasEvtAttrGetter =
            typeof evtAttrDesc?.get === 'function' ||
            typeof evtAttrDesc?.set === 'function' ||
            (!evtAttrDesc && 'attributes' in evt);
          const rawEvtAttrs = evt.attributes;
          if (rawEvtAttrs && typeof rawEvtAttrs === 'object') {
            finalEvtAttrs = this.sanitizer.sanitize(
              rawEvtAttrs as Record<string, unknown>,
              false
            );
            const syncedEvtInPlace = syncSanitizedAttributesInPlace(
              rawEvtAttrs as Record<string, unknown>,
              finalEvtAttrs
            );
            if (!evtNeedsClone && (hasEvtAttrGetter || !syncedEvtInPlace)) {
              this.childRecordTracker.track(finalEvtAttrs);
              try {
                if (hasEvtAttrGetter && evtAttrDesc?.configurable) {
                  Object.defineProperty(evt, 'attributes', {
                    value: finalEvtAttrs,
                    writable: true,
                    enumerable: true,
                    configurable: true,
                  });
                } else {
                  evt.attributes = finalEvtAttrs;
                }
                const afterEvtAttrDesc = Object.getOwnPropertyDescriptor(evt, 'attributes');
                if (
                  !afterEvtAttrDesc ||
                  'get' in afterEvtAttrDesc ||
                  'set' in afterEvtAttrDesc ||
                  afterEvtAttrDesc.value !== finalEvtAttrs
                ) {
                  evtNeedsClone = true;
                }
              } catch {
                evtNeedsClone = true;
              }
            }
          } else {
            evtNeedsClone = true;
          }

          if (evtNeedsClone) {
            this.childRecordTracker.track(finalEvtAttrs);
            const rawTs = readSafe(() => evt.timestamp, 0);
            const clonedEvt: SpanEventRecord = {
              name: safeEvtName,
              timestamp:
                typeof rawTs === 'number' && Number.isFinite(rawTs)
                  ? rawTs
                  : 0,
              attributes: finalEvtAttrs,
            };
            this.eventTracker.track(clonedEvt);
            safeEvents.push(clonedEvt);
            needsEventsReplacement = true;
          } else {
            safeEvents.push(evt);
          }
        }

        resolvedEvents = needsEventsReplacement ? safeEvents : rawEvents;
        if (needsEventsReplacement || targetSpan !== span) {
          this.eventArrayTracker.track(resolvedEvents);
          try {
            if (hasEventsGetter && eventsDesc?.configurable && targetSpan === span) {
              Object.defineProperty(targetSpan, 'events', {
                value: resolvedEvents,
                writable: true,
                enumerable: true,
                configurable: true,
              });
            } else {
              targetSpan.events = resolvedEvents;
            }
            const afterEventsDesc = Object.getOwnPropertyDescriptor(targetSpan, 'events');
            if (
              !afterEventsDesc ||
              'get' in afterEventsDesc ||
              'set' in afterEventsDesc ||
              afterEventsDesc.value !== resolvedEvents
            ) {
              ensureClonedSpan().events = resolvedEvents;
            }
          } catch {
            ensureClonedSpan().events = resolvedEvents;
          }
        }
      } else {
        ensureClonedSpan().events = resolvedEvents;
      }
    } catch {
      resolvedEvents = [];
      ensureClonedSpan().events = [];
    }

    return targetSpan;
  }

  export(span: SpanRecord, options?: { allowRawPayloads?: boolean }): void {
    if (this.isClearing || isHardBurned() || !span || typeof span !== 'object') {
      return;
    }
    this.trackSpanRecord(span);
    if (isHardBurned()) {
      if (this.hasRetainedState()) {
        this.clear();
      }
      return;
    }
    const rawAllowed = (options?.allowRawPayloads ?? this.allowRawPayloads) === true;
    const retainedSpan = this.sanitizeStandaloneSpan(span, rawAllowed);
    if (isHardBurned()) {
      if (this.hasRetainedState()) {
        this.clear();
      }
      return;
    }
    this.enqueueSpan(retainedSpan, false);
  }

  [EXPORT_OWNED_SPAN_SYMBOL](span: SpanRecord): void {
    this.enqueueSpan(span, false);
  }

  getSpans(): readonly SpanRecord[] {
    if (isHardBurned()) {
      return [];
    }
    if (this.spans.length === 0) {
      return [];
    }
    const scrubSnapshotAndClear = (): readonly SpanRecord[] => {
      for (const span of snapshot) {
        try {
          scrubSpanRecord(span);
        } catch {
          // Best-effort scrub if reading spans triggered hard burn.
        }
      }
      snapshot.length = 0;
      if (this.hasRetainedState()) {
        this.clear();
      }
      return [];
    };

    // Return an isolated snapshot so later unexposed appends do not accumulate unbounded WeakRefs,
    // while only exposed snapshots and their spans remain registered for burn scrubbing.
    const snapshot = [...this.spans];
    if (isHardBurned()) {
      return scrubSnapshotAndClear();
    }
    this.spanArrayTracker.track(snapshot);
    for (const span of snapshot) {
      this.trackSpanRecord(span);
    }
    if (isHardBurned()) {
      return scrubSnapshotAndClear();
    }
    return snapshot;
  }

  clear(): void {
    if (this.isClearing) {
      return;
    }
    this.isClearing = true;
    try {
      const previousSpans = this.spans;
      this.spans = [];
      let allScrubbed = true;
      let firstError: unknown;
      const recordError = (err: unknown) => {
        allScrubbed = false;
        if (firstError === undefined) {
          firstError = err;
        }
      };

      const scrubSingleSpan = (span: SpanRecord): boolean => {
        try {
          const result = scrubSpanRecord(span);
          if (!result.ok) {
            allScrubbed = false;
          }
          if (result.error !== undefined && firstError === undefined) {
            firstError = result.error;
          }
          return result.ok;
        } catch (err) {
          recordError(err);
          return false;
        }
      };

      const scrubArray = (arr: SpanRecord[]): boolean =>
        scrubSpanArrayElements(arr, scrubSingleSpan, recordError);

      try {
        scrubArray(previousSpans);
      } catch (err) {
        recordError(err);
      }
      for (const ref of [...this.spanArrayTracker.refs]) {
        const retained = ref.deref();
        if (!retained) {
          this.spanArrayTracker.untrack(ref);
          continue;
        }
        try {
          const clean = retained === previousSpans ? allScrubbed : scrubArray(retained);
          let retainedLength = -1;
          try {
            retainedLength = retained.length;
          } catch (err) {
            recordError(err);
          }
          if (clean && retainedLength === 0) {
            this.spanArrayTracker.untrack(ref, retained);
          }
        } catch (err) {
          recordError(err);
        }
      }
      for (const ref of [...this.spanTracker.refs]) {
        const retainedSpan = ref.deref();
        if (!retainedSpan) {
          this.spanTracker.untrack(ref);
          continue;
        }
        if (scrubSingleSpan(retainedSpan)) {
          this.spanTracker.untrack(ref, retainedSpan);
        }
      }
      for (const ref of [...this.eventArrayTracker.refs]) {
        const retainedEvents = ref.deref();
        if (!retainedEvents) {
          this.eventArrayTracker.untrack(ref);
          continue;
        }
        try {
          const clean = scrubEventArray(retainedEvents, recordError);
          if (!clean) {
            allScrubbed = false;
          }
          if (clean && retainedEvents.length === 0) {
            this.eventArrayTracker.untrack(ref, retainedEvents);
          }
        } catch (err) {
          recordError(err);
        }
      }
      for (const ref of [...this.eventTracker.refs]) {
        const retainedEvt = ref.deref();
        if (!retainedEvt) {
          this.eventTracker.untrack(ref);
          continue;
        }
        if (scrubSpanEvent(retainedEvt, recordError)) {
          this.eventTracker.untrack(ref, retainedEvt);
        } else {
          allScrubbed = false;
        }
      }
      for (const ref of [...this.childRecordTracker.refs]) {
        const retainedRec = ref.deref();
        if (!retainedRec) {
          this.childRecordTracker.untrack(ref);
          continue;
        }
        try {
          if (scrubRecordEntries(retainedRec)) {
            this.childRecordTracker.untrack(ref, retainedRec);
          } else {
            allScrubbed = false;
          }
        } catch (err) {
          recordError(err);
        }
      }

      if (firstError !== undefined) {
        throw firstError;
      }
      if (!allScrubbed) {
        throw new Error('Telemetry burn could not scrub immutable retained span data.');
      }
    } finally {
      this.isClearing = false;
    }
  }

  count(): number {
    return this.spans.length;
  }
}

export async function exportToOtlp(
  endpoint: string,
  span: SpanRecord,
  serviceName = 'knowthankyew-app',
  sanitizeAttributes?: (attrs: Record<string, unknown>) => Record<string, string | number | boolean>,
  allowRawPayloads = false,
  allowedKeys?: Iterable<string>,
  customValueDomains?: CustomValueDomains,
  shouldAbort?: () => boolean
): Promise<void> {
  try {
    if (typeof fetch === 'undefined' || shouldAbort?.() || isHardBurned()) return;

    const candidateAttributes = sanitizeAttributes
      ? sanitizeAttributes(span.attributes)
      : span.attributes;
    const sanitizerPair =
      allowedKeys || customValueDomains
        ? createAllowlistSanitizer(allowedKeys, customValueDomains)
        : defaultSanitizerPair;
    const safeAttributes = sanitizerPair.sanitize(candidateAttributes, allowRawPayloads);
    const rawServiceName = serviceName || 'knowthankyew-app';
    const safeServiceName = allowRawPayloads
      ? rawServiceName.length > 256
        ? formatTruncatedDigest(rawServiceName)
        : rawServiceName
      : sanitizeAllowlistedStringValue('service', rawServiceName);
    const safeSpanName = sanitizeSpanName(span.name, allowRawPayloads);
    const { traceId, spanId } = toOtlpIdentifiers(span.id);
    const serializedBody = JSON.stringify({
      resourceSpans: [
        {
          resource: {
            attributes: [{ key: 'service.name', value: { stringValue: safeServiceName } }],
          },
          scopeSpans: [
            {
              spans: [
                {
                  traceId,
                  spanId,
                  name: safeSpanName,
                  startTimeUnixNano: String(Math.trunc(span.startTime * 1_000_000)),
                  endTimeUnixNano: String(Math.trunc((span.endTime || span.startTime) * 1_000_000)),
                  attributes: Object.entries(safeAttributes)
                    .filter(
                      ([key]) =>
                        allowRawPayloads ||
                        (sanitizerPair.allowlist.has(key.toLowerCase()) &&
                          !isCollectorBoundaryExcludedKey(key))
                    )
                    .map(([key, val]) => ({
                      key,
                      value: toOtlpAttributeValue(val),
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
    });

    // Evaluate caller abort callback first, then re-read the realm tombstone immediately before dispatch.
    const abortedByCaller = shouldAbort?.() ?? false;
    if (abortedByCaller || isHardBurned()) return;

    await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: serializedBody,
    });
  } catch {
    // Fail-safe: silently swallow telemetry preparation and transmission errors to preserve app continuity
  }
}
