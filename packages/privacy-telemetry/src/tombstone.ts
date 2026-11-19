const REALM_STATE_SYMBOL = Symbol.for('knowthankyew.privacyTelemetry.realmState.v1');
const LIVE_EXPORTERS_SYMBOL = Symbol.for('knowthankyew.privacyTelemetry.liveExporters.v1');
const LIVE_ALIASES_SYMBOL = Symbol.for('knowthankyew.privacyTelemetry.liveAliases.v1');
export const EXPORT_OWNED_SPAN_SYMBOL = Symbol.for('knowthankyew.privacyTelemetry.exportOwnedSpan.v1');

export interface WipeRegistryResult {
  hasError: boolean;
  firstError: unknown;
}

export function createWeakRef<T extends object>(target: T): WeakRef<T> {
  if (typeof WeakRef !== 'undefined') {
    return new WeakRef(target);
  }
  return { deref: () => target } as WeakRef<T>;
}

interface WeakTargetRegistry {
  readonly refs: Set<WeakRef<object>>;
  readonly wipers: WeakMap<object, (target: object) => void>;
  readonly finalizer: FinalizationRegistry<WeakRef<object>> | null;
}

export interface PrivacyTelemetryRealmState {
  hardBurned: boolean;
  readonly hardBurnListeners: Set<() => void>;
  readonly liveManagerRefs: Set<WeakRef<object>>;
  readonly liveManagerWipers: WeakMap<object, (target: object) => void>;
  readonly liveManagerFinalizer: FinalizationRegistry<WeakRef<object>> | null;
}

function isValidRealmState(candidate: unknown): candidate is PrivacyTelemetryRealmState {
  if (candidate === null || typeof candidate !== 'object') {
    return false;
  }
  const state = candidate as Partial<PrivacyTelemetryRealmState>;
  return (
    typeof state.hardBurned === 'boolean' &&
    state.hardBurnListeners instanceof Set &&
    state.liveManagerRefs instanceof Set &&
    state.liveManagerWipers instanceof WeakMap
  );
}

function getOrCreateRealmState(): PrivacyTelemetryRealmState {
  const host = globalThis as Record<PropertyKey, unknown>;
  const existing = host[REALM_STATE_SYMBOL];
  if (isValidRealmState(existing)) {
    return existing;
  }

  let latchedHardBurned =
    existing !== null &&
    typeof existing === 'object' &&
    Boolean((existing as { hardBurned?: unknown }).hardBurned);

  const hardBurnListeners = new Set<() => void>();
  const liveManagerRefs = new Set<WeakRef<object>>();
  const liveManagerWipers = new WeakMap<object, (target: object) => void>();
  const liveManagerFinalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<object>>((ref) => {
          liveManagerRefs.delete(ref);
        })
      : null;

  const state = {} as PrivacyTelemetryRealmState;
  Object.defineProperty(state, 'hardBurned', {
    enumerable: true,
    configurable: false,
    get: () => latchedHardBurned,
    set: (value: boolean) => {
      // Tombstones are strictly one-way within a JS realm.
      if (value) {
        latchedHardBurned = true;
      }
    },
  });
  Object.defineProperties(state, {
    hardBurnListeners: {
      value: hardBurnListeners,
      enumerable: true,
      writable: false,
      configurable: false,
    },
    liveManagerRefs: {
      value: liveManagerRefs,
      enumerable: true,
      writable: false,
      configurable: false,
    },
    liveManagerWipers: {
      value: liveManagerWipers,
      enumerable: true,
      writable: false,
      configurable: false,
    },
    liveManagerFinalizer: {
      value: liveManagerFinalizer,
      enumerable: true,
      writable: false,
      configurable: false,
    },
  });
  Object.preventExtensions(state);

  try {
    Object.defineProperty(host, REALM_STATE_SYMBOL, {
      value: state,
      enumerable: false,
      writable: false,
      configurable: false,
    });
    return state;
  } catch {
    const raced = host[REALM_STATE_SYMBOL];
    if (isValidRealmState(raced)) {
      if (latchedHardBurned) {
        raced.hardBurned = true;
      }
      return raced;
    }
    host[REALM_STATE_SYMBOL] = state;
    return state;
  }
}

/**
 * Returns the realm-shared hard-burn registry and tombstone state.
 */
export function getRealmState(): PrivacyTelemetryRealmState {
  return getOrCreateRealmState();
}

/**
 * Returns whether a hard burn tombstone has been recorded in this JS realm.
 */
export function isHardBurned(): boolean {
  return getOrCreateRealmState().hardBurned;
}

/**
 * Records an irreversible process-realm hard-burn tombstone and returns
 * whether the realm had already been burned prior to this call.
 */
export function recordRealmHardBurn(): boolean {
  const state = getOrCreateRealmState();
  const wasBurned = state.hardBurned;
  state.hardBurned = true;
  return wasBurned;
}

function isValidWeakTargetRegistry(candidate: unknown): candidate is WeakTargetRegistry {
  if (candidate === null || typeof candidate !== 'object') {
    return false;
  }
  const registry = candidate as Partial<WeakTargetRegistry>;
  return registry.refs instanceof Set && registry.wipers instanceof WeakMap;
}

function getOrCreateLiveExportersRegistry(): WeakTargetRegistry {
  const host = globalThis as Record<PropertyKey, unknown>;
  const existing = host[LIVE_EXPORTERS_SYMBOL];
  if (isValidWeakTargetRegistry(existing)) {
    return existing;
  }

  const refs = new Set<WeakRef<object>>();
  const wipers = new WeakMap<object, (target: object) => void>();
  const finalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<object>>((ref) => {
          refs.delete(ref);
        })
      : null;

  const registry = {} as WeakTargetRegistry;
  Object.defineProperties(registry, {
    refs: { value: refs, enumerable: true, writable: false, configurable: false },
    wipers: { value: wipers, enumerable: true, writable: false, configurable: false },
    finalizer: { value: finalizer, enumerable: true, writable: false, configurable: false },
  });
  Object.preventExtensions(registry);

  try {
    Object.defineProperty(host, LIVE_EXPORTERS_SYMBOL, {
      value: registry,
      enumerable: false,
      writable: false,
      configurable: false,
    });
    return registry;
  } catch {
    const raced = host[LIVE_EXPORTERS_SYMBOL];
    if (isValidWeakTargetRegistry(raced)) {
      return raced;
    }
    host[LIVE_EXPORTERS_SYMBOL] = registry;
    return registry;
  }
}

/**
 * Registers an exporter wipe callback under weak realm tracking so hard burn scrubs standalone exporters.
 */
export function registerLiveExporter(exporter: object, wipe: (target: object) => void): void {
  const { refs, wipers, finalizer } = getOrCreateLiveExportersRegistry();
  wipers.set(exporter, wipe);
  const ref = createWeakRef(exporter);
  refs.add(ref);
  finalizer?.register(exporter, ref);
}

/**
 * Invokes registered wipe callbacks for all live targets in a weak registry while preserving first failure.
 */
export function wipeWeakTargetRegistry(
  refs: Set<WeakRef<object>>,
  wipers: WeakMap<object, (target: object) => void>,
  skipTarget?: unknown
): WipeRegistryResult {
  let hasError = false;
  let firstError: unknown;
  for (const ref of [...refs]) {
    const target = ref.deref();
    if (!target) {
      refs.delete(ref);
      continue;
    }
    if (skipTarget !== undefined && target === skipTarget) {
      continue;
    }
    try {
      wipers.get(target)?.(target);
    } catch (err) {
      if (!hasError) {
        hasError = true;
        firstError = err;
      }
    }
  }
  return { hasError, firstError };
}

/**
 * Scrubs all live registered MemoryExporter instances across the JS realm.
 */
export function wipeLiveExporters(): WipeRegistryResult {
  const { refs, wipers } = getOrCreateLiveExportersRegistry();
  return wipeWeakTargetRegistry(refs, wipers);
}

interface RetainedAliasRegistry extends WeakTargetRegistry {
  readonly refsByTarget: WeakMap<object, WeakRef<object>>;
}

function isValidRetainedAliasRegistry(candidate: unknown): candidate is RetainedAliasRegistry {
  if (!isValidWeakTargetRegistry(candidate)) {
    return false;
  }
  return (candidate as Partial<RetainedAliasRegistry>).refsByTarget instanceof WeakMap;
}

function getOrCreateRetainedAliasRegistry(): RetainedAliasRegistry {
  const host = globalThis as Record<PropertyKey, unknown>;
  const existing = host[LIVE_ALIASES_SYMBOL];
  if (isValidRetainedAliasRegistry(existing)) {
    return existing;
  }

  const refs = new Set<WeakRef<object>>();
  const wipers = new WeakMap<object, (target: object) => void>();
  const refsByTarget = new WeakMap<object, WeakRef<object>>();
  const finalizer =
    typeof FinalizationRegistry !== 'undefined'
      ? new FinalizationRegistry<WeakRef<object>>((ref) => {
          refs.delete(ref);
        })
      : null;

  const registry = {} as RetainedAliasRegistry;
  Object.defineProperties(registry, {
    refs: { value: refs, enumerable: true, writable: false, configurable: false },
    wipers: { value: wipers, enumerable: true, writable: false, configurable: false },
    refsByTarget: { value: refsByTarget, enumerable: true, writable: false, configurable: false },
    finalizer: { value: finalizer, enumerable: true, writable: false, configurable: false },
  });
  Object.preventExtensions(registry);

  try {
    Object.defineProperty(host, LIVE_ALIASES_SYMBOL, {
      value: registry,
      enumerable: false,
      writable: false,
      configurable: false,
    });
    return registry;
  } catch {
    const raced = host[LIVE_ALIASES_SYMBOL];
    if (isValidRetainedAliasRegistry(raced)) {
      return raced;
    }
    host[LIVE_ALIASES_SYMBOL] = registry;
    return registry;
  }
}

/**
 * Registers a consumer-exposed alias under weak realm tracking with a static wiper
 * so aliases remain scrubbable even if their issuing manager/exporter is garbage collected.
 */
export function registerRetainedAlias(target: object, wipe: (target: object) => void): void {
  if (isHardBurned()) {
    wipe(target);
    return;
  }
  const { refs, wipers, refsByTarget, finalizer } = getOrCreateRetainedAliasRegistry();
  wipers.set(target, wipe);
  if (!refsByTarget.has(target)) {
    const ref = createWeakRef(target);
    refs.add(ref);
    refsByTarget.set(target, ref);
    finalizer?.register(target, ref, target);
  }
  if (isHardBurned()) {
    wipe(target);
  }
}

/**
 * Removes an explicitly scrubbed alias from realm weak tracking.
 */
export function unregisterRetainedAlias(target: object): void {
  const { refs, wipers, refsByTarget, finalizer } = getOrCreateRetainedAliasRegistry();
  const ref = refsByTarget.get(target);
  if (ref) {
    refs.delete(ref);
    refsByTarget.delete(target);
  }
  wipers.delete(target);
  finalizer?.unregister(target);
}

/**
 * Scrubs all live consumer-exposed aliases tracked across the JS realm.
 */
export function wipeRetainedAliases(): WipeRegistryResult {
  const { refs, wipers } = getOrCreateRetainedAliasRegistry();
  return wipeWeakTargetRegistry(refs, wipers);
}
