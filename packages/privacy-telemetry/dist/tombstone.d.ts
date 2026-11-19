export declare const EXPORT_OWNED_SPAN_SYMBOL: unique symbol;
export interface WipeRegistryResult {
    hasError: boolean;
    firstError: unknown;
}
export declare function createWeakRef<T extends object>(target: T): WeakRef<T>;
export interface PrivacyTelemetryRealmState {
    hardBurned: boolean;
    readonly hardBurnListeners: Set<() => void>;
    readonly liveManagerRefs: Set<WeakRef<object>>;
    readonly liveManagerWipers: WeakMap<object, (target: object) => void>;
    readonly liveManagerFinalizer: FinalizationRegistry<WeakRef<object>> | null;
}
/**
 * Returns the realm-shared hard-burn registry and tombstone state.
 */
export declare function getRealmState(): PrivacyTelemetryRealmState;
/**
 * Returns whether a hard burn tombstone has been recorded in this JS realm.
 */
export declare function isHardBurned(): boolean;
/**
 * Records an irreversible process-realm hard-burn tombstone and returns
 * whether the realm had already been burned prior to this call.
 */
export declare function recordRealmHardBurn(): boolean;
/**
 * Registers an exporter wipe callback under weak realm tracking so hard burn scrubs standalone exporters.
 */
export declare function registerLiveExporter(exporter: object, wipe: (target: object) => void): void;
/**
 * Invokes registered wipe callbacks for all live targets in a weak registry while preserving first failure.
 */
export declare function wipeWeakTargetRegistry(refs: Set<WeakRef<object>>, wipers: WeakMap<object, (target: object) => void>, skipTarget?: unknown): WipeRegistryResult;
/**
 * Scrubs all live registered MemoryExporter instances across the JS realm.
 */
export declare function wipeLiveExporters(): WipeRegistryResult;
/**
 * Registers a consumer-exposed alias under weak realm tracking with a static wiper
 * so aliases remain scrubbable even if their issuing manager/exporter is garbage collected.
 */
export declare function registerRetainedAlias(target: object, wipe: (target: object) => void): void;
/**
 * Removes an explicitly scrubbed alias from realm weak tracking.
 */
export declare function unregisterRetainedAlias(target: object): void;
/**
 * Scrubs all live consumer-exposed aliases tracked across the JS realm.
 */
export declare function wipeRetainedAliases(): WipeRegistryResult;
//# sourceMappingURL=tombstone.d.ts.map