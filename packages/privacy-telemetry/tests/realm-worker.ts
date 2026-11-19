import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { rolldown } from 'rolldown';

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(THIS_DIR, '../src');

let coreBundlePromise: Promise<string> | null = null;
let handoffBundlePromise: Promise<string> | null = null;

async function buildCoreBundleCode(): Promise<string> {
  const virtualEntryId = 'virtual:kty-core-realm-entry';
  const resolvedVirtualEntry = '\0kty-core-realm-entry';

  const bundle = await rolldown({
    input: virtualEntryId,
    plugins: [
      {
        name: 'kty-core-realm-worker-plugin',
        resolveId(id: string) {
          if (id === virtualEntryId) return resolvedVirtualEntry;
          return null;
        },
        load(id: string) {
          if (id === resolvedVirtualEntry) {
            return [
              `export * from ${JSON.stringify(resolve(SRC_DIR, 'index.ts'))};`,
              `export { registerRetainedAlias } from ${JSON.stringify(resolve(SRC_DIR, 'tombstone.ts'))};`,
            ].join('\n');
          }
          return null;
        },
      },
    ],
  });
  try {
    const generated = await bundle.generate({
      format: 'es',
      codeSplitting: false,
    });
    return generated.output[0].code;
  } finally {
    await bundle.close();
  }
}

async function buildHandoffBundleCode(): Promise<string> {
  const virtualEntryId = 'virtual:kty-handoff-realm-entry';
  const resolvedVirtualEntry = '\0kty-handoff-realm-entry';
  const resolvedMockReact = '\0kty-mock-react';

  const bundle = await rolldown({
    input: virtualEntryId,
    plugins: [
      {
        name: 'kty-handoff-realm-worker-plugin',
        resolveId(id: string) {
          if (id === virtualEntryId) return resolvedVirtualEntry;
          if (id === 'react') return resolvedMockReact;
          return null;
        },
        load(id: string) {
          if (id === resolvedVirtualEntry) {
            return [
              `export { validateHandoffPayload } from ${JSON.stringify(resolve(SRC_DIR, 'handoff.ts'))};`,
              `export { TelemetryManager, isHardBurned } from ${JSON.stringify(resolve(SRC_DIR, 'manager.ts'))};`,
              `export { useKTYHandoff } from ${JSON.stringify(resolve(SRC_DIR, 'react/useKTYHandoff.ts'))};`,
            ].join('\n');
          }
          if (id === resolvedMockReact) {
            return [
              'export const useState = (...args) => globalThis.__ktyReactMock.useState(...args);',
              'export const useCallback = (...args) => globalThis.__ktyReactMock.useCallback(...args);',
              'export const useEffect = (...args) => globalThis.__ktyReactMock.useEffect(...args);',
            ].join('\n');
          }
          return null;
        },
      },
    ],
  });
  try {
    const generated = await bundle.generate({
      format: 'es',
      codeSplitting: false,
    });
    return generated.output[0].code;
  } finally {
    await bundle.close();
  }
}

function getCoreBundleCode(): Promise<string> {
  if (!coreBundlePromise) {
    coreBundlePromise = buildCoreBundleCode();
  }
  return coreBundlePromise;
}

function getHandoffBundleCode(): Promise<string> {
  if (!handoffBundlePromise) {
    handoffBundlePromise = buildHandoffBundleCode();
  }
  return handoffBundlePromise;
}

interface WorkerOutcome {
  ok: boolean;
  error?: string;
}

async function executeWorkerScript(workerSource: string, workerData: unknown): Promise<void> {
  const outcome = await new Promise<WorkerOutcome>((resolvePromise, rejectPromise) => {
    const worker = new Worker(workerSource, {
      eval: true,
      workerData,
    });
    let settled = false;
    worker.once('message', (msg: WorkerOutcome) => {
      settled = true;
      void worker.terminate().finally(() => resolvePromise(msg));
    });
    worker.once('error', (err: Error) => {
      if (!settled) {
        settled = true;
        void worker.terminate().finally(() => rejectPromise(err));
      }
    });
    worker.once('exit', (code: number) => {
      if (!settled) {
        settled = true;
        rejectPromise(new Error(`Realm worker exited unexpectedly with code ${code}`));
      }
    });
  });

  if (!outcome.ok) {
    throw new Error(outcome.error || 'Isolated realm assertion failed');
  }
}

/**
 * Executes an async scenario inside a genuinely isolated V8 Worker realm with freshly
 * loaded @knowthankyew/privacy-telemetry core modules (`core`, `loadCopy`, `assert`).
 */
export async function runCoreRealmScenario(scenarioBody: string): Promise<void> {
  const bundleCode = await getCoreBundleCode();
  const workerSource = `
const { parentPort, workerData } = require('node:worker_threads');
const assert = require('node:assert/strict');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

(async () => {
  try {
    const loadCopy = (tag = 'default') => {
      const tagged = '// realm-copy:' + String(tag) + '\\n' + workerData.bundleCode;
      return import('data:text/javascript;base64,' + Buffer.from(tagged, 'utf8').toString('base64'));
    };
    const core = await loadCopy('primary');
    const fn = new AsyncFunction('core', 'loadCopy', 'assert', workerData.scenarioBody);
    await fn(core, loadCopy, assert);
    parentPort.postMessage({ ok: true });
  } catch (err) {
    parentPort.postMessage({ ok: false, error: err && err.stack ? err.stack : String(err) });
  }
})();
`;
  await executeWorkerScript(workerSource, { bundleCode, scenarioBody });
}

/**
 * Executes an async scenario inside a genuinely isolated V8 Worker realm pre-populated
 * with sessionStorage, window/message listeners, BroadcastChannel, and React hook mocks.
 */
export async function runHandoffRealmScenario(scenarioBody: string): Promise<void> {
  const bundleCode = await getHandoffBundleCode();
  const workerSource = `
const { parentPort, workerData } = require('node:worker_threads');
const assert = require('node:assert/strict');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

function setupHandoffGlobals() {
  const storageMap = new Map();
  const windowListeners = new Map();
  const channelsByName = new Map();

  globalThis.sessionStorage = {
    getItem: (k) => storageMap.get(k) ?? null,
    setItem: (k, v) => { storageMap.set(k, String(v)); },
    removeItem: (k) => { storageMap.delete(k); },
  };

  globalThis.window = {
    location: { origin: 'https://app.knowthankyew.org', search: '', pathname: '/' },
    addEventListener: (type, fn) => {
      if (!windowListeners.has(type)) windowListeners.set(type, new Set());
      windowListeners.get(type).add(fn);
    },
    removeEventListener: (type, fn) => {
      windowListeners.get(type)?.delete(fn);
    },
    dispatchEvent: (ev) => {
      for (const fn of [...(windowListeners.get(ev.type) ?? [])]) {
        fn(ev);
      }
      return true;
    },
  };

  class MockBroadcastChannel {
    constructor(name) {
      this.name = name;
      this.onmessage = null;
      if (!channelsByName.has(name)) channelsByName.set(name, new Set());
      channelsByName.get(name).add(this);
    }
    postMessage(data) {
      for (const peer of [...(channelsByName.get(this.name) ?? [])]) {
        if (peer !== this) peer.onmessage?.({ data });
      }
    }
    close() {
      channelsByName.get(this.name)?.delete(this);
    }
  }
  globalThis.BroadcastChannel = MockBroadcastChannel;

  function createReactMock() {
    const states = [];
    const cleanups = [];
    const prevDepsMap = new Map();
    let pendingEffects = [];
    let stateCursor = 0;
    let effectCursor = 0;

    globalThis.__ktyReactMock = {
      useState: (initial) => {
        const idx = stateCursor++;
        if (!(idx in states)) {
          states[idx] = typeof initial === 'function' ? initial() : initial;
        }
        const setState = (next) => {
          states[idx] = typeof next === 'function' ? next(states[idx]) : next;
        };
        return [states[idx], setState];
      },
      useCallback: (fn) => fn,
      useEffect: (fn, deps) => {
        const idx = effectCursor++;
        pendingEffects.push({ idx, fn, deps });
      },
    };

    return {
      mount(renderFn) {
        states.length = 0;
        cleanups.length = 0;
        prevDepsMap.clear();

        const runPass = () => {
          stateCursor = 0;
          effectCursor = 0;
          pendingEffects = [];
          const out = renderFn();
          for (const eff of pendingEffects) {
            const prevDeps = prevDepsMap.get(eff.idx);
            const changed =
              !prevDeps ||
              !eff.deps ||
              eff.deps.length !== prevDeps.length ||
              eff.deps.some((d, i) => !Object.is(d, prevDeps[i]));
            if (changed) {
              cleanups[eff.idx]?.();
              cleanups[eff.idx] = eff.fn();
              prevDepsMap.set(eff.idx, eff.deps);
            }
          }
          return out;
        };

        const result = runPass();
        return {
          result,
          rerender: runPass,
          unmount: () => {
            for (const c of cleanups) c?.();
          },
        };
      },
    };
  }

  function createValidPayload() {
    return {
      version: '1.0',
      originApp: 'knowthankyew-extension',
      domain: 'example.com',
      scanTimestamp: '2026-11-14T00:00:00.000Z',
      riskScore: 80,
      summary: { critical: 1, warning: 0, info: 0 },
      findings: [
        {
          ruleId: 'WARRANTY_VOID_IF_REMOVED',
          title: 'Warranty Void If Removed',
          category: 'WARRANTY_DISCLAIMER',
          severity: 'CRITICAL',
          statuteCode: '15 U.S.C. § 2302',
          statuteTitle: 'Magnuson-Moss Warranty Act Tie-In Prohibition',
          matchedSnippet: 'Warranty void if seal broken',
          explanation: 'Tie-in warranty voiding clauses are prohibited under federal law.',
          recommendation: 'Review manufacturer repair obligations.',
        },
      ],
      primaryLegalLink: null,
      targetTool: 'warranty-watch',
    };
  }

  return { storageMap, windowListeners, createReactMock, createValidPayload };
}

(async () => {
  try {
    const env = setupHandoffGlobals();
    const loadCopy = (tag = 'default') => {
      const tagged = '// handoff-copy:' + String(tag) + '\\n' + workerData.bundleCode;
      return import('data:text/javascript;base64,' + Buffer.from(tagged, 'utf8').toString('base64'));
    };
    const handoffMod = await loadCopy('primary');
    const fn = new AsyncFunction('handoffMod', 'loadCopy', 'env', 'assert', workerData.scenarioBody);
    await fn(handoffMod, loadCopy, env, assert);
    parentPort.postMessage({ ok: true });
  } catch (err) {
    parentPort.postMessage({ ok: false, error: err && err.stack ? err.stack : String(err) });
  }
})();
`;
  await executeWorkerScript(workerSource, { bundleCode, scenarioBody });
}
