import { describe, it } from 'vitest';
import { runHandoffRealmScenario } from './realm-worker.js';

describe('useKTYHandoff hard-burn tombstone persistence across remounts', () => {
  it('persists hard-burn across unmount/remount after TelemetryManager.burn()', async () => {
    await runHandoffRealmScenario(`
      const { storageMap, windowListeners, createReactMock, createValidPayload } = env;
      const { validateHandoffPayload, TelemetryManager, useKTYHandoff } = handoffMod;
      const reactRunner = createReactMock();

      const payload = createValidPayload();
      assert.equal(validateHandoffPayload(payload), true);
      storageMap.set('kty_handoff', JSON.stringify(payload));

      const mounted1 = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
      assert.equal(mounted1.result.isHandoffActive, true);

      const tm = new TelemetryManager({ burnEnabled: true });
      tm.burn();
      const afterBurn = mounted1.rerender();
      assert.equal(afterBurn.payload, null);
      assert.equal(storageMap.has('kty_handoff'), false);
      mounted1.unmount();

      // Plant fresh payload in sessionStorage & attempt remount in same JS realm
      storageMap.set('kty_handoff', JSON.stringify(createValidPayload()));
      const mounted2 = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
      assert.equal(mounted2.result.payload, null);
      assert.equal(storageMap.has('kty_handoff'), false);

      // Late postMessage handoff is also rejected and scrubbed
      for (const fn of [...(windowListeners.get('message') ?? [])]) {
        fn({
          type: 'message',
          origin: 'https://app.knowthankyew.org',
          source: globalThis.window,
          data: { type: 'KTY_HANDOFF_PAYLOAD', payload: createValidPayload() },
        });
      }
      assert.equal(mounted2.rerender().payload, null);
      assert.equal(storageMap.has('kty_handoff'), false);
      mounted2.unmount();
    `);
  });

  it('persists hard-burn across unmount/remount after KTY_HARD_BURN_DOM broadcast', async () => {
    await runHandoffRealmScenario(`
      const { storageMap, windowListeners, createReactMock, createValidPayload } = env;
      const { useKTYHandoff } = handoffMod;
      const reactRunner = createReactMock();
      const mounted1 = reactRunner.mount(() => useKTYHandoff('warranty-watch'));

      const bc = new BroadcastChannel('kty_hard_burn');
      bc.postMessage({ type: 'KTY_HARD_BURN_DOM' });
      bc.close();
      mounted1.unmount();

      storageMap.set('kty_handoff', JSON.stringify(createValidPayload()));
      const mounted2 = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
      assert.equal(mounted2.result.payload, null);
      assert.equal(storageMap.has('kty_handoff'), false);

      // Direct window.postMessage KTY_HANDOFF_PAYLOAD is also ignored
      for (const fn of [...(windowListeners.get('message') ?? [])]) {
        fn({
          type: 'message',
          origin: 'https://app.knowthankyew.org',
          source: globalThis.window,
          data: { type: 'KTY_HANDOFF_PAYLOAD', payload: createValidPayload() },
        });
      }
      assert.equal(mounted2.rerender().payload, null);
      mounted2.unmount();
    `);
  });

  it('ignores KTY_HANDOFF_PAYLOAD and KTY_HARD_BURN_DOM from untrusted origins, opaque origin, or foreign sources', async () => {
    await runHandoffRealmScenario(`
      const { storageMap, windowListeners, createReactMock, createValidPayload } = env;
      const { TelemetryManager, useKTYHandoff } = handoffMod;
      const reactRunner = createReactMock();

      const tm = new TelemetryManager({ burnEnabled: true });
      tm.startSpan('scan_started', { rule_id: 'AR-001' }).end('OK');
      storageMap.set('kty_handoff', JSON.stringify({ ...createValidPayload(), targetTool: 'lease-audit' }));

      const mounted = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
      assert.equal(mounted.result.payload, null);

      const untrustedEvents = [
        { type: 'message', origin: 'https://evil.example', source: globalThis.window },
        { type: 'message', origin: 'null', source: globalThis.window },
        { type: 'message', source: globalThis.window },
        { type: 'message', origin: 'https://app.knowthankyew.org', source: {} },
      ];

      for (const base of untrustedEvents) {
        for (const fn of [...(windowListeners.get('message') ?? [])]) {
          fn({ ...base, data: { type: 'KTY_HARD_BURN_DOM' } });
          fn({
            ...base,
            data: { type: 'KTY_HANDOFF_PAYLOAD', payload: createValidPayload() },
          });
        }
      }

      assert.equal(mounted.rerender().payload, null);
      assert.equal(tm.getBufferedSpans().length, 1);
      assert.equal(storageMap.has('kty_handoff'), true);

      // Same-origin / window-sourced handoff STILL succeeds because none of the spoofed burns took effect
      for (const fn of [...(windowListeners.get('message') ?? [])]) {
        fn({
          type: 'message',
          origin: 'https://app.knowthankyew.org',
          source: globalThis.window,
          data: { type: 'KTY_HANDOFF_PAYLOAD', payload: createValidPayload() },
        });
      }
      assert.equal(mounted.rerender().isHandoffActive, true);
      mounted.unmount();
    `);

    // Also fail closed when window.location.origin is opaque ('null')
    await runHandoffRealmScenario(`
      const { createReactMock, createValidPayload } = env;
      const { TelemetryManager, useKTYHandoff } = handoffMod;
      const opaqueListeners = new Map();
      globalThis.window = {
        location: { origin: 'null', search: '', pathname: '/' },
        addEventListener: (type, fn) => {
          if (!opaqueListeners.has(type)) opaqueListeners.set(type, new Set());
          opaqueListeners.get(type).add(fn);
        },
        removeEventListener: (type, fn) => {
          opaqueListeners.get(type)?.delete(fn);
        },
      };
      const opaqueRunner = createReactMock();
      const opaqueTm = new TelemetryManager({ burnEnabled: true });
      opaqueTm.startSpan('scan_started', { rule_id: 'AR-001' }).end('OK');
      const opaqueMount = opaqueRunner.mount(() => useKTYHandoff('warranty-watch'));
      for (const fn of [...(opaqueListeners.get('message') ?? [])]) {
        fn({ type: 'message', origin: 'null', source: globalThis.window, data: { type: 'KTY_HARD_BURN_DOM' } });
        fn({
          type: 'message',
          origin: 'null',
          source: globalThis.window,
          data: { type: 'KTY_HANDOFF_PAYLOAD', payload: createValidPayload() },
        });
      }
      assert.equal(opaqueMount.rerender().payload, null);
      assert.equal(opaqueTm.getBufferedSpans().length, 1);
      opaqueMount.unmount();
    `);
  });

  it('synchronously wipes active TelemetryManager buffers and tombstones realm on trusted KTY_HARD_BURN_DOM', async () => {
    await runHandoffRealmScenario(`
      const { windowListeners, createReactMock } = env;
      const { TelemetryManager, useKTYHandoff } = handoffMod;
      const reactRunner = createReactMock();

      const tm = new TelemetryManager({ burnEnabled: true });
      tm.startSpan('scan_started', { rule_id: 'AR-001' }).end('OK');
      const pendingSpan = tm.startSpan('scan_started', { rule_id: 'CA_CIV_1950_5' });
      tm.recordAuditEvent('document_ingested', 'Uploaded doc');
      const retainedAudit = tm.getAuditLog();

      const tmSecondary = new TelemetryManager({ burnEnabled: true });
      tmSecondary.startSpan('rules_evaluated', { rule_id: 'AR-001' }).end('OK');
      const secondaryPendingSpan = tmSecondary.startSpan('rules_evaluated', { rule_id: 'CA_CIV_1950_5' });
      tmSecondary.recordAuditEvent('audit_performed', 'Secondary manager event');
      assert.equal(tm.getBufferedSpans().length, 1);
      assert.equal(tm.getAuditLog().length, 1);
      assert.equal(tmSecondary.getBufferedSpans().length, 1);
      assert.equal(tmSecondary.getAuditLog().length, 1);

      const mounted = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
      for (const fn of [...(windowListeners.get('message') ?? [])]) {
        fn({
          type: 'message',
          origin: 'https://app.knowthankyew.org',
          source: globalThis.window,
          data: { type: 'KTY_HARD_BURN_DOM' },
        });
      }

      // Synchronous wipe of ALL active manager internal storage; prior audit snapshot remains isolated
      assert.equal(tm.getBufferedSpans().length, 0);
      assert.equal(tm.getAuditLog().length, 0);
      assert.equal(retainedAudit.length, 1);
      assert.equal(tm.getPrivacyAuditReport().activeSpanCount, 0);
      assert.equal(tmSecondary.getBufferedSpans().length, 0);
      assert.equal(tmSecondary.getAuditLog().length, 0);

      // Outstanding pre-burn span.end(), reset(), restartSession(), and new managers all fail closed
      pendingSpan.end('OK');
      secondaryPendingSpan.end('OK');
      assert.equal(tm.getBufferedSpans().length, 0);
      assert.equal(tmSecondary.getBufferedSpans().length, 0);

      tmSecondary.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      tmSecondary.recordAuditEvent('document_ingested', 'Post-burn secondary audit');
      assert.equal(tmSecondary.getBufferedSpans().length, 0);
      assert.equal(tmSecondary.getAuditLog().length, 0);

      tm.reset();
      tm.restartSession();
      tm.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      tm.recordAuditEvent('document_ingested', 'Post-burn audit');
      assert.equal(tm.getBufferedSpans().length, 0);
      assert.equal(tm.getAuditLog().length, 0);

      const tm2 = new TelemetryManager({ burnEnabled: true });
      tm2.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      tm2.recordAuditEvent('document_ingested', 'Second manager after realm burn');
      assert.equal(tm2.getBufferedSpans().length, 0);
      assert.equal(tm2.getAuditLog().length, 0);

      // Even managers with burnEnabled: false honor an existing realm hard-burn tombstone
      const disabledPostBurnTm = new TelemetryManager({ burnEnabled: false });
      disabledPostBurnTm.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      disabledPostBurnTm.recordAuditEvent('document_ingested', 'Post-burn audit on burnEnabled=false');
      assert.equal(disabledPostBurnTm.getBufferedSpans().length, 0);
      assert.equal(disabledPostBurnTm.getAuditLog().length, 0);

      mounted.unmount();
    `);
  });

  it('wipes existing burnEnabled: false managers upon external hard burn and establishes tombstone when sessionStorage throws SecurityError', async () => {
    await runHandoffRealmScenario(`
      const { windowListeners, createReactMock } = env;
      const { TelemetryManager, isHardBurned, useKTYHandoff } = handoffMod;
      const reactRunner = createReactMock();

      // A burnEnabled: false manager cannot initiate a hard burn on its own
      const passiveTm = new TelemetryManager({ burnEnabled: false });
      passiveTm.startSpan('scan_started', { rule_id: 'AR-001' }).end('OK');
      passiveTm.burn();
      assert.equal(passiveTm.getBufferedSpans().length, 1);
      assert.equal(isHardBurned(), false);

      const origSessionStorageDesc = Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage');
      // Simulate SecurityError when sessionStorage property getter is restricted after mount
      Object.defineProperty(globalThis, 'sessionStorage', {
        configurable: true,
        get() {
          throw new Error('SecurityError: sessionStorage denied');
        },
      });

      try {
        const mounted = reactRunner.mount(() => useKTYHandoff('warranty-watch'));
        for (const fn of [...(windowListeners.get('message') ?? [])]) {
          fn({
            type: 'message',
            origin: 'https://app.knowthankyew.org',
            source: globalThis.window,
            data: { type: 'KTY_HARD_BURN_DOM' },
          });
        }

        assert.equal(isHardBurned(), true);
        assert.equal(passiveTm.getBufferedSpans().length, 0);
        assert.equal(passiveTm.getAuditLog().length, 0);

        passiveTm.reset();
        passiveTm.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
        assert.equal(passiveTm.getBufferedSpans().length, 0);

        mounted.unmount();
      } finally {
        if (origSessionStorageDesc) {
          Object.defineProperty(globalThis, 'sessionStorage', origSessionStorageDesc);
        } else {
          delete globalThis.sessionStorage;
        }
      }
    `);
  });
});
