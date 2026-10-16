import { n as e, t } from "./chunks/handoff-u36nFV0R.js";
//#region src/allowlist.ts
var n = /* @__PURE__ */ new Set(/* @__PURE__ */ "rule_id.rule_ids.statute_code.jurisdiction.status.risk_level.duration_ms.duration_sec.clause_count.total_clauses.flagged_clauses.flagged_count.standard_count.watch_count.unenforceable_count.char_count.matched_violations.error_code.job_id.service.action.step.current_step.total_steps.progress_pct.loss.device.adapter_path.adapter_size_bytes.base_model.dataset_hash.dataset_relative_path.exchange.routing_key".split("."));
function r(e) {
	function t(e, t) {
		return e >>> t | e << 32 - t;
	}
	let n = Math.pow, r = n(2, 32), i, a, o = "", s = [], c = [], l = 0, u = {};
	for (let e = 2; l < 64; e++) if (!u[e]) {
		for (i = 0; i < 313; i += e) u[i] = !0;
		s[l] = n(e, .5) * r | 0, c[l++] = n(e, 1 / 3) * r | 0;
	}
	let d = new TextEncoder().encode(e), f = d.length * 8, p = (d.length + 8 >> 6) + 1 << 6, m = new Uint8Array(p);
	m.set(d), m[d.length] = 128;
	let h = new DataView(m.buffer);
	h.setUint32(p - 8, Math.floor(f / r), !1), h.setUint32(p - 4, f >>> 0, !1);
	let g = p >> 2, _ = Array(g);
	for (i = 0; i < g; i++) _[i] = h.getUint32(i * 4, !1);
	for (a = 0; a < _.length;) {
		let e = _.slice(a, a += 16), n = s.slice(0);
		for (i = 0; i < 64; i++) {
			let n = e[i - 15], r = e[i - 2], a = t(n, 7) ^ t(n, 18) ^ n >>> 3, o = t(r, 17) ^ t(r, 19) ^ r >>> 10;
			e[i] = i < 16 ? e[i] : e[i - 16] + a + e[i - 7] + o | 0;
			let l = t(s[4], 6) ^ t(s[4], 11) ^ t(s[4], 25), u = s[4] & s[5] ^ ~s[4] & s[6], d = s[7] + l + u + c[i] + e[i] | 0;
			s = [
				d + ((t(s[0], 2) ^ t(s[0], 13) ^ t(s[0], 22)) + (s[0] & s[1] ^ s[0] & s[2] ^ s[1] & s[2]) | 0) | 0,
				s[0],
				s[1],
				s[2],
				s[3] + d | 0,
				s[4],
				s[5],
				s[6]
			];
		}
		for (i = 0; i < 8; i++) s[i] = s[i] + n[i] | 0;
	}
	for (i = 0; i < 8; i++) for (a = 3; a >= 0; a--) {
		let e = s[i] >> 8 * a & 255;
		o += (e < 16 ? "0" : "") + e.toString(16);
	}
	return `[TRUNCATED_HASH_${o.slice(0, 8)}]`;
}
function i(e) {
	let t = new Set(n);
	if (e) for (let n of e) t.add(n.toLowerCase());
	return {
		allowlist: t,
		sanitize: (e, n = !1) => {
			let i = {};
			for (let [a, o] of Object.entries(e)) {
				let e = a.toLowerCase();
				if (!t.has(e) && !n) {
					i[a] = "[REDACTED_BY_DEFAULT_ALLOWLIST]";
					continue;
				}
				typeof o == "string" ? i[a] = o.length > 256 && !n ? r(o) : o : (typeof o == "number" || typeof o == "boolean") && (i[a] = o);
			}
			return i;
		}
	};
}
//#endregion
//#region src/exporter.ts
var a = class {
	spans = [];
	maxCapacity;
	constructor(e = 500) {
		this.maxCapacity = e;
	}
	export(e) {
		this.spans.push(e), this.spans.length > this.maxCapacity && this.spans.shift();
	}
	getSpans() {
		return this.spans;
	}
	clear() {
		this.spans = [];
	}
	count() {
		return this.spans.length;
	}
};
async function o(e, t, n = "knowthankyew-app") {
	if (typeof fetch < "u") try {
		await fetch(e, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ resourceSpans: [{
				resource: { attributes: [{
					key: "service.name",
					value: { stringValue: n }
				}] },
				scopeSpans: [{ spans: [{
					traceId: t.id,
					spanId: t.id,
					name: t.name,
					startTimeUnixNano: t.startTime * 1e6,
					endTimeUnixNano: (t.endTime || t.startTime) * 1e6,
					attributes: Object.entries(t.attributes).map(([e, t]) => ({
						key: e,
						value: typeof t == "string" ? { stringValue: t } : typeof t == "number" ? Number.isInteger(t) ? { intValue: t } : { doubleValue: t } : { boolValue: t }
					})),
					status: { code: t.status === "OK" ? 1 : t.status === "ERROR" ? 2 : 0 }
				}] }]
			}] })
		});
	} catch {}
}
//#endregion
//#region src/claims.ts
function s(e, t) {
	return e.isLocalOnlyHonest ? {
		isLocalOnlyHonest: !0,
		isEnterpriseBuild: !1,
		appTitleSuffix: "",
		badgeLabel: "Zero Network • Memory-Only",
		dropzoneNotice: "100% Client-Side Local Execution • Zero Network Transmission",
		disclaimerExecutionText: t?.domainDisclaimerClause ? t.domainDisclaimerClause : "All rule evaluations execute 100% locally in your browser with zero remote network transmission.",
		footerTitle: t?.consumerFooterTitle || "100% Local Air-Gapped Compliance Engine.",
		footerSubtext: t?.consumerFooterSubtext || "Zero Telemetry • Zero Remote PII/Document Egress • Grounded Statutory Realities",
		modalStatusTitle: "100% Local-First & Private (Memory-Only Telemetry)",
		modalStatusDescription: "All computation and telemetry spans remain buffered strictly in volatile memory. No outbound network calls are made. Telemetry purges immediately upon invoking \"Burn Local Data\".",
		otlpEndpoint: null
	} : {
		isLocalOnlyHonest: !1,
		isEnterpriseBuild: !0,
		appTitleSuffix: t?.appTitleSuffix || " (Enterprise Build)",
		badgeLabel: `OTLP Active (${e.telemetryMode})`,
		dropzoneNotice: "Local Document Parsing • OTLP Operational Metadata Active (Strictly Redacted)",
		disclaimerExecutionText: `Rule evaluations execute in-browser. Scrubbed operational telemetry is exported to configured OTLP endpoint (${e.otlpEndpoint}). Document text is never transmitted.`,
		footerTitle: t?.enterpriseFooterTitle || "Enterprise Compliance Engine (OTLP Telemetry Active).",
		footerSubtext: t?.enterpriseFooterSubtext || "Enterprise Telemetry Mode • Operational Metadata Export Active • Document Bodies Air-Gapped",
		modalStatusTitle: "Enterprise OTLP Telemetry Active",
		modalStatusDescription: `Telemetry spans are exported to configured OTLP endpoint: ${e.otlpEndpoint}. Document text and sensitive fields are redacted via strict allowlist.`,
		otlpEndpoint: e.otlpEndpoint
	};
}
//#endregion
//#region src/manager.ts
var c = class {
	config;
	memoryExporter;
	auditLog = [];
	isBurned = !1;
	sanitizer;
	allowlist;
	constructor(e, t) {
		let n;
		try {
			n = void 0;
		} catch {}
		n ||= (typeof globalThis < "u" ? globalThis : void 0)?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;
		let r = n ? "otlp" : "memory_only";
		this.config = {
			mode: r,
			otlpEndpoint: n || null,
			allowRawPayloads: !1,
			burnEnabled: !0,
			auditDurable: !1,
			networkEgress: r === "otlp" ? "allow_otlp" : "deny",
			serviceName: "knowthankyew-app",
			...e
		};
		let { allowlist: o, sanitize: s } = i(t);
		this.allowlist = o, this.sanitizer = s, this.memoryExporter = new a();
	}
	getConfig() {
		return this.config;
	}
	updateConfig(e) {
		this.config = {
			...this.config,
			...e
		}, this.config.otlpEndpoint && this.config.mode === "memory_only" && (this.config.mode = "otlp", this.config.networkEgress = "allow_otlp");
	}
	sanitizeAttributes(e) {
		return this.sanitizer(e, this.config.allowRawPayloads);
	}
	startSpan(e, t = {}) {
		if (this.config.mode === "disabled" || this.isBurned) return {
			spanId: "noop",
			end: () => {}
		};
		let n = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`, r = Date.now(), i = this.sanitizeAttributes(t);
		return {
			spanId: n,
			end: (t = "OK", a = {}) => {
				if (this.config.mode === "disabled" || this.isBurned) return;
				let s = Date.now(), c = {
					...i,
					...this.sanitizeAttributes(a)
				}, l = {
					id: n,
					name: e,
					startTime: r,
					endTime: s,
					durationMs: s - r,
					status: t,
					attributes: c,
					events: []
				};
				this.memoryExporter.export(l), this.config.mode === "otlp" && this.config.otlpEndpoint && o(this.config.otlpEndpoint, l, this.config.serviceName);
			}
		};
	}
	recordAuditEvent(e, t, n) {
		this.isBurned || this.auditLog.push({
			id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			action: e,
			summary: t,
			details: n ? this.sanitizeAttributes(n) : void 0
		});
	}
	getBufferedSpans() {
		return this.memoryExporter.getSpans();
	}
	getMemorySpans() {
		return this.memoryExporter.getSpans();
	}
	getAuditLog() {
		return this.auditLog;
	}
	downloadSessionAuditJson() {
		let e = {
			generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
			service: this.config.serviceName || "knowthankyew-app",
			telemetryMode: this.config.mode,
			eventCount: this.auditLog.length,
			events: this.auditLog
		};
		return JSON.stringify(e, null, 2);
	}
	getPrivacyAuditReport() {
		let e = this.config.mode !== "otlp" && !this.config.otlpEndpoint && this.config.networkEgress === "deny";
		return {
			telemetryMode: this.config.mode,
			networkEgress: this.config.networkEgress,
			burnEnabled: this.config.burnEnabled,
			durableAudit: this.config.auditDurable,
			otlpEndpoint: this.config.otlpEndpoint || null,
			allowRawPayloads: this.config.allowRawPayloads,
			activeSpanCount: this.memoryExporter.count(),
			sessionAuditCount: this.auditLog.length,
			isLocalOnlyHonest: e
		};
	}
	getPrivacyClaims(e) {
		return s(this.getPrivacyAuditReport(), e);
	}
	burn() {
		this.config.burnEnabled && (this.memoryExporter.clear(), this.auditLog = [], this.isBurned = !0);
	}
	reset() {
		this.memoryExporter.clear(), this.auditLog = [], this.isBurned = !1;
	}
	restartSession() {
		this.reset();
	}
};
//#endregion
export { n as DEFAULT_SAFE_ALLOWLIST_KEYS, t as KTY_HANDOFF_SESSION_KEY, a as MemoryExporter, c as TelemetryManager, i as createAllowlistSanitizer, o as exportToOtlp, r as formatTruncatedDigest, s as getPrivacyClaims, e as validateHandoffPayload };
