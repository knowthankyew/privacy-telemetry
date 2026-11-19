//#region src/sha256.ts
function e(e) {
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
	return o;
}
//#endregion
//#region src/allowlist.ts
var t = /* @__PURE__ */ new Set(/* @__PURE__ */ "rule_id.rule_ids.statute_code.jurisdiction.status.risk_level.duration_ms.duration_sec.clause_count.total_clauses.flagged_clauses.flagged_count.standard_count.watch_count.unenforceable_count.char_count.matched_violations.error_code.job_id.service.action.step.current_step.total_steps.progress_pct.loss.device.adapter_size_bytes.base_model.dataset_hash.exchange.routing_key".split(".")), n = "[REDACTED_BY_DEFAULT_ALLOWLIST]", r = "[REDACTED_SENSITIVE_VALUE]", i = 256, a = 4096, o = 50, s = 3600, c = /[\r\n\x00-\x1f\x7f]/, l = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,24}/, u = /(?:^|\D)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)/, d = /(?:^|\D)(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{1,4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})(?!\d)/, f = /(?:^|\D)(4\d{12}(?:\d{3})?(?:\d{3})?|(?:5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))\d{12}|3[47]\d{13}|(?:6011|65\d{2}|64[4-9]\d)\d{12}(?:\d{3})?)(?!\d)/g, p = /\bBearer\s+[A-Za-z0-9\-._~+/]{1,200}={0,4}|(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,128}|ghp_[A-Za-z0-9]{20,128}|eyJ[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128}\.[A-Za-z0-9_-]{4,128})\b/i, m = /(?:^|[\s"'(=]|file:(?:\/\/(?:localhost)?)?)(?:\/(?:Users|home|tmp|var|private)\/[^\s"')]{1,200}|\/?[A-Za-z]:[\\/]Users[\\/][^\s"')]{1,200})/i, h = /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|(?:job|test-job|run|task|j)[-_](?:[0-9]{1,8}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))$/, g = /^(?:(?:job|test-job|run|task|j)[-_])?(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?!\d{13,19}$)[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/, _ = /^(?:hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/, ee = /^hmac:[a-f0-9]{16,64}$/, te = /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{12,64}|(?:hmac|sha256):[a-f0-9]{16,64})$/, ne = "[REDACTED_KEY]", re = /* @__PURE__ */ "AL.AK.AZ.AR.CA.CO.CT.DE.DC.FL.GA.HI.ID.IL.IN.IA.KS.KY.LA.ME.MD.MA.MI.MN.MS.MO.MT.NE.NV.NH.NJ.NM.NY.NC.ND.OH.OK.OR.PA.RI.SC.SD.TN.TX.UT.VT.VA.WA.WV.WI.WY".split("."), ie = /* @__PURE__ */ new Set([
	"AR-001",
	"AR-002",
	"AR-003",
	"ARB-001",
	"ARB-002",
	"ARB-003",
	"UNI-001",
	"UNI-002",
	"SURV-001",
	"SURV-002",
	"US-CO-001",
	"US-IL-001",
	"US-OR-001",
	"EU-AR-001",
	"EU-AR-002",
	"EU-SURV-001",
	"UK-AR-001",
	"UK-AR-002",
	"UK-CONS-001",
	"CA-SEC-DEP-CAP-01",
	"CA-SEC-DEP-RET-02",
	"CA-ENTRY-NOT-03",
	"CA-EVICT-SLF-04",
	"CA-HABIT-REP-05",
	"CA-LATE-FEE-06",
	"FL-SEC-DEP-RET-01",
	"FL-ENTRY-NOT-02",
	"FL-PROHIB-PRAC-03",
	"FL-HABIT-REP-04",
	"IL-SEC-DEP-RET-01",
	"IL-EVICT-SLF-02",
	"IL-RETALIAT-03",
	"IL-DEP-INT-04",
	"NY-SEC-DEP-CAP-01",
	"NY-SEC-DEP-RET-02",
	"NY-ENTRY-NOT-06",
	"NY-LATE-FEE-03",
	"NY-EVICT-SLF-04",
	"NY-HABIT-WAR-05",
	"NY-OCCUP-ROOM-07",
	"TX-SEC-DEP-RET-01",
	"TX-LATE-FEE-02",
	"TX-LOCKOUT-SLF-03",
	"TX-UTIL-SHUT-04",
	"TX-HABIT-REP-05",
	"FED-FHA-FAM-01",
	"FED-FHA-DIS-02",
	"FED-SCRA-MIL-03",
	"FED-LEAD-DISC-04",
	"illegal_register_shortage_deduction",
	"illegal_uniform_equipment_deduction",
	"salaried_under_exemption_threshold",
	"missing_overtime_multiplier",
	"unexplained_mandatory_fee",
	"salaried_under_threshold",
	"fica_math_mismatch",
	"KTY-WARRANTY-EXCL-001",
	"KTY-WARRANTY-DISCLAIM-001",
	"WARRANTY_VOID_IF_REMOVED",
	"CA_CIV_1950_5",
	"FLSA_EXEMPT_541",
	"implied_warranty_disclaimer",
	...re.map((e) => `state_daily_overtime_${e}`),
	...re.map((e) => `state_implied_override_${e}`)
]), ae = /* @__PURE__ */ new Set([
	"HuggingFaceTB/SmolLM2-135M",
	"google/gemma-2-2b-it",
	"microsoft/BitNet-b1.58-2B-4T"
]);
function oe(e) {
	return ie.has(e) || _.test(e);
}
function se(e) {
	return ae.has(e) || _.test(e);
}
var ce = /^(?:HTTP_)?[45]\d{2}$/, le = /* @__PURE__ */ new Set(/* @__PURE__ */ "edge_inference_notice.unknown_error.internal_error.validation_error.invalid_request.invalid_payload.invalid_argument.unauthorized.forbidden.not_found.conflict.rate_limited.timeout.gateway_timeout.service_unavailable.network_error.network_denied.parse_error.parse_failed.ocr_failed.pdf_extract_failed.model_load_failed.inference_failed.inference_timeout.burn_activated.telemetry_disabled.handoff_rejected.handoff_expired.handoff_invalid.worker_failed.queue_timeout.broker_unavailable.storage_unavailable.ERR_TIMEOUT.ERR_NETWORK.ERR_VALIDATION.ERR_PARSE.ERR_OCR.ERR_PDF.ERR_INFERENCE.ERR_UNAUTHORIZED.ERR_FORBIDDEN.ERR_NOT_FOUND.ERR_RATE_LIMITED.ERR_INTERNAL.ERR_UNAVAILABLE.ERR_CONFLICT.ECONNREFUSED.ETIMEDOUT.ENOTFOUND.ECONNRESET.EPIPE.ENOENT.TimeoutException.TimeoutError.ValidationException.ValidationError.ArgumentException.ArgumentNullException.InvalidOperationException.HttpRequestException.OperationCanceledException.TaskCanceledException.IOException.JsonException.FormatException.KeyNotFoundException.UnauthorizedAccessException.TypeError.ValueError.RuntimeError.KeyError.OSError.NetworkError.AbortError.SyntaxError".split("."));
function ue(e) {
	return le.has(e) || ce.test(e) || _.test(e);
}
var de = /^v?\d{1,4}\.\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:-(?:alpha|beta|rc|preview|nightly|dev|canary)(?:\.\d{1,4})?)?(?:\+(?:[0-9a-f]{7,40}|\d{1,12}))?$/, fe = /^(?:cleveland-clinic-main|mayo-clinic-rochester|ascension-health-national|kaiser-foundation-hospitals|HOSP-\d{1,6}|(?:hosp_|hmac:)[a-f0-9]{16,64})$/, pe = /^(?:\d{4}[A-Z0-9]|hmac:[a-f0-9]{16})$/, me = /(?:^|[._-])(?:tenant|ssn|social_security|email|phone|telephone|mobile|address|street|dob|birth|patient|diagnosis|prognosis|symptom|condition|disease|disorder|hiv|aids|pregnant|pregnancy|cancer|diabetes|medical|clinical|medication|prescription|treatment|mrn|phi|claimant|employee|employer|landlord|wage|salary|income|pay_rate|hourly_rate|annual_salary|gross_pay|net_pay|pay_amount|excerpt|snippet|prompt|raw_text|raw_payload|raw_content|clause_text|document_text|agreement_text|matched_text|matched_clause|matched_snippet|client|customer|victim|plaintiff|defendant|username|full_name|first_name|last_name|company|holdings|corp|corporation|llc|inc|ltd|vendor|merchant|creditor|organization|org|firm|business)(?:\d{0,6})?(?:$|[._-])|(?:^|[._-])name$/, he = /^(?:[a-z][a-z0-9._-]{0,63}|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+){1,3})$/, ge = /^(?:(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|dataset_relative|arbitrary|arbitrary_custom|matched|redflag|domain_custom|safe_custom|safe_registered|unkeyed_cleartext)[._-]?(?:count|cnt|pct|percent|percentage|ms|sec|bytes|score|status|level|tier|channel|path|code|type|key|field)|(?:safe|custom|domain|subscription|plan|review|document|report|artifact|adapter|dataset|matched|redflag)(?:Count|Cnt|Pct|Percent|Percentage|Ms|Sec|Bytes|Score|Status|Level|Tier|Channel|Path|Code|Type|Key|Field)|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$/, _e = /* @__PURE__ */ new Set([
	"agreement_title",
	"hospital_id",
	"household_size",
	"fpl_percentage"
]);
function ve(e) {
	return typeof e == "string" && _e.has(e.toLowerCase());
}
function ye(e) {
	let t = !1, n = !1, i = !1, a = [];
	for (let r of Object.keys(e)) {
		let e = r.toLowerCase();
		e === "hospital_id" ? (t = !0, a.push(r)) : e === "household_size" ? (n = !0, a.push(r)) : e === "fpl_percentage" && (i = !0, a.push(r));
	}
	if (t && n && i) for (let t of a) e[t] = r;
}
var be = /* @__PURE__ */ new Set(/* @__PURE__ */ "hospital_id,cpt_code,statute_code,household_size,fpl_percentage,charity_eligible,unconditional_gift_triggered,line_count,has_itemized_breakdown,discrepancy_count,discount_percent,has_income_verified,has_balance_due,unlawful_count,score_percentage,sidecar_active,agreement_title,ocr_used,state,overtime_hours,regular_hours,redflag_count,is_compliant,parsed_line_count,has_overtime,has_deductions,product_type,product_category,warranty_type,protection_score,violations_count,findings_count,risk_score,has_illegal_tie_in,has_implied_disclaimer,extension.action,extension.rule_category,extension.rule_id,extension.severity,extension.scan_duration_ms,extension.traps_found,extension.critical_count,extension.warning_count,app.version,app.environment,service.instance.id,base_model,dataset_hash,adapter_size_bytes,current_step,total_steps,progress_pct,loss,device,exchange,routing_key,surprisal.preflight.enabled,surprisal.preflight.status,surprisal.preflight.duration_ms,surprisal.cases.original_count,surprisal.cases.ablated_count,surprisal.cases.anomalous_count,howso.preflight.enabled,howso.preflight.status,howso.preflight.duration_ms,howso.cases.original_count,howso.cases.ablated_count,howso.cases.anomalous_count,audit.allowlist_enforced,audit.collector_verified".split(","));
function v(e) {
	return t.has(e) || S.has(e) || C.has(e) || Ne.has(e);
}
function xe(e) {
	return e.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2").toLowerCase();
}
function y(e) {
	return me.test(xe(e));
}
function Se(e) {
	return typeof e == "string" && he.test(e) && !T(e);
}
function b(e) {
	if (!Se(e) || y(e)) return !1;
	let t = e.toLowerCase();
	return v(t) || be.has(t) || ge.test(e);
}
var Ce = /* @__PURE__ */ new WeakSet();
function x(e) {
	if (!e) return;
	if (e instanceof Map && Ce.has(e)) return e;
	let t = /* @__PURE__ */ new Map(), n = e instanceof Map || typeof e.entries == "function" && typeof e.forEach == "function" ? e.entries() : Object.entries(e);
	for (let [e, r] of n) {
		if (!e || !r || !b(e)) continue;
		let n = e.toLowerCase(), i = /* @__PURE__ */ new Set();
		for (let e of r) typeof e == "string" && _.test(e) && i.add(e);
		t.set(n, i);
	}
	if (t.size !== 0) return Ce.add(t), t;
}
var we = /^(?:sha256:)?(?:[0-9a-f]{12,64}|[0-9A-F]{12,64})$/, Te = /* @__PURE__ */ new Set(/* @__PURE__ */ "scan_started,scan_complete,scan_completed,document_ingested,rules_evaluated,audit_performed,handoff_sent,handoff_received,handoff_rejected,edge_inference_started,edge_inference_completed,edge_inference_failed,edge_export,ocr_started,ocr_completed,pdf_extracted,burn,hard_burn,export,dispute_generated,extension.page_scan,evaluate_subscription_agreement,parse_agreement,parse_contract,evaluate_charity_care,audit_medical_bill,parse_bill,evaluate_lease_rules,evaluate_edge_semantic_lora,segment_clauses,audit_evaluation,parse_document,enterprise_job,analyze_paystub,parse_paystub,parse_wage_statement,analyze_warranty,parse_warranty,parse_warranty_card,job.accepted,job.publish_failed,job.published,job.edge_export_requested,job.edge_exported,job.consumed,job.registered,job.completed,job.failed,job.training.started,job.training.finished,job.transition,job.transition.pending,job.transition.queued,job.transition.training,job.transition.succeeded,job.transition.failed,job.transition.cancelled,job.transition.canceled,surprisal.preflight,howso.preflight,rule.evaluated".split(",")), Ee = /^hmac:[a-f0-9]{16}$/, De = /^\[TRUNCATED_HASH_[a-f0-9]{8}\]$/, Oe = /^\d{1,3}\s+(?:U\.?S\.?C\.?|C\.?F\.?R\.?|Stat\.)\s+(?:(?:§§?|Part)\s*)?\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?$/, ke = /^\d{1,4}\s+ILCS\s+\d{1,4}[A-Za-z]?(?:-(?:\d{1,4}|[A-Za-z]))?(?:\/|\/\d{1,4}(?:-\d{1,4})?[A-Za-z]?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?$/, Ae = /^(?:Cal\.|N\.Y\.|Mass\.|Tex\.|Fla\.|Ill\.|Wash\.|Colo\.|Or\.|Pa\.|N\.J\.|Va\.|Md\.|Ga\.|N\.C\.|S\.C\.|Minn\.|Wis\.|Ariz\.|Nev\.|Mich\.|Conn\.|Ind\.|Ohio|Iowa|Utah|Tenn\.|Ky\.|La\.|Ala\.|Ark\.|Kan\.|Mo\.|Neb\.|Mont\.|Idaho|Wyo\.|Me\.|Vt\.|N\.H\.|R\.I\.|Del\.|Alaska|Hawaii|D\.C\.|UCC|FDCPA|FCRA|FLSA|TILA|SCRA|FHA|HIPAA|ROSCA|CCPA|CPRA|BIPA|FTC)(?:\s+(?:Rev\.|Gen\.|Bus\.|Prof\.|Civ\.|Lab\.|Prop\.|Penal|Ins\.|Health|Educ\.|Fin\.|Gov\.|Com\.|Code|Laws?|Stat\.|Act|Ann\.|ch\.|c\.|Part|Title|&|GBL|RPL|Art\.|\d{1,4}[A-Za-z]?)){0,5}(?:,\s*|\s*)(?:§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?|Ch\.\s*\d{1,4}(?:\s*§§?\s*\d{1,5}[A-Za-z]?(?:\.\d{1,4}[A-Za-z]?){0,2}(?:-(?:\d{1,4}|[A-Za-z]))?(?:\((?:\d{1,3}(?:-[A-Za-z])?|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,4}(?:-(?:\d{1,4}|[A-Za-z]))?)?)$/, je = /^(?:EU\s+)?(?:GDPR(?:\s+Art\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?|Directive\s+\d{4}\/\d{1,4}\/[A-Z]{2,4}(?:,?\s+Art(?:icle)?\.?\s*\d{1,4}(?:\.\d{1,4})?(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3})?)$/, Me = /^UK\s+(?:Consumer\s+Rights|DMCC|Data\s+Protection|Employment\s+Rights)\s+Act\s+\d{4}(?:,?\s+(?:Part|Chapter|Section|Sec\.|§)\s*\d{1,4}(?:\((?:\d{1,3}|[A-Za-z]{1,2}|[ivx]{1,4})\)){0,3}){0,3}$/, S = /* @__PURE__ */ new Set(/* @__PURE__ */ "step,current_step,total_steps,loss,http.status_code,duration_ms,duration_sec,progress_pct,adapter_size_bytes,clause_count,total_clauses,flagged_clauses,flagged_count,standard_count,watch_count,unenforceable_count,char_count,matched_violations,extension.scan_duration_ms,extension.traps_found,extension.critical_count,extension.warning_count,household_size,fpl_percentage,line_count,discrepancy_count,discount_percent,parsed_line_count,unlawful_count,score_percentage,overtime_hours,regular_hours,redflag_count,protection_score,violations_count,findings_count,surprisal.preflight.duration_ms,surprisal.cases.original_count,surprisal.cases.ablated_count,surprisal.cases.anomalous_count,howso.preflight.duration_ms,howso.cases.original_count,howso.cases.ablated_count,howso.cases.anomalous_count".split(",")), C = /* @__PURE__ */ new Set([
	"ocr_used",
	"sidecar_active",
	"charity_eligible",
	"unconditional_gift_triggered",
	"has_income_verified",
	"has_balance_due",
	"has_itemized_breakdown",
	"has_deductions",
	"has_overtime",
	"has_illegal_tie_in",
	"has_implied_disclaimer",
	"is_compliant",
	"surprisal.preflight.enabled",
	"howso.preflight.enabled",
	"audit.allowlist_enforced",
	"audit.collector_verified"
]), Ne = /* @__PURE__ */ new Set([
	"rule_id",
	"error_code",
	"device",
	"http.method",
	"job_id",
	"service",
	"service.name",
	"action",
	"status",
	"audit_status",
	"risk_level",
	"exchange",
	"routing_key",
	"error_type",
	"extension.action",
	"extension.rule_category",
	"extension.rule_id",
	"extension.severity",
	"app.version",
	"app.environment",
	"howso.preflight.status",
	"surprisal.preflight.status"
]), Pe = /* @__PURE__ */ new Set(/* @__PURE__ */ "OK.ERROR.UNSET.Pending.Queued.Training.TrainingFinished.Succeeded.Failed.Completed.Cancelled.Canceled.Timeout.Unknown.ok.error.unset.pending.queued.training.training_finished.succeeded.failed.completed.cancelled.canceled.timeout.unknown.degraded.burned.Standard.Watch.Flagged.LikelyUnenforceable.Unenforceable.Compliant.NonCompliant.Disabled.disabled.Skipped.skipped.FellBack".split(".")), Fe = /* @__PURE__ */ new Set(/* @__PURE__ */ "Standard.Watch.Flagged.LikelyUnenforceable.Unenforceable.Compliant.NonCompliant.Passed.Failed.Completed.Pending.OK.ERROR.Unknown.standard.watch.flagged.likely_unenforceable.unenforceable.compliant.non_compliant.passed.failed.completed.pending.ok.error.unknown".split(".")), Ie = /* @__PURE__ */ new Set(/* @__PURE__ */ "Critical.High.Medium.Moderate.Low.Info.Warning.None.Minimal.Elevated.Severe.CRITICAL.HIGH.MEDIUM.MODERATE.LOW.INFO.WARNING.NONE.critical.high.medium.moderate.low.info.warning.none".split(".")), Le = /* @__PURE__ */ new Set([
	"Disabled",
	"Skipped",
	"Completed",
	"FellBack",
	"Passed",
	"Failed",
	"Error",
	"OK",
	"disabled",
	"skipped",
	"completed",
	"fell_back",
	"passed",
	"failed",
	"error",
	"ok"
]), Re = /* @__PURE__ */ new Set([
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"PATCH",
	"OPTIONS",
	"CONNECT",
	"TRACE"
]), ze = /* @__PURE__ */ new Set([
	"cpu",
	"cuda",
	"cuda:0",
	"cuda:1",
	"cuda:2",
	"cuda:3",
	"cuda:4",
	"cuda:5",
	"cuda:6",
	"cuda:7",
	"mps",
	"webgpu",
	"wasm",
	"gpu",
	"npu",
	"ane",
	"xpu",
	"rocm",
	"directml",
	"auto",
	"none",
	"unknown",
	"x64",
	"arm64"
]), Be = /* @__PURE__ */ new Set([
	"scan_started",
	"scan_complete",
	"scan_completed",
	"document_ingested",
	"rules_evaluated",
	"audit_performed",
	"handoff_sent",
	"handoff_received",
	"handoff_rejected",
	"edge_inference_started",
	"edge_inference_completed",
	"edge_inference_failed",
	"edge_export",
	"ocr_started",
	"ocr_completed",
	"pdf_extracted",
	"burn",
	"hard_burn",
	"export",
	"dispute_generated"
]), Ve = /* @__PURE__ */ new Set([
	"AUTO_RENEWAL",
	"ARBITRATION",
	"UNILATERAL_CHANGE",
	"SURVEILLANCE",
	"WARRANTY_DISCLAIMER",
	"WAGE_THEFT",
	"TERMS",
	"BILLING",
	"PRIVACY",
	"DARK_PATTERN"
]), He = /* @__PURE__ */ new Set([
	"knowthankyew-app",
	"privacy-telemetry",
	"knowthankyew-extension",
	"lease-audit",
	"care-check",
	"careCheck",
	"paystub-check",
	"bill-of-rights-bot",
	"warranty-watch",
	"ftaas-api",
	"ftaas-worker",
	"ftaas-inference",
	"surprisal-service",
	"howso-preflight",
	"mail-stripper",
	"mail-stripper-imap",
	"unsubscribe-shield-ext",
	"gradcast",
	"genesis",
	"mac-screen-record",
	"kty-ntfs",
	"enterprise-self-host",
	"test-svc",
	"unknown"
]), Ue = {
	status: Pe,
	audit_status: Fe,
	risk_level: Ie,
	"extension.severity": Ie,
	"howso.preflight.status": Le,
	"surprisal.preflight.status": Le,
	"http.method": Re,
	device: ze,
	action: Be,
	"extension.action": Be,
	"extension.rule_category": Ve,
	service: He,
	"service.name": He,
	"app.environment": /* @__PURE__ */ new Set([
		"development",
		"dev",
		"staging",
		"stage",
		"production",
		"prod",
		"test",
		"testing",
		"ci",
		"local",
		"sandbox",
		"preview",
		"Development",
		"Staging",
		"Production"
	]),
	exchange: /* @__PURE__ */ new Set([
		"ftaas.direct",
		"ftaas.dlx",
		"ftaas.events",
		"ftaas.topic",
		"default",
		"direct"
	]),
	routing_key: /* @__PURE__ */ new Set([
		"job.requested",
		"job.updated",
		"job.status",
		"job.completed",
		"job.failed",
		"job.dlq",
		"job.cancelled",
		"job.canceled",
		"job.progress",
		"job.edge_export"
	])
}, We = /* @__PURE__ */ new Set(/* @__PURE__ */ "AL.AK.AZ.AR.CA.CO.CT.DE.DC.FL.GA.HI.ID.IL.IN.IA.KS.KY.LA.ME.MD.MA.MI.MN.MS.MO.MT.NE.NV.NH.NJ.NM.NY.NC.ND.OH.OK.OR.PA.RI.SC.SD.TN.TX.UT.VT.VA.WA.WV.WI.WY.AS.GU.MP.PR.VI.FED.FEDERAL.FTC.DEFAULT.US.UK.EU.EU_CRD.UK_DMCC.CA-ON.Alabama.Alaska.Arizona.Arkansas.California.Colorado.Connecticut.Delaware.District of Columbia.Florida.Georgia.Hawaii.Idaho.Illinois.Indiana.Iowa.Kansas.Kentucky.Louisiana.Maine.Maryland.Massachusetts.Michigan.Minnesota.Mississippi.Missouri.Montana.Nebraska.Nevada.New Hampshire.New Jersey.New Mexico.New York.North Carolina.North Dakota.Ohio.Oklahoma.Oregon.Pennsylvania.Rhode Island.South Carolina.South Dakota.Tennessee.Texas.Utah.Vermont.Virginia.Washington.West Virginia.Wisconsin.Wyoming.Puerto Rico.American Samoa.Virgin Islands.Guam.Northern Mariana Islands.United States.US Federal.Federal.United Kingdom.European Union".split(".")), Ge = /* @__PURE__ */ new Set([
	"Full",
	"Limited",
	"Disclaimed / As-Is",
	"Unspecified"
]), Ke = /* @__PURE__ */ new Set([
	"Electronics & Laptops",
	"Electronics & Computers",
	"Automotive & EV Accessories",
	"Automotive / EV",
	"Home Appliances",
	"Tools & Hardware",
	"Tools & Equipment",
	"Smart Home Devices",
	"Furniture & Home Goods",
	"General Consumer Product",
	"Consumer Electronics",
	"Automotive Vehicle",
	"Home Appliance",
	"General",
	"Electronics",
	"Automotive",
	"Appliances",
	"Tools"
]);
function w(e, t) {
	if (e === "service.instance.id") return "service_instance_id";
	let n = t ? xe(t) : e;
	return n.endsWith("_path") ? n.startsWith("adapter") ? "adapter_hmac_path" : n.startsWith("dataset_") ? "dataset_jsonl_path" : "path" : e === "rule_ids" ? "rule_ids" : e === "base_model" ? "base_model" : e === "dataset_hash" ? "dataset_hash" : e === "jurisdiction" || e === "state" ? "jurisdiction" : e === "warranty_type" ? "warranty_type" : e === "product_type" || e === "product_category" ? "product_type" : e === "statute_code" ? "statute_code" : e === "hospital_id" ? "hospital_id" : e === "cpt_code" ? "cpt_code" : S.has(e) ? "numeric" : C.has(e) || e.startsWith("is_") || e.startsWith("has_") || e.endsWith(".enabled") || e.endsWith("_enabled") ? "boolean" : Ne.has(e) ? "strict_token" : "custom";
}
function qe(e) {
	return e.length <= 64 && (Oe.test(e) || ke.test(e) || Ae.test(e) || je.test(e) || Me.test(e)) ? e : r;
}
function Je(e, t, n, i, a, o) {
	if (i === "[REDACTED_SENSITIVE_VALUE]") return i;
	let s = o?.has(t) ?? !1;
	if (!a && s && (y(e) || y(t) || !(o?.get(t)?.has(i) ?? !1))) return r;
	if (i === "") return i;
	if (n === "adapter_hmac_path") return i.length === 21 && Ee.test(i) ? i : r;
	if (n === "dataset_jsonl_path") {
		if (i.length > 128 || !i.endsWith(".jsonl")) return r;
		let e = i.slice(0, -6);
		return T(i, { skipSsn: g.test(e) }) ? r : h.test(e) ? i : r;
	}
	let c = ee.test(i);
	return i.length > 128 || T(i, { skipSsn: c }) ? r : a && !De.test(i) || c ? i : r;
}
function Ye(e) {
	if (e === "") return "";
	let t = e.split(",");
	if (t.length > o) return r;
	for (let e of t) if (!oe(e)) return r;
	return e;
}
function Xe(e, t) {
	let n = Ue[e];
	if (n) {
		let i = e === "device" ? t.toLowerCase() : t;
		return n.has(i) ? t : r;
	}
	return e === "job_id" ? h.test(t) ? t : r : e === "rule_id" || e === "extension.rule_id" ? oe(t) ? t : r : e === "error_code" || e === "error_type" ? ue(t) ? t : r : e === "app.version" && de.test(t) ? t : r;
}
function Ze(e, t, n) {
	let a = !t && (n?.has("rule_ids") ?? !1);
	if (a && y("rule_ids")) return r;
	let c = a ? n?.get("rule_ids") : void 0;
	if (e.length === 0) return a ? r : "";
	if (e.length > o) return r;
	let l = [];
	for (let n of e) {
		if (typeof n != "string" || a && !(c?.has(n) ?? !1)) return r;
		let e = t ? n.length > i ? O(n) : n : D("rule_id", n);
		if (e === "[REDACTED_SENSITIVE_VALUE]") return r;
		l.push(e);
	}
	let u = l.join(",");
	return u.length > s ? t ? O(u) : r : u;
}
function Qe(e, t, n, a) {
	let c = e.toLowerCase(), l = w(c, e);
	if (l === "adapter_hmac_path" || l === "dataset_jsonl_path" || l === "path") return Je(e, c, l, t, n, a);
	if (t === "[REDACTED_SENSITIVE_VALUE]" || De.test(t)) return t;
	if (!n && (a?.has(c) ?? !1)) {
		let n = a?.get(c);
		if (y(e) || y(c)) return r;
		if (l === "rule_ids") {
			if (t === "") return r;
			if (t.length > s) return O(t);
			let e = t.split(",");
			if (e.length > o || !e.every((e) => n?.has(e) ?? !1)) return r;
		} else if (!(n?.has(t) ?? !1)) return r;
	}
	if (l === "rule_ids" && t.length <= s) {
		if (n) return t;
		let e = Ye(t);
		if (e !== "[REDACTED_SENSITIVE_VALUE]" && !(e === "" ? [] : e.split(",")).some((e) => T(e, { skipSsn: _.test(e) }))) return e;
	}
	if (t.length > i) return O(t);
	if (n) return t;
	if (T(t, { skipSsn: l === "dataset_hash" && we.test(t) || c === "job_id" && g.test(t) || l === "service_instance_id" && te.test(t) || (l === "base_model" || c === "rule_id" || c === "extension.rule_id" || c === "error_code" || c === "error_type") && _.test(t) || l === "hospital_id" && /^(?:hosp_|hmac:)[a-f0-9]{16,64}$/.test(t) || l === "cpt_code" && Ee.test(t) || l === "custom" && /^(?:hmac|sha256):[a-f0-9]{16,64}$/.test(t) })) return r;
	switch (l) {
		case "numeric":
		case "boolean": return r;
		case "base_model": return se(t) ? t : r;
		case "dataset_hash": return we.test(t) ? t : r;
		case "jurisdiction": return We.has(t) ? t : r;
		case "warranty_type": return Ge.has(t) ? t : r;
		case "product_type": return Ke.has(t) ? t : r;
		case "statute_code": return qe(t);
		case "hospital_id": return fe.test(t) ? t : r;
		case "cpt_code": return pe.test(t) ? t : r;
		case "service_instance_id": return te.test(t) ? t : r;
		case "rule_ids": return Ye(t);
		case "strict_token": return Xe(c, t);
		case "custom": {
			let n = a?.has(c) ?? !1;
			return _.test(t) && (!n || !(y(e) || y(c)) && (a?.get(c)?.has(t) ?? !1)) ? t : r;
		}
	}
}
function $e(e) {
	let t = 0, n = !1;
	for (let r = e.length - 1; r >= 0; r--) {
		let i = e.charCodeAt(r) - 48;
		n && (i *= 2, i > 9 && (i -= 9)), t += i, n = !n;
	}
	return t % 10 == 0;
}
function T(e, t) {
	if (e.length > a || c.test(e) || l.test(e) || !t?.skipSsn && u.test(e) || d.test(e) || p.test(e) || m.test(e)) return !0;
	for (let t of e.matchAll(f)) if ($e(t[1])) return !0;
	return !1;
}
function et(e) {
	return typeof e == "string" && e.length > 0 && e.length <= 128 && Te.has(e) && !T(e);
}
function E(e, t = !1) {
	return e ? t ? e.length > i ? O(e) : e : et(e) && !T(e) ? e : "[REDACTED_SPAN_NAME]" : "[REDACTED_SPAN_NAME]";
}
function D(e, t) {
	return Qe(e, t, !1);
}
function O(t) {
	return `[TRUNCATED_HASH_${e(t).slice(0, 8)}]`;
}
function k(e, a) {
	let o = x(a), s = new Set(t);
	if (e) for (let t of e) {
		if (typeof t != "string") continue;
		let e = t.toLowerCase();
		(v(e) || b(t)) && s.add(e);
	}
	if (o) for (let [e, t] of o.entries()) t.size > 0 && s.add(e);
	return {
		allowlist: s,
		sanitize: (e, a = !1) => {
			let c = {};
			for (let [l, u] of Object.entries(e)) {
				let e = l.toLowerCase(), d = s.has(e), f = v(e);
				if (!a && (!d || !f && !b(l))) {
					c[ne] = n;
					continue;
				}
				let p = a && l.length > i ? O(l) : l;
				if (typeof u == "string") {
					c[p] = Qe(l, u, a, o);
					continue;
				}
				let m = t.has(e) || S.has(e) || C.has(e);
				if (!a && !m && (y(l) || y(e) || T(l))) {
					c[p] = r;
					continue;
				}
				let h = o?.has(e) ?? !1;
				if (typeof u == "number") {
					if (!Number.isFinite(u)) {
						c[p] = r;
						continue;
					}
					if (h && !a) {
						c[p] = r;
						continue;
					}
					let t = w(e);
					c[p] = a || t === "numeric" ? u : r;
					continue;
				}
				if (typeof u == "boolean") {
					if (h && !a) {
						c[p] = r;
						continue;
					}
					let t = w(e);
					c[p] = a || t === "boolean" || t === "custom" ? u : r;
					continue;
				}
				if (Array.isArray(u) && e === "rule_ids") {
					c[p] = Ze(u, a, o);
					continue;
				}
				c[p] = r;
			}
			return a || ye(c), c;
		}
	};
}
//#endregion
//#region src/tombstone.ts
var A = Symbol.for("knowthankyew.privacyTelemetry.realmState.v1"), j = Symbol.for("knowthankyew.privacyTelemetry.liveExporters.v1"), M = Symbol.for("knowthankyew.privacyTelemetry.liveAliases.v1"), tt = Symbol.for("knowthankyew.privacyTelemetry.exportOwnedSpan.v1");
function N(e) {
	return typeof WeakRef < "u" ? new WeakRef(e) : { deref: () => e };
}
function nt(e) {
	if (typeof e != "object" || !e) return !1;
	let t = e;
	return typeof t.hardBurned == "boolean" && t.hardBurnListeners instanceof Set && t.liveManagerRefs instanceof Set && t.liveManagerWipers instanceof WeakMap;
}
function P() {
	let e = globalThis, t = e[A];
	if (nt(t)) return t;
	let n = typeof t == "object" && !!t && !!t.hardBurned, r = /* @__PURE__ */ new Set(), i = /* @__PURE__ */ new Set(), a = /* @__PURE__ */ new WeakMap(), o = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		i.delete(e);
	}) : null, s = {};
	Object.defineProperty(s, "hardBurned", {
		enumerable: !0,
		configurable: !1,
		get: () => n,
		set: (e) => {
			e && (n = !0);
		}
	}), Object.defineProperties(s, {
		hardBurnListeners: {
			value: r,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		liveManagerRefs: {
			value: i,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		liveManagerWipers: {
			value: a,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		liveManagerFinalizer: {
			value: o,
			enumerable: !0,
			writable: !1,
			configurable: !1
		}
	}), Object.preventExtensions(s);
	try {
		return Object.defineProperty(e, A, {
			value: s,
			enumerable: !1,
			writable: !1,
			configurable: !1
		}), s;
	} catch {
		let t = e[A];
		return nt(t) ? (n && (t.hardBurned = !0), t) : (e[A] = s, s);
	}
}
function F() {
	return P();
}
function I() {
	return P().hardBurned;
}
function rt() {
	let e = P(), t = e.hardBurned;
	return e.hardBurned = !0, t;
}
function L(e) {
	if (typeof e != "object" || !e) return !1;
	let t = e;
	return t.refs instanceof Set && t.wipers instanceof WeakMap;
}
function it() {
	let e = globalThis, t = e[j];
	if (L(t)) return t;
	let n = /* @__PURE__ */ new Set(), r = /* @__PURE__ */ new WeakMap(), i = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		n.delete(e);
	}) : null, a = {};
	Object.defineProperties(a, {
		refs: {
			value: n,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		wipers: {
			value: r,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		finalizer: {
			value: i,
			enumerable: !0,
			writable: !1,
			configurable: !1
		}
	}), Object.preventExtensions(a);
	try {
		return Object.defineProperty(e, j, {
			value: a,
			enumerable: !1,
			writable: !1,
			configurable: !1
		}), a;
	} catch {
		let t = e[j];
		return L(t) ? t : (e[j] = a, a);
	}
}
function at(e, t) {
	let { refs: n, wipers: r, finalizer: i } = it();
	r.set(e, t);
	let a = N(e);
	n.add(a), i?.register(e, a);
}
function R(e, t, n) {
	let r = !1, i;
	for (let a of [...e]) {
		let o = a.deref();
		if (!o) {
			e.delete(a);
			continue;
		}
		if (n === void 0 || o !== n) try {
			t.get(o)?.(o);
		} catch (e) {
			r || (r = !0, i = e);
		}
	}
	return {
		hasError: r,
		firstError: i
	};
}
function ot() {
	let { refs: e, wipers: t } = it();
	return R(e, t);
}
function st(e) {
	return L(e) ? e.refsByTarget instanceof WeakMap : !1;
}
function z() {
	let e = globalThis, t = e[M];
	if (st(t)) return t;
	let n = /* @__PURE__ */ new Set(), r = /* @__PURE__ */ new WeakMap(), i = /* @__PURE__ */ new WeakMap(), a = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		n.delete(e);
	}) : null, o = {};
	Object.defineProperties(o, {
		refs: {
			value: n,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		wipers: {
			value: r,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		refsByTarget: {
			value: i,
			enumerable: !0,
			writable: !1,
			configurable: !1
		},
		finalizer: {
			value: a,
			enumerable: !0,
			writable: !1,
			configurable: !1
		}
	}), Object.preventExtensions(o);
	try {
		return Object.defineProperty(e, M, {
			value: o,
			enumerable: !1,
			writable: !1,
			configurable: !1
		}), o;
	} catch {
		let t = e[M];
		return st(t) ? t : (e[M] = o, o);
	}
}
function B(e, t) {
	if (I()) {
		t(e);
		return;
	}
	let { refs: n, wipers: r, refsByTarget: i, finalizer: a } = z();
	if (r.set(e, t), !i.has(e)) {
		let t = N(e);
		n.add(t), i.set(e, t), a?.register(e, t, e);
	}
	I() && t(e);
}
function V(e) {
	let { refs: t, wipers: n, refsByTarget: r, finalizer: i } = z(), a = r.get(e);
	a && (t.delete(a), r.delete(e)), n.delete(e), i?.unregister(e);
}
function ct() {
	let { refs: e, wipers: t } = z();
	return R(e, t);
}
//#endregion
//#region src/exporter.ts
var lt = /^[0-9a-f]{32}$/, ut = /^[0-9a-f]{16}$/, H = "00000000000000000000000000000000", U = "0000000000000000";
function dt(t) {
	let n = typeof t == "string" ? t.trim() : "", r = n.toLowerCase(), i = lt.test(r) && r !== H ? r : e(`kty:trace:${n || "fallback"}`).slice(0, 32);
	i === H && (i = "00000000000000000000000000000001");
	let a = ut.test(r) && r !== U ? r : e(`kty:span:${n || "fallback"}`).slice(0, 16);
	if (a === U && (a = "0000000000000001"), !lt.test(i) || i === H || !ut.test(a) || a === U) throw Error("Invalid OTLP trace or span identifier");
	return {
		traceId: i,
		spanId: a
	};
}
function ft(e) {
	return typeof e == "string" ? { stringValue: e } : typeof e == "number" ? Number.isFinite(e) ? Number.isSafeInteger(e) ? { intValue: e } : { doubleValue: e } : { stringValue: r } : typeof e == "boolean" ? { boolValue: e } : Array.isArray(e) ? { arrayValue: { values: e.map((e) => ft(e)) } } : { stringValue: r };
}
var pt = k();
function W(e) {
	let n = !0, i;
	try {
		i = Reflect.ownKeys(e);
	} catch {
		return !1;
	}
	let a = e;
	for (let o of i) try {
		let i = Object.getOwnPropertyDescriptor(e, o);
		if (!i) continue;
		let s = !1;
		if (i.configurable) try {
			s = Reflect.deleteProperty(e, o);
		} catch {
			s = !1;
		}
		if (!s && !("value" in i && (i.value === "[REDACTED_SENSITIVE_VALUE]" || i.value === "[REDACTED_BY_DEFAULT_ALLOWLIST]"))) try {
			a[o] = r;
		} catch {
			n = !1;
		}
		let c = Object.getOwnPropertyDescriptor(e, o);
		if (c) {
			let e = "value" in c && (c.value === "[REDACTED_SENSITIVE_VALUE]" || c.value === "[REDACTED_BY_DEFAULT_ALLOWLIST]"), r = typeof o == "string" && (o === "[REDACTED_KEY]" || t.has(o));
			(!e || !r) && (n = !1);
		}
	} catch {
		n = !1;
	}
	return n;
}
function G(e, t, n) {
	try {
		let r = Object.getOwnPropertyDescriptor(e, t);
		if (r && "value" in r && r.value === n) return !0;
		if (r && ("get" in r || "set" in r)) return r.configurable && K(e, t, n) ? !0 : (typeof r.get == "function" && e[t], typeof r.set == "function" && (e[t] = n), K(e, t, n));
		e[t] = n;
		let i = Object.getOwnPropertyDescriptor(e, t);
		return i && "value" in i ? i.value === n : K(e, t, n) ? e[t] === n : !1;
	} catch {
		return !1;
	}
}
function K(e, t, n) {
	try {
		let r = Object.getOwnPropertyDescriptor(e, t), i = !!(r && ("get" in r || "set" in r)), a = !r && t in e;
		if (!i && !a) return !0;
		Object.defineProperty(e, t, {
			value: n,
			writable: !0,
			enumerable: r ? r.enumerable ?? !0 : !0,
			configurable: !0
		});
		let o = Object.getOwnPropertyDescriptor(e, t);
		return !!(o && "value" in o && o.value === n);
	} catch {
		return !1;
	}
}
function q(e, t) {
	if (!e || typeof e != "object") return !0;
	let n = !0;
	try {
		let t = e.attributes;
		t && typeof t == "object" && (W(t) || (n = !1)), K(e, "attributes", {}) || (n = !1);
	} catch (e) {
		n = !1, t?.(e);
	}
	return G(e, "name", "[REDACTED]") || (n = !1), G(e, "timestamp", 0) || (n = !1), n;
}
function J(e, t) {
	let n = !0, r = 0;
	try {
		r = e.length;
	} catch (e) {
		return t?.(e), !1;
	}
	for (let i = 0; i < r; i++) try {
		let r = e[i];
		q(r, t) || (n = !1);
	} catch (e) {
		n = !1, t?.(e);
	}
	try {
		e.length = 0;
	} catch {
		try {
			e.length > 0 && !n && (n = !1);
		} catch (e) {
			n = !1, t?.(e);
		}
	}
	return n;
}
function Y(e) {
	let t = !0, n, r = (e) => {
		t = !1, n === void 0 && (n = e);
	};
	try {
		let n = e.attributes;
		n && typeof n == "object" && (W(n) || (t = !1)), K(e, "attributes", {}) || (t = !1);
	} catch (e) {
		r(e);
	}
	try {
		let n = e.events;
		Array.isArray(n) && !J(n, r) && (t = !1), K(e, "events", []) || (t = !1);
	} catch (e) {
		r(e);
	}
	G(e, "name", "[REDACTED_SPAN_NAME]") || (t = !1), G(e, "id", "[REDACTED]") || (t = !1), G(e, "status", "UNSET") || (t = !1), G(e, "startTime", 0) || (t = !1);
	try {
		(Object.getOwnPropertyDescriptor(e, "endTime") || "endTime" in e || e.endTime !== void 0) && !G(e, "endTime", 0) && (t = !1);
	} catch (e) {
		t = !1, r(e);
	}
	try {
		(Object.getOwnPropertyDescriptor(e, "durationMs") || "durationMs" in e || e.durationMs !== void 0) && !G(e, "durationMs", 0) && (t = !1);
	} catch (e) {
		t = !1, r(e);
	}
	return n === void 0 ? { ok: t } : {
		ok: !1,
		error: n
	};
}
function mt(e, t, n) {
	let r = !0, i = 0;
	try {
		i = e.length;
	} catch (e) {
		return n(e), !1;
	}
	for (let a = 0; a < i; a++) try {
		let n = e[a];
		t(n) || (r = !1);
	} catch (e) {
		r = !1, n(e);
	}
	try {
		e.length = 0;
	} catch {}
	return r;
}
function ht(e) {
	if (!Array.isArray(e)) return;
	let t = !0, n, r = (e) => {
		t = !1, n === void 0 && (n = e);
	};
	mt(e, (e) => {
		let r = Y(e);
		return r.ok || (t = !1), r.error !== void 0 && n === void 0 && (n = r.error), r.ok;
	}, r) || (t = !1);
	let i = -1;
	try {
		i = e.length;
	} catch (e) {
		r(e);
	}
	if (t && i === 0 && V(e), n !== void 0) throw n;
	if (!t) throw Error("Telemetry burn could not scrub immutable retained span data.");
}
function gt(e) {
	let t = Y(e);
	if (t.ok && t.error === void 0 && V(e), t.error !== void 0) throw t.error;
	if (!t.ok) throw Error("Telemetry burn could not scrub immutable retained span data.");
}
function _t(e) {
	if (!Array.isArray(e)) return;
	let t, n = (e) => {
		t === void 0 && (t = e);
	}, r = J(e, n), i = -1;
	try {
		i = e.length;
	} catch (e) {
		n(e);
	}
	if (r && t === void 0 && i === 0 && V(e), t !== void 0) throw t;
	if (!r) throw Error("Telemetry burn could not scrub immutable retained span data.");
}
function vt(e) {
	let t, n = q(e, (e) => {
		t === void 0 && (t = e);
	});
	if (n && t === void 0 && V(e), t !== void 0) throw t;
	if (!n) throw Error("Telemetry burn could not scrub immutable retained span data.");
}
function yt(e) {
	if (W(e)) {
		V(e);
		return;
	}
	throw Error("Telemetry burn could not scrub immutable retained span data.");
}
var X = class {
	aliasWiper;
	tracked = /* @__PURE__ */ new WeakSet();
	refs = /* @__PURE__ */ new Set();
	finalizer = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		this.refs.delete(e);
	}) : void 0;
	constructor(e) {
		this.aliasWiper = e;
	}
	track(e) {
		if (!e || typeof e != "object" || this.tracked.has(e)) return !1;
		this.tracked.add(e);
		let t = new WeakRef(e);
		return this.refs.add(t), this.finalizer?.register(e, t, e), this.aliasWiper && B(e, this.aliasWiper), !0;
	}
	untrack(e, t) {
		this.refs.delete(e), t && (this.finalizer?.unregister(t), this.tracked.delete(t), this.aliasWiper && V(t));
	}
};
function bt(e) {
	e instanceof Q && e.clear();
}
function Z(e, t) {
	let n = Reflect.ownKeys(e), r = Object.entries(t);
	if (n.length === r.length && n.every((n) => {
		if (typeof n != "string" || !Object.prototype.hasOwnProperty.call(t, n)) return !1;
		let r = Object.getOwnPropertyDescriptor(e, n);
		return !(!r || "get" in r || "set" in r || !Object.is(r.value, t[n]));
	})) return !0;
	try {
		for (let r of n) if ((typeof r != "string" || !Object.prototype.hasOwnProperty.call(t, r)) && !Reflect.deleteProperty(e, r)) return !1;
		for (let [t, n] of r) {
			let r = Object.getOwnPropertyDescriptor(e, t);
			if (r && ("get" in r || "set" in r) || !r && t in e) {
				if (r && !r.configurable) return !1;
				Object.defineProperty(e, t, {
					value: n,
					writable: !0,
					enumerable: !0,
					configurable: !0
				});
			} else e[t] = n;
			let i = Object.getOwnPropertyDescriptor(e, t);
			if (!i || "get" in i || "set" in i || !Object.is(i.value, n)) return !1;
		}
		return !0;
	} catch {
		return !1;
	}
}
var Q = class {
	spans = [];
	maxCapacity;
	allowRawPayloads;
	sanitizer;
	isClearing = !1;
	spanArrayTracker = new X(ht);
	spanTracker = new X(gt);
	eventArrayTracker = new X(_t);
	eventTracker = new X(vt);
	childRecordTracker = new X(yt);
	constructor(e = 500, t) {
		this.maxCapacity = e, this.allowRawPayloads = t?.allowRawPayloads === !0, this.sanitizer = k(t?.additionalKeys, t?.customValueDomains), at(this, bt);
	}
	hasRetainedState() {
		return this.spans.length > 0 || this.spanArrayTracker.refs.size > 0 || this.spanTracker.refs.size > 0 || this.eventArrayTracker.refs.size > 0 || this.eventTracker.refs.size > 0 || this.childRecordTracker.refs.size > 0;
	}
	trackSpanChildren(e) {
		try {
			let t = e.attributes;
			t && typeof t == "object" && this.childRecordTracker.track(t);
		} catch {}
		try {
			let t = e.events;
			if (Array.isArray(t)) {
				this.eventArrayTracker.track(t);
				for (let e of t) if (e && typeof e == "object") {
					this.eventTracker.track(e);
					try {
						let t = e.attributes;
						t && typeof t == "object" && this.childRecordTracker.track(t);
					} catch {}
				}
			}
		} catch {}
	}
	trackSpanRecord(e) {
		e && typeof e == "object" && (this.spanTracker.track(e), this.trackSpanChildren(e));
	}
	enqueueSpan(e, t) {
		if (!(this.isClearing || I())) {
			if (t && (this.trackSpanRecord(e), I())) {
				this.hasRetainedState() && this.clear();
				return;
			}
			if (!Object.isExtensible(this.spans)) {
				this.spanArrayTracker.track(this.spans);
				let t = [...this.spans];
				if (I()) {
					for (let e of t) try {
						Y(e);
					} catch {}
					try {
						Y(e);
					} catch {}
					this.hasRetainedState() && this.clear();
					return;
				}
				this.spans = t;
			}
			this.spans.push(e), this.spans.length > this.maxCapacity && this.spans.shift();
		}
	}
	sanitizeStandaloneSpan(e, t) {
		let n = e, r = (e, t) => {
			try {
				return e();
			} catch {
				return t;
			}
		}, i = {}, a = [], o = () => {
			if (n === e) {
				let o = r(() => e.id, "[REDACTED]"), s = r(() => e.name, ""), c = r(() => e.startTime, 0), l = r(() => e.endTime, void 0), u = r(() => e.durationMs, void 0), d = r(() => e.status, "UNSET");
				n = {
					id: typeof o == "string" ? o : "[REDACTED]",
					name: E(typeof s == "string" ? s : "", t),
					startTime: typeof c == "number" && Number.isFinite(c) ? c : 0,
					endTime: typeof l == "number" && Number.isFinite(l) ? l : void 0,
					durationMs: typeof u == "number" && Number.isFinite(u) ? u : void 0,
					status: d === "OK" || d === "ERROR" || d === "UNSET" ? d : "UNSET",
					attributes: i,
					events: a
				}, this.spanTracker.track(n);
			}
			return n;
		};
		if (t) {
			try {
				let t = e.name;
				if (typeof t == "string" && t.length > 256) {
					let n = E(t, !0);
					try {
						e.name = n;
						let t = Object.getOwnPropertyDescriptor(e, "name");
						(!t || "get" in t || t.value !== n) && (o().name = n);
					} catch {
						o().name = n;
					}
				}
			} catch {}
			try {
				if (typeof Object.getOwnPropertyDescriptor(e, "attributes")?.get != "function") {
					let t = e.attributes;
					if (t && typeof t == "object") {
						if (i = t, Object.keys(t).some((e) => {
							let n = Object.getOwnPropertyDescriptor(t, e);
							if (typeof n?.get == "function") return !1;
							let r = n?.value;
							return e.length > 256 || typeof r == "string" && r.length > 256;
						})) {
							let r = this.sanitizer.sanitize(t, !0);
							if (i = r, !Z(t, r) || n !== e) {
								this.childRecordTracker.track(r);
								try {
									n.attributes = r, n.attributes !== r && (o().attributes = r);
								} catch {
									o().attributes = r;
								}
							}
						} else n !== e && (n.attributes = i);
					}
				}
			} catch {}
			try {
				if (typeof Object.getOwnPropertyDescriptor(e, "events")?.get != "function") {
					let t = e.events;
					if (Array.isArray(t)) {
						a = t;
						let r = !1, i = [];
						for (let e = 0; e < t.length; e++) {
							let n = t[e];
							if (!n || typeof n != "object") {
								i.push(n);
								continue;
							}
							let a = !1, o = n.name;
							if (typeof o == "string" && o.length > 256) {
								o = E(o, !0);
								try {
									n.name = o;
									let e = Object.getOwnPropertyDescriptor(n, "name");
									(!e || "get" in e || e.value !== o) && (a = !0);
								} catch {
									a = !0;
								}
							}
							let s = n.attributes;
							if (typeof Object.getOwnPropertyDescriptor(n, "attributes")?.get != "function" && s && typeof s == "object") {
								let e = s;
								if (Object.keys(e).some((t) => {
									let n = Object.getOwnPropertyDescriptor(e, t);
									if (typeof n?.get == "function") return !1;
									let r = n?.value;
									return t.length > 256 || typeof r == "string" && r.length > 256;
								})) {
									let t = this.sanitizer.sanitize(e, !0);
									if (s = t, !Z(e, t)) {
										this.childRecordTracker.track(t);
										try {
											n.attributes = t, n.attributes !== t && (a = !0);
										} catch {
											a = !0;
										}
									}
								}
							}
							if (a) {
								let e = {
									name: typeof o == "string" ? o : "[REDACTED_SPAN_NAME]",
									timestamp: typeof n.timestamp == "number" && Number.isFinite(n.timestamp) ? n.timestamp : 0,
									attributes: s && typeof s == "object" ? s : {}
								};
								this.eventTracker.track(e), i.push(e), r = !0;
							} else i.push(n);
						}
						if (r) {
							a = i, this.eventArrayTracker.track(i);
							try {
								n.events = i, n.events !== i && (o().events = i);
							} catch {
								o().events = i;
							}
						} else n !== e && (n.events = a);
					}
				}
			} catch {}
			return n;
		}
		try {
			let t = Object.getOwnPropertyDescriptor(e, "name"), r = typeof t?.get == "function" || typeof t?.set == "function" || !t && "name" in e, i = e.name, a = E(typeof i == "string" ? i : "", !1);
			if (r || i !== a) try {
				r && t?.configurable && n === e ? Object.defineProperty(n, "name", {
					value: a,
					writable: !0,
					enumerable: !0,
					configurable: !0
				}) : n.name = a;
				let i = Object.getOwnPropertyDescriptor(n, "name");
				(!i || "get" in i || "set" in i || i.value !== a) && (o().name = a);
			} catch {
				o().name = a;
			}
		} catch {
			o().name = "[REDACTED_SPAN_NAME]";
		}
		try {
			let t = e.attributes;
			if (t && typeof t == "object") {
				let r = this.sanitizer.sanitize(t, !1), a = Object.getOwnPropertyDescriptor(e, "attributes"), s = typeof a?.get == "function" || typeof a?.set == "function" || !a && "attributes" in e, c = Z(t, r);
				if (i = !s && c ? t : r, s || !c || n !== e) {
					this.childRecordTracker.track(i);
					try {
						s && a?.configurable && n === e ? Object.defineProperty(n, "attributes", {
							value: i,
							writable: !0,
							enumerable: !0,
							configurable: !0
						}) : n.attributes = i;
						let t = Object.getOwnPropertyDescriptor(n, "attributes");
						(!t || "get" in t || "set" in t || t.value !== i) && (o().attributes = i);
					} catch {
						o().attributes = i;
					}
				}
			} else this.childRecordTracker.track(i), o().attributes = i;
		} catch {
			let e = {};
			i = e, this.childRecordTracker.track(e), o().attributes = e;
		}
		try {
			let t = Object.getOwnPropertyDescriptor(e, "events"), i = typeof t?.get == "function" || typeof t?.set == "function" || !t && "events" in e, s = e.events;
			if (Array.isArray(s)) {
				let c = i, l = [];
				for (let e = 0; e < s.length; e++) {
					let t = s[e];
					if (!t || typeof t != "object") {
						c = !0;
						continue;
					}
					let n = Object.getOwnPropertyDescriptor(t, "name"), a = typeof n?.get == "function" || typeof n?.set == "function" || !n && "name" in t, o = t.name, u = E(typeof o == "string" ? o : "", !1), d = i || a;
					if (!d && o !== u) try {
						t.name = u;
						let e = Object.getOwnPropertyDescriptor(t, "name");
						(!e || "get" in e || "set" in e || e.value !== u) && (d = !0);
					} catch {
						d = !0;
					}
					let f = {}, p = Object.getOwnPropertyDescriptor(t, "attributes"), m = typeof p?.get == "function" || typeof p?.set == "function" || !p && "attributes" in t, h = t.attributes;
					if (h && typeof h == "object") {
						f = this.sanitizer.sanitize(h, !1);
						let e = Z(h, f);
						if (!d && (m || !e)) {
							this.childRecordTracker.track(f);
							try {
								m && p?.configurable ? Object.defineProperty(t, "attributes", {
									value: f,
									writable: !0,
									enumerable: !0,
									configurable: !0
								}) : t.attributes = f;
								let e = Object.getOwnPropertyDescriptor(t, "attributes");
								(!e || "get" in e || "set" in e || e.value !== f) && (d = !0);
							} catch {
								d = !0;
							}
						}
					} else d = !0;
					if (d) {
						this.childRecordTracker.track(f);
						let e = r(() => t.timestamp, 0), n = {
							name: u,
							timestamp: typeof e == "number" && Number.isFinite(e) ? e : 0,
							attributes: f
						};
						this.eventTracker.track(n), l.push(n), c = !0;
					} else l.push(t);
				}
				if (a = c ? l : s, c || n !== e) {
					this.eventArrayTracker.track(a);
					try {
						i && t?.configurable && n === e ? Object.defineProperty(n, "events", {
							value: a,
							writable: !0,
							enumerable: !0,
							configurable: !0
						}) : n.events = a;
						let r = Object.getOwnPropertyDescriptor(n, "events");
						(!r || "get" in r || "set" in r || r.value !== a) && (o().events = a);
					} catch {
						o().events = a;
					}
				}
			} else o().events = a;
		} catch {
			a = [], o().events = [];
		}
		return n;
	}
	export(e, t) {
		if (this.isClearing || I() || !e || typeof e != "object") return;
		if (this.trackSpanRecord(e), I()) {
			this.hasRetainedState() && this.clear();
			return;
		}
		let n = (t?.allowRawPayloads ?? this.allowRawPayloads) === !0, r = this.sanitizeStandaloneSpan(e, n);
		if (I()) {
			this.hasRetainedState() && this.clear();
			return;
		}
		this.enqueueSpan(r, !1);
	}
	[tt](e) {
		this.enqueueSpan(e, !1);
	}
	getSpans() {
		if (I() || this.spans.length === 0) return [];
		let e = () => {
			for (let e of t) try {
				Y(e);
			} catch {}
			return t.length = 0, this.hasRetainedState() && this.clear(), [];
		}, t = [...this.spans];
		if (I()) return e();
		this.spanArrayTracker.track(t);
		for (let e of t) this.trackSpanRecord(e);
		return I() ? e() : t;
	}
	clear() {
		if (!this.isClearing) {
			this.isClearing = !0;
			try {
				let e = this.spans;
				this.spans = [];
				let t = !0, n, r = (e) => {
					t = !1, n === void 0 && (n = e);
				}, i = (e) => {
					try {
						let r = Y(e);
						return r.ok || (t = !1), r.error !== void 0 && n === void 0 && (n = r.error), r.ok;
					} catch (e) {
						return r(e), !1;
					}
				}, a = (e) => mt(e, i, r);
				try {
					a(e);
				} catch (e) {
					r(e);
				}
				for (let n of [...this.spanArrayTracker.refs]) {
					let i = n.deref();
					if (!i) {
						this.spanArrayTracker.untrack(n);
						continue;
					}
					try {
						let o = i === e ? t : a(i), s = -1;
						try {
							s = i.length;
						} catch (e) {
							r(e);
						}
						o && s === 0 && this.spanArrayTracker.untrack(n, i);
					} catch (e) {
						r(e);
					}
				}
				for (let e of [...this.spanTracker.refs]) {
					let t = e.deref();
					if (!t) {
						this.spanTracker.untrack(e);
						continue;
					}
					i(t) && this.spanTracker.untrack(e, t);
				}
				for (let e of [...this.eventArrayTracker.refs]) {
					let n = e.deref();
					if (!n) {
						this.eventArrayTracker.untrack(e);
						continue;
					}
					try {
						let i = J(n, r);
						i || (t = !1), i && n.length === 0 && this.eventArrayTracker.untrack(e, n);
					} catch (e) {
						r(e);
					}
				}
				for (let e of [...this.eventTracker.refs]) {
					let n = e.deref();
					if (!n) {
						this.eventTracker.untrack(e);
						continue;
					}
					q(n, r) ? this.eventTracker.untrack(e, n) : t = !1;
				}
				for (let e of [...this.childRecordTracker.refs]) {
					let n = e.deref();
					if (!n) {
						this.childRecordTracker.untrack(e);
						continue;
					}
					try {
						W(n) ? this.childRecordTracker.untrack(e, n) : t = !1;
					} catch (e) {
						r(e);
					}
				}
				if (n !== void 0) throw n;
				if (!t) throw Error("Telemetry burn could not scrub immutable retained span data.");
			} finally {
				this.isClearing = !1;
			}
		}
	}
	count() {
		return this.spans.length;
	}
};
async function xt(e, t, n = "knowthankyew-app", r, i = !1, a, o, s) {
	try {
		if (typeof fetch > "u" || s?.() || I()) return;
		let c = r ? r(t.attributes) : t.attributes, l = a || o ? k(a, o) : pt, u = l.sanitize(c, i), d = n || "knowthankyew-app", f = i ? d.length > 256 ? O(d) : d : D("service", d), p = E(t.name, i), { traceId: m, spanId: h } = dt(t.id), g = JSON.stringify({ resourceSpans: [{
			resource: { attributes: [{
				key: "service.name",
				value: { stringValue: f }
			}] },
			scopeSpans: [{ spans: [{
				traceId: m,
				spanId: h,
				name: p,
				startTimeUnixNano: String(Math.trunc(t.startTime * 1e6)),
				endTimeUnixNano: String(Math.trunc((t.endTime || t.startTime) * 1e6)),
				attributes: Object.entries(u).filter(([e]) => i || l.allowlist.has(e.toLowerCase()) && !ve(e)).map(([e, t]) => ({
					key: e,
					value: ft(t)
				})),
				status: { code: t.status === "OK" ? 1 : t.status === "ERROR" ? 2 : 0 }
			}] }]
		}] });
		if ((s?.() ?? !1) || I()) return;
		await fetch(e, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: g
		});
	} catch {}
}
//#endregion
//#region src/claims.ts
function St(e, t) {
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
var Ct = 500, wt = {
	document_ingested: "Local document ingested for analysis",
	rules_evaluated: "Compliance rules evaluated locally",
	letter_generated: "Local dispute or response letter generated",
	burn_invoked: "Volatile telemetry burn invoked",
	audit_performed: "Local privacy or compliance audit completed",
	edge_inference_started: "In-browser edge inference started",
	edge_inference_completed: "In-browser edge inference completed",
	edge_inference_failed: "In-browser edge inference failed",
	handoff_received: "Cross-engine handoff received",
	handoff_rejected: "Cross-engine handoff rejected",
	handoff_sent: "Cross-engine handoff dispatched",
	scan_started: "Local compliance scan started",
	scan_complete: "Local compliance scan completed",
	scan_completed: "Local compliance scan completed",
	ocr_started: "Local OCR processing started",
	ocr_completed: "Local OCR processing completed",
	pdf_extracted: "Local PDF text extraction completed",
	burn: "Volatile telemetry burned",
	hard_burn: "Hard burn teardown executed",
	export: "Local export generated",
	dispute_generated: "Local dispute draft generated"
};
function $(e) {
	let t = !0, n;
	try {
		let n = e.details;
		n && typeof n == "object" && (W(n) || (t = !1)), K(e, "details", void 0) || (t = !1);
	} catch (e) {
		t = !1, n = e;
	}
	return G(e, "summary", "[REDACTED_AUDIT_SUMMARY]") || (t = !1), G(e, "action", "[REDACTED_ACTION]") || (t = !1), G(e, "id", "[REDACTED]") || (t = !1), G(e, "timestamp", "") || (t = !1), n === void 0 ? { ok: t } : {
		ok: !1,
		error: n
	};
}
function Tt(e) {
	let t = $(e);
	if (t.ok && t.error === void 0 && V(e), t.error !== void 0) throw t.error;
	if (!t.ok) throw Error("Telemetry burn could not scrub immutable retained audit record.");
}
function Et(e) {
	if (W(e)) {
		V(e);
		return;
	}
	throw Error("Telemetry burn could not scrub immutable retained audit record.");
}
function Dt() {
	let { hardBurnListeners: e } = F();
	for (let t of [...e]) try {
		t();
	} catch {}
}
var Ot = !1;
function kt(e, t) {
	let n = rt();
	if (Ot) return;
	Ot = !0;
	let r, i = !1;
	try {
		if (t) try {
			t();
		} catch (e) {
			r = e, i = !0;
		}
		let { liveManagerRefs: n, liveManagerWipers: a } = F(), o = R(n, a, e);
		o.hasError && !i && (r = o.firstError, i = !0);
		let s = ot();
		s.hasError && !i && (r = s.firstError, i = !0);
		let c = ct();
		c.hasError && !i && (r = c.firstError, i = !0);
	} finally {
		Ot = !1;
	}
	if (n || Dt(), i) throw r;
}
function At() {
	kt();
}
function jt(e) {
	let { hardBurnListeners: t } = F();
	return t.add(e), () => {
		t.delete(e);
	};
}
var Mt = class e {
	config;
	otlpProvisionedAtInit;
	memoryExporter;
	auditLog = [];
	isBurned = !1;
	sanitizer;
	normalizedCustomDomains;
	issuedAuditRecordRefs = /* @__PURE__ */ new Set();
	issuedAuditRecordFinalizer = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		this.issuedAuditRecordRefs.delete(e);
	}) : void 0;
	issuedAuditDetailsRefs = /* @__PURE__ */ new Set();
	issuedAuditDetailsFinalizer = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		this.issuedAuditDetailsRefs.delete(e);
	}) : void 0;
	pendingSpanCaptureRefs = /* @__PURE__ */ new Set();
	pendingSpanCaptureFinalizer = typeof FinalizationRegistry < "u" ? new FinalizationRegistry((e) => {
		this.pendingSpanCaptureRefs.delete(e);
	}) : void 0;
	allowlist;
	constructor(t, n, r) {
		let i;
		try {
			i = void 0;
		} catch {}
		i ||= (typeof globalThis < "u" ? globalThis : void 0)?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;
		let a = i ? "otlp" : "memory_only", o = {
			mode: a,
			otlpEndpoint: i || null,
			allowRawPayloads: !1,
			burnEnabled: !0,
			auditDurable: !1,
			networkEgress: a === "otlp" ? "allow_otlp" : "deny",
			serviceName: "knowthankyew-app",
			...t
		};
		t?.networkEgress === void 0 && (o.networkEgress = o.mode === "otlp" && o.otlpEndpoint ? "allow_otlp" : "deny"), this.config = o, this.otlpProvisionedAtInit = !!(o.mode === "otlp" && o.otlpEndpoint && o.networkEgress === "allow_otlp"), this.normalizedCustomDomains = x(r);
		let { allowlist: s, sanitize: c } = k(n, this.normalizedCustomDomains);
		this.allowlist = s, this.sanitizer = c, this.memoryExporter = new Q(), I() && (this.isBurned = !0);
		let { liveManagerRefs: l, liveManagerFinalizer: u, liveManagerWipers: d } = F(), f = N(this);
		l.add(f), u?.register(this, f), d.set(this, e.wipeInstance);
	}
	static wipeInstance(t) {
		t instanceof e && (t.isBurned = !0, t.scrubAllStorage());
	}
	isScrubbingStorage = !1;
	scrubAllStorage() {
		if (this.isScrubbingStorage) return;
		this.isScrubbingStorage = !0;
		let e, t = !1;
		try {
			try {
				this.clearPendingSpanCaptures();
			} catch (n) {
				t ||= (e = n, !0);
			}
			try {
				this.clearAuditLogStorage();
			} catch (n) {
				t ||= (e = n, !0);
			}
			try {
				this.memoryExporter.clear();
			} catch (n) {
				t ||= (e = n, !0);
			}
			if (t) throw e;
		} finally {
			this.isScrubbingStorage = !1;
		}
	}
	clearAuditLogStorage() {
		let e = this.auditLog;
		this.auditLog = [];
		let t = !0, n, r = !1, i = (e) => {
			t = !1, r ||= (n = e, !0);
		};
		for (let n of e) try {
			let e = $(n);
			e.ok || (t = !1), e.error !== void 0 && i(e.error);
		} catch (e) {
			i(e);
		}
		try {
			e.length = 0;
		} catch {}
		for (let e of [...this.issuedAuditRecordRefs]) {
			let n = e.deref();
			if (!n) {
				this.issuedAuditRecordRefs.delete(e);
				continue;
			}
			try {
				let r = $(n);
				r.ok && r.error === void 0 ? (this.issuedAuditRecordRefs.delete(e), this.issuedAuditRecordFinalizer?.unregister(n), V(n)) : (t = !1, r.error !== void 0 && i(r.error));
			} catch (e) {
				i(e);
			}
		}
		for (let e of [...this.issuedAuditDetailsRefs]) {
			let n = e.deref();
			if (!n) {
				this.issuedAuditDetailsRefs.delete(e);
				continue;
			}
			try {
				W(n) ? (this.issuedAuditDetailsRefs.delete(e), this.issuedAuditDetailsFinalizer?.unregister(n), V(n)) : t = !1;
			} catch (e) {
				i(e);
			}
		}
		if (r) throw n;
		if (!t) throw Error("Telemetry burn could not scrub immutable retained audit record.");
	}
	scrubPendingSpanCapture(e) {
		if (e.ref &&= (this.pendingSpanCaptureRefs.delete(e.ref), void 0), this.pendingSpanCaptureFinalizer?.unregister(e), e.cleared) return;
		e.cleared = !0, e.safeName = "[REDACTED_SPAN_NAME]";
		let t = e.sanitizedAttrs;
		if (e.sanitizedAttrs = null, t && !W(t)) throw Error("Telemetry burn could not scrub immutable pending span attributes.");
	}
	clearPendingSpanCaptures() {
		let e, t = !1;
		for (let n of [...this.pendingSpanCaptureRefs]) {
			let r = n.deref();
			if (!r) {
				this.pendingSpanCaptureRefs.delete(n);
				continue;
			}
			try {
				this.scrubPendingSpanCapture(r);
			} catch (n) {
				t ||= (e = n, !0);
			}
		}
		if (t) throw e;
	}
	createPendingSpanHandle(e, t, n, r) {
		return {
			spanId: e,
			end: (i = "OK", a = {}) => {
				try {
					if (this.isDisabledOrTombstoned() || n.cleared) return;
					let r = Date.now(), o = i === "OK" || i === "ERROR" || i === "UNSET" ? i : "UNSET", s = this.sanitizeAttributes({
						...n.sanitizedAttrs ?? {},
						...this.sanitizeAttributes(a)
					});
					if (this.isDisabledOrTombstoned() || n.cleared) return;
					let c = {
						id: e,
						name: E(n.safeName, this.config.allowRawPayloads),
						startTime: t,
						endTime: r,
						durationMs: r - t,
						status: o,
						attributes: s,
						events: []
					};
					this.memoryExporter[tt](c), this.otlpProvisionedAtInit && this.config.mode === "otlp" && this.config.otlpEndpoint && this.config.networkEgress === "allow_otlp" && xt(this.config.otlpEndpoint, c, this.config.serviceName, (e) => this.sanitizeAttributes(e), this.config.allowRawPayloads, this.allowlist, this.normalizedCustomDomains, () => this.isTombstoned() || this.config.mode !== "otlp" || !this.config.otlpEndpoint || this.config.networkEgress !== "allow_otlp");
				} finally {
					r();
				}
			}
		};
	}
	isTombstoned() {
		return this.isBurned || I();
	}
	isDisabledOrTombstoned() {
		return this.config.mode === "disabled" || this.isTombstoned() || this.isScrubbingStorage;
	}
	getConfig() {
		return this.config;
	}
	updateConfig(e) {
		this.config = {
			...this.config,
			...e
		}, this.config.otlpEndpoint && this.config.mode === "memory_only" && (this.config.mode = "otlp", e.networkEgress === "allow_otlp" && (this.config.networkEgress = "allow_otlp"));
	}
	sanitizeAttributes(e) {
		return this.sanitizer(e, this.config.allowRawPayloads);
	}
	startSpan(e, t = {}) {
		if (this.isDisabledOrTombstoned()) return {
			spanId: "noop",
			end: () => {}
		};
		let n = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`, r = Date.now(), i = this.config.allowRawPayloads, a = E(e, i), o = this.sanitizeAttributes(t);
		if (this.isDisabledOrTombstoned() || this.config.allowRawPayloads !== i && (a = E(e, this.config.allowRawPayloads), o = this.sanitizeAttributes(o), this.isDisabledOrTombstoned())) return W(o), {
			spanId: "noop",
			end: () => {}
		};
		let s = {
			safeName: a,
			sanitizedAttrs: o,
			cleared: !1
		}, c = N(s);
		return s.ref = c, this.pendingSpanCaptureRefs.add(c), this.pendingSpanCaptureFinalizer?.register(s, c, s), this.createPendingSpanHandle(n, r, s, () => {
			this.scrubPendingSpanCapture(s);
		});
	}
	recordAuditEvent(e, t, n) {
		if (this.isTombstoned() || this.isScrubbingStorage) return;
		let r = this.config.allowRawPayloads, i = n ? this.sanitizeAttributes(n) : void 0;
		if (this.isTombstoned() || this.isScrubbingStorage) {
			i && W(i);
			return;
		}
		if (i && this.config.allowRawPayloads !== r && (i = this.sanitizeAttributes(i), this.isTombstoned() || this.isScrubbingStorage)) {
			W(i);
			return;
		}
		let a = Object.prototype.hasOwnProperty.call(wt, e), o = this.config.allowRawPayloads ? e.length > 128 ? O(e) : e : a ? e : "[REDACTED_ACTION]", s = this.config.allowRawPayloads ? t.length > 256 ? O(t) : t : a ? wt[e] : "[REDACTED_AUDIT_SUMMARY]";
		for (this.auditLog.push({
			id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			action: o,
			summary: s,
			details: i
		}); this.auditLog.length > Ct;) this.auditLog.shift();
	}
	getBufferedSpans() {
		return this.memoryExporter.getSpans();
	}
	getMemorySpans() {
		return this.memoryExporter.getSpans();
	}
	getAuditLog() {
		return this.isTombstoned() || this.isScrubbingStorage ? [] : this.auditLog.map((e) => {
			let t = e.details ? { ...e.details } : void 0;
			if (t) {
				let e = N(t);
				this.issuedAuditDetailsRefs.add(e), this.issuedAuditDetailsFinalizer?.register(t, e, t), B(t, Et);
			}
			let n = {
				...e,
				...t ? { details: t } : {}
			}, r = N(n);
			return this.issuedAuditRecordRefs.add(r), this.issuedAuditRecordFinalizer?.register(n, r, n), B(n, Tt), n;
		});
	}
	downloadSessionAuditJson() {
		let e = this.isTombstoned() || this.isScrubbingStorage ? [] : this.auditLog, t = {
			generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
			service: this.config.serviceName || "knowthankyew-app",
			telemetryMode: this.config.mode,
			eventCount: e.length,
			events: e
		};
		return JSON.stringify(t, null, 2);
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
		return St(this.getPrivacyAuditReport(), e);
	}
	burn() {
		this.config.burnEnabled && (this.isBurned = !0, kt(this, () => this.scrubAllStorage()));
	}
	reset() {
		try {
			this.scrubAllStorage();
		} finally {
			this.isBurned = this.isBurned || I();
		}
	}
	restartSession() {
		this.reset();
	}
}, Nt = "kty_handoff", Pt = /* @__PURE__ */ new Set([
	"AUTO_RENEWAL",
	"ARBITRATION",
	"UNILATERAL_CHANGE",
	"SURVEILLANCE",
	"WARRANTY_DISCLAIMER"
]), Ft = /* @__PURE__ */ new Set([
	"CRITICAL",
	"WARNING",
	"INFO"
]), It = /* @__PURE__ */ new Set([
	"bill-of-rights-bot",
	"lease-audit",
	"care-check",
	"warranty-watch",
	"paystub-check"
]);
function Lt(e) {
	if (!e || typeof e != "object") return !1;
	let t = e;
	if (t.version !== "1.0" || t.originApp !== "knowthankyew-extension" || typeof t.domain != "string" || t.domain.trim().length === 0 || typeof t.scanTimestamp != "string" || Number.isNaN(Date.parse(t.scanTimestamp)) || typeof t.riskScore != "number" || t.riskScore < 0 || t.riskScore > 100 || !t.summary || typeof t.summary != "object" || typeof t.summary.critical != "number" || typeof t.summary.warning != "number" || typeof t.summary.info != "number" || !Number.isFinite(t.summary.critical) || !Number.isFinite(t.summary.warning) || !Number.isFinite(t.summary.info) || !Number.isInteger(t.summary.critical) || !Number.isInteger(t.summary.warning) || !Number.isInteger(t.summary.info) || t.summary.critical < 0 || t.summary.warning < 0 || t.summary.info < 0 || !Array.isArray(t.findings)) return !1;
	for (let e of t.findings) if (!e || typeof e != "object" || typeof e.ruleId != "string" || e.ruleId.trim().length === 0 || typeof e.title != "string" || e.title.trim().length === 0 || !Pt.has(e.category) || !Ft.has(e.severity) || typeof e.statuteCode != "string" || typeof e.statuteTitle != "string" || typeof e.matchedSnippet != "string" || typeof e.explanation != "string" || typeof e.recommendation != "string") return !1;
	return !(typeof t.targetTool != "string" || !It.has(t.targetTool) || t.primaryLegalLink !== null && (!t.primaryLegalLink || typeof t.primaryLegalLink != "object" || typeof t.primaryLegalLink.url != "string" || typeof t.primaryLegalLink.title != "string"));
}
//#endregion
export { et as C, e as D, E, y as S, D as T, ne as _, jt as a, O as b, xt as c, W as d, I as f, r as g, n as h, At as i, K as l, t as m, Lt as n, St as o, _e as p, Mt as r, Q as s, Nt as t, G as u, T as v, x as w, ve as x, k as y };
