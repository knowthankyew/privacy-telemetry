//#region src/handoff.ts
var e = "kty_handoff", t = /* @__PURE__ */ new Set([
	"AUTO_RENEWAL",
	"ARBITRATION",
	"UNILATERAL_CHANGE",
	"SURVEILLANCE",
	"WARRANTY_DISCLAIMER"
]), n = /* @__PURE__ */ new Set([
	"CRITICAL",
	"WARNING",
	"INFO"
]), r = /* @__PURE__ */ new Set([
	"bill-of-rights-bot",
	"lease-audit",
	"care-check",
	"warranty-watch",
	"paystub-check"
]);
function i(e) {
	if (!e || typeof e != "object") return !1;
	let i = e;
	if (i.version !== "1.0" || i.originApp !== "knowthankyew-extension" || typeof i.domain != "string" || i.domain.trim().length === 0 || typeof i.scanTimestamp != "string" || Number.isNaN(Date.parse(i.scanTimestamp)) || typeof i.riskScore != "number" || i.riskScore < 0 || i.riskScore > 100 || !i.summary || typeof i.summary != "object" || typeof i.summary.critical != "number" || typeof i.summary.warning != "number" || typeof i.summary.info != "number" || !Array.isArray(i.findings)) return !1;
	for (let e of i.findings) if (!e || typeof e != "object" || typeof e.ruleId != "string" || e.ruleId.trim().length === 0 || typeof e.title != "string" || e.title.trim().length === 0 || !t.has(e.category) || !n.has(e.severity) || typeof e.statuteCode != "string" || typeof e.statuteTitle != "string" || typeof e.matchedSnippet != "string" || typeof e.explanation != "string" || typeof e.recommendation != "string") return !1;
	return !(typeof i.targetTool != "string" || !r.has(i.targetTool) || i.primaryLegalLink !== null && (!i.primaryLegalLink || typeof i.primaryLegalLink != "object" || typeof i.primaryLegalLink.url != "string" || typeof i.primaryLegalLink.title != "string"));
}
//#endregion
export { i as n, e as t };
