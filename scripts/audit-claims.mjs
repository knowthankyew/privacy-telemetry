#!/usr/bin/env node
/**
 * audit-claims.mjs - Automated Claims, Architectural Parity & Privacy Invariant Linter for privacy-telemetry.
 *
 * Enforces:
 * 1. Zero-Egress Privacy Invariant:
 *    - Verifies default telemetry operates in memory_only mode with zero network egress ('deny').
 *    - Verifies packages/privacy-telemetry/src/ contains zero unauthorized network egress primitives
 *      (fetch, XMLHttpRequest, sendBeacon, WebSocket), permitting fetch strictly in exportToOtlp.
 *    - Verifies .NET PrivacyTelemetryOptions defaults to memory_only and network egress deny.
 * 2. Telemetry Allowlist & Redaction Parity:
 *    - Validates strict allowlist coverage across TypeScript and .NET implementations.
 *    - Prohibits sensitive PII/PHI keys (e.g. ssn, patient_name, gross_pay, lease_snippet) in default allowlists.
 *    - Verifies fail-closed redaction token invariants ([REDACTED_...]).
 * 3. Single Source of Truth for Dynamic Claims:
 *    - Validates honest dynamic privacy claims generator (getPrivacyClaims & IsLocalOnlyHonest).
 * 4. Cross-Engine Structured Handoff Protocol Parity:
 *    - Validates tool IDs, categories, severities, and fail-closed envelope validator.
 * 5. Supply Chain & Central Package Management (CPM) Conformance:
 *    - Validates Directory.Packages.props and Directory.Build.props fail-closed security properties.
 * 6. Vocabulary Guardrails:
 *    - Prohibits unprovable marketing adjectives ('bulletproof', 'conclusive', 'definitive', 'infinitely scalable').
 * 7. Portfolio Master Brief Parity:
 *    - Verifies that KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md accurately reflects current privacy-telemetry test inventory.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  stripLineComment,
  stripBlockComments,
  FORBIDDEN_NETWORK_REGEX,
  testNetworkPrimitive,
  scanSourceForNetworkPrimitives,
  scanDocumentationForVocabulary,
  BANNED_VOCABULARY,
} from './claims-linter-core.mjs';

export {
  stripLineComment,
  stripBlockComments,
  FORBIDDEN_NETWORK_REGEX,
  testNetworkPrimitive,
  scanSourceForNetworkPrimitives,
  scanDocumentationForVocabulary,
  BANNED_VOCABULARY,
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..');
const DEV_ROOT = resolve(REPO_ROOT, '..');

const PROHIBITED_WORDS = [
  /\bbullet-?proof\b/i,
  /\brock\s+solid\b/i,
  /\bconclusive\b/i,
  /\bdefinitive\b/i,
  /\binfinitely scalable\b/i,
];

const PROHIBITED_ALLOWLIST_KEYS = [
  'patient_name',
  'ssn',
  'tenant_name',
  'gross_pay',
  'lease_snippet',
  'raw_text',
  'prompt',
  'matched_snippet',
  'matchedSnippet',
  'clause_text',
  'password',
  'adapter_path',
  'dataset_relative_path',
];

const REQUIRED_SHARED_ALLOWLIST_KEYS = [
  'job_id',
  'status',
  'duration_ms',
  'duration_sec',
  'rule_id',
  'rule_ids',
  'jurisdiction',
  'clause_count',
  'flagged_count',
  'device',
  'dataset_hash',
];

const EXPECTED_HANDOFF_TOOLS = [
  'bill-of-rights-bot',
  'lease-audit',
  'care-check',
  'warranty-watch',
  'paystub-check',
];

/**
 * Audit 1: Zero-Egress & Network Invariants
 */
const FETCH_PRIMITIVE_REGEX =
  /(?:\b(?:fetch|\??\.\s*fetch)\s*\(|=\s*fetch\b|\[\s*['"`]fetch['"`]\s*\]|\b(?:window|globalThis|self)\s*(?:\.\s*fetch|\[\s*['"`]fetch['"`]\s*\]))/;

const NON_FETCH_NETWORK_REGEX =
  /(?:\b(?:XMLHttpRequest|axios)\b|\[\s*['"`](?:XMLHttpRequest|sendBeacon|WebSocket|EventSource|axios)['"`]\s*\]|\bnavigator\s*(?:\??\.\s*sendBeacon|\[\s*['"`]sendBeacon['"`]\s*\])|\bnew\s+(?:WebSocket|EventSource|Image)\b|\bnew\s+Worker\s*\(\s*(?:new\s+URL\s*\(\s*)?['"`]https?:\/\/|\bimport\s*\(\s*['"`]https?:\/\/|\bdocument\s*(?:\??\.\s*createElement|\[\s*['"`]createElement['"`]\s*\])\s*\(\s*['"`]script['"`]\s*\))/;

function sanitizeCSharpSegment(source, startIdx = 0, stopSpec = null) {
  let out = '';
  let i = startIdx;
  let parenDepth = 0;
  let bracketDepth = 0;
  let braceDepth = 0;
  let inFormatSpecifier = false;

  const countRun = (ch, fromIdx) => {
    let k = fromIdx;
    while (k < source.length && source[k] === ch) {
      k++;
    }
    return k - fromIdx;
  };

  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];

    if (stopSpec) {
      if (inFormatSpecifier) {
        if (ch === '}') {
          if (!stopSpec.isRaw) {
            return { out, nextIdx: i + 1 };
          }
          const closeRun = countRun('}', i);
          if (closeRun >= stopSpec.dollarCount) {
            return { out, nextIdx: i + stopSpec.dollarCount };
          }
          i += closeRun;
          continue;
        }
        i++;
        continue;
      }

      if (parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
        if (ch === ':') {
          inFormatSpecifier = true;
          i++;
          continue;
        }
        if (ch === '}') {
          if (!stopSpec.isRaw) {
            return { out, nextIdx: i + 1 };
          }
          const closeRun = countRun('}', i);
          if (closeRun >= stopSpec.dollarCount) {
            return { out, nextIdx: i + stopSpec.dollarCount };
          }
        }
      }
    }

    if (ch === '/' && next === '/') {
      i += 2;
      while (
        i < source.length &&
        source[i] !== '\n' &&
        source[i] !== '\r' &&
        source[i] !== '\u0085' &&
        source[i] !== '\u2028' &&
        source[i] !== '\u2029'
      ) {
        i++;
      }
      if (
        i < source.length &&
        (source[i] === '\r' ||
          source[i] === '\u0085' ||
          source[i] === '\u2028' ||
          source[i] === '\u2029') &&
        source[i + 1] !== '\n'
      ) {
        out += '\n';
        i++;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      const prevChar = out.length > 0 ? out[out.length - 1] : '';
      let sawNewline = false;
      i += 2;
      while (i < source.length) {
        if (source[i] === '\n') {
          out += '\n';
          sawNewline = true;
        }
        if (source[i] === '*' && source[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      if (!sawNewline && /\w/.test(prevChar) && i < source.length && /\w/.test(source[i])) {
        out += ' ';
      }
      continue;
    }

    // Verbatim interpolated strings: $@"..." or @$"..."
    if (
      (ch === '$' && next === '@' && source[i + 2] === '"') ||
      (ch === '@' && next === '$' && source[i + 2] === '"')
    ) {
      out += '""';
      i += 3;
      while (i < source.length) {
        if (source[i] === '"' && source[i + 1] === '"') {
          i += 2;
          continue;
        }
        if (source[i] === '"') {
          i++;
          break;
        }
        if (source[i] === '{') {
          if (source[i + 1] === '{') {
            i += 2;
            continue;
          }
          const hole = sanitizeCSharpSegment(source, i + 1, { isRaw: false, dollarCount: 1 });
          out += ` (${hole.out}) `;
          i = hole.nextIdx;
          continue;
        }
        if (source[i] === '}' && source[i + 1] === '}') {
          i += 2;
          continue;
        }
        i++;
      }
      continue;
    }

    // Verbatim non-interpolated strings: @"..."
    if (ch === '@' && next === '"') {
      out += '""';
      i += 2;
      while (i < source.length) {
        if (source[i] === '"') {
          if (source[i + 1] === '"') {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    // Raw strings ("""...""") and raw interpolated strings ($"""...""", $$"""...""", ...)
    if (ch === '$' || ch === '"') {
      const dollarCount = countRun('$', i);
      const quoteCount = countRun('"', i + dollarCount);
      if (quoteCount >= 3) {
        out += '""';
        i += dollarCount + quoteCount;
        while (i < source.length) {
          if (source[i] === '"') {
            const closeQuotes = countRun('"', i);
            if (closeQuotes >= quoteCount) {
              i += quoteCount;
              break;
            }
            i += closeQuotes;
            continue;
          }
          if (dollarCount > 0 && source[i] === '{') {
            const braceRun = countRun('{', i);
            if (braceRun < dollarCount) {
              i += braceRun;
              continue;
            }
            // Literal braces precede the final dollarCount braces that open the hole
            i += braceRun;
            const hole = sanitizeCSharpSegment(source, i, { isRaw: true, dollarCount });
            out += ` (${hole.out}) `;
            i = hole.nextIdx;
            continue;
          }
          i++;
        }
        continue;
      }
    }

    // Regular interpolated string: $"..."
    if (ch === '$' && next === '"') {
      out += '""';
      i += 2;
      while (i < source.length) {
        if (source[i] === '\\' && i + 1 < source.length) {
          i += 2;
          continue;
        }
        if (source[i] === '"') {
          i++;
          break;
        }
        if (source[i] === '{') {
          if (source[i + 1] === '{') {
            i += 2;
            continue;
          }
          const hole = sanitizeCSharpSegment(source, i + 1, { isRaw: false, dollarCount: 1 });
          out += ` (${hole.out}) `;
          i = hole.nextIdx;
          continue;
        }
        if (source[i] === '}' && source[i + 1] === '}') {
          i += 2;
          continue;
        }
        i++;
      }
      continue;
    }

    // Regular string literal "..." (preserve only exact sentinel literals needed for option checks)
    if (ch === '"') {
      const startToken = i;
      i++;
      while (i < source.length) {
        if (source[i] === '\\' && i + 1 < source.length) {
          i += 2;
          continue;
        }
        if (source[i] === '"') {
          i++;
          break;
        }
        i++;
      }
      const rawToken = source.slice(startToken, i);
      out += rawToken === '"deny"' || rawToken === '"memory_only"' ? rawToken : '""';
      continue;
    }

    // Character literal '...'
    if (ch === "'") {
      i++;
      while (i < source.length) {
        if (source[i] === '\\' && i + 1 < source.length) {
          i += 2;
          continue;
        }
        if (source[i] === "'") {
          i++;
          break;
        }
        i++;
      }
      out += "''";
      continue;
    }

    if (stopSpec) {
      if (ch === '(') parenDepth++;
      else if (ch === ')' && parenDepth > 0) parenDepth--;
      else if (ch === '[') bracketDepth++;
      else if (ch === ']' && bracketDepth > 0) bracketDepth--;
      else if (ch === '{') braceDepth++;
      else if (ch === '}' && braceDepth > 0) braceDepth--;
    }

    out += ch;
    i++;
  }

  return { out, nextIdx: i };
}

function sanitizeCSharpForAudit(source) {
  return sanitizeCSharpSegment(source, 0, null)
    .out.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\U([0-9a-fA-F]{8})/g, (_, hex) => {
      const cp = parseInt(hex, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : '\\U' + hex;
    })
    .replace(/\p{Cf}/gu, '');
}

function extractBalancedDelimiterFrom(source, openIdx, openCh, closeCh) {
  if (openIdx < 0 || source[openIdx] !== openCh) return null;
  let depth = 0;
  let inLineComment = false;
  let inBlockComment = false;
  let quote = null;
  for (let i = openIdx; i < source.length; i++) {
    const ch = source[i];
    const next = source[i + 1];
    if (inLineComment) {
      if (ch === '\n') inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (quote) {
      if (ch === '\\') {
        i++;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '/' && next === '/') {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === openCh) {
      depth++;
    } else if (ch === closeCh) {
      depth--;
      if (depth === 0) {
        return {
          body: source.slice(openIdx + 1, i),
          endIdx: i,
        };
      }
    }
  }
  return null;
}

function extractBalancedBracesFrom(source, openIdx) {
  return extractBalancedDelimiterFrom(source, openIdx, '{', '}');
}

function extractBalancedParensFrom(source, openIdx) {
  return extractBalancedDelimiterFrom(source, openIdx, '(', ')');
}

function skipStatementOrBracedBlock(text, startIdx) {
  let i = startIdx;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < text.length) {
        if (text[i] === '\\') {
          i += 2;
          continue;
        }
        if (text[i] === ch) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === '(') {
      const ext = extractBalancedParensFrom(text, i);
      if (!ext) return -1;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '[') {
      const ext = extractBalancedDelimiterFrom(text, i, '[', ']');
      if (!ext) return -1;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '{') {
      const ext = extractBalancedBracesFrom(text, i);
      if (!ext) return -1;
      i = ext.endIdx + 1;
      let j = i;
      while (j < text.length && /\s/.test(text[j])) j++;
      if (text[j] === '=') {
        return skipStatementOrBracedBlock(text, j + 1);
      }
      return i;
    }
    if (ch === ';') {
      return i + 1;
    }
    i++;
  }
  return i;
}

function scanCSharpNamespaceScope(
  text,
  initialNamespace,
  expectedNamespace,
  className,
  bodies,
  namespaceDepth = 0,
  meta = { hasPartial: false, hasNonPartial: false }
) {
  let activeNs = initialNamespace;
  let fileScopedActive = false;
  let i = 0;

  while (i < text.length) {
    while (i < text.length && (/\s/.test(text[i]) || text[i] === ';')) {
      i++;
    }
    if (i >= text.length) break;

    if (text[i] === '#') {
      if (/^#\s*(?:if|elif|else|endif|define|undef)\b/.test(text.slice(i))) {
        return false;
      }
      const nlIdx = text.indexOf('\n', i);
      i = nlIdx === -1 ? text.length : nlIdx + 1;
      continue;
    }

    if (text[i] === '[') {
      const attrIdx = skipLeadingAttributeLists(text, i);
      if (attrIdx === -1) return false;
      i = attrIdx;
      continue;
    }

    const nsRegex =
      /\bnamespace\s+(@?[A-Za-z_][A-Za-z0-9_]*(?:\.@?[A-Za-z_][A-Za-z0-9_]*)*)\s*(;|{)/y;
    nsRegex.lastIndex = i;
    const nsMatch = nsRegex.exec(text);
    if (nsMatch) {
      const nsName = nsMatch[1].replace(/@/g, '');
      if (nsMatch[2] === ';') {
        if (namespaceDepth > 0 || fileScopedActive) {
          return false;
        }
        activeNs = nsName;
        fileScopedActive = true;
        i = nsRegex.lastIndex;
        continue;
      }
      if (fileScopedActive) {
        return false;
      }
      const openIdx = nsRegex.lastIndex - 1;
      const ext = extractBalancedBracesFrom(text, openIdx);
      if (!ext) return false;
      const nestedNs = activeNs ? `${activeNs}.${nsName}` : nsName;
      if (
        !scanCSharpNamespaceScope(
          ext.body,
          nestedNs,
          expectedNamespace,
          className,
          bodies,
          namespaceDepth + 1,
          meta
        )
      ) {
        return false;
      }
      i = ext.endIdx + 1;
      continue;
    }

    const typeRegex =
      /(?:(?:public|internal|private|protected|file|static|sealed|abstract|partial|readonly|ref|unsafe|new)\s+)*(class|struct|record(?:\s+(?:class|struct))?|interface|enum)\s+(@?[A-Za-z_][A-Za-z0-9_]*)\b/y;
    typeRegex.lastIndex = i;
    const typeMatch = typeRegex.exec(text);
    if (typeMatch) {
      const isPartialDecl = /\bpartial\b/.test(typeMatch[0]);
      const typeKind = typeMatch[1];
      const declName = typeMatch[2].replace(/^@/, '');
      let scan = typeRegex.lastIndex;
      let hasGenericTypeParams = false;
      let hasPrimaryCtor = false;
      let seenBaseOrConstraint = false;

      const isTargetClass = () =>
        typeKind === 'class' &&
        declName === className &&
        !hasGenericTypeParams &&
        (expectedNamespace === null || activeNs === expectedNamespace);

      while (scan < text.length) {
        while (scan < text.length && /\s/.test(text[scan])) scan++;
        if (scan >= text.length) return false;
        const ch = text[scan];
        if (ch === '<') {
          if (!seenBaseOrConstraint) {
            hasGenericTypeParams = true;
          }
          const gen = extractBalancedDelimiterFrom(text, scan, '<', '>');
          if (!gen) return false;
          scan = gen.endIdx + 1;
          continue;
        }
        if (ch === '(') {
          if (!seenBaseOrConstraint) {
            hasPrimaryCtor = true;
          }
          const paren = extractBalancedParensFrom(text, scan);
          if (!paren) return false;
          scan = paren.endIdx + 1;
          continue;
        }
        if (ch === ':') {
          seenBaseOrConstraint = true;
          scan++;
          continue;
        }
        if (
          text.startsWith('where', scan) &&
          (scan === 0 || !/[A-Za-z0-9_]/.test(text[scan - 1])) &&
          /^where\b/.test(text.slice(scan))
        ) {
          seenBaseOrConstraint = true;
          scan += 5;
          continue;
        }
        if (ch === '{') {
          const ext = extractBalancedBracesFrom(text, scan);
          if (!ext) return false;
          if (isTargetClass()) {
            // Reject primary constructors or base-class/constraint clauses whose implicit base()
            // execution or virtual overrides can mutate derived field initializers.
            if (hasPrimaryCtor || seenBaseOrConstraint) return false;
            if (isPartialDecl) {
              meta.hasPartial = true;
            } else {
              meta.hasNonPartial = true;
            }
            bodies.push(ext.body);
          }
          i = ext.endIdx + 1;
          break;
        }
        if (ch === ';') {
          if (isTargetClass() && (hasPrimaryCtor || seenBaseOrConstraint)) return false;
          i = scan + 1;
          break;
        }
        scan++;
      }
      if (scan >= text.length) return false;
      continue;
    }

    const nextIdx = skipStatementOrBracedBlock(text, i);
    if (nextIdx === -1 || nextIdx <= i) return false;
    i = nextIdx;
  }

  return true;
}

function extractCombinedClassBody(sourcesInput, className, expectedNamespace = null) {
  const sources = Array.isArray(sourcesInput) ? sourcesInput : [sourcesInput];
  const bodies = [];
  const meta = { hasPartial: false, hasNonPartial: false };
  const targetNameRegex = new RegExp(`\\b@?${className}\\b`);
  for (const source of sources) {
    const cleanSource = sanitizeCSharpForAudit(source);
    if (!targetNameRegex.test(cleanSource)) {
      continue;
    }
    if (!scanCSharpNamespaceScope(cleanSource, '', expectedNamespace, className, bodies, 0, meta)) {
      return null;
    }
  }
  if (bodies.length === 0) {
    return null;
  }
  if (bodies.length > 1 && meta.hasNonPartial) {
    return null;
  }
  if (meta.hasPartial && bodies.length < 2) {
    return null;
  }
  return bodies.map((body) => stripNestedTypeDeclarations(body)).join('\n');
}

function skipLeadingAttributeLists(text, startIdx) {
  let idx = startIdx;
  while (idx < text.length) {
    while (idx < text.length && /\s/.test(text[idx])) {
      idx++;
    }
    if (text[idx] !== '[') {
      break;
    }
    let bracketDepth = 1;
    let quote = null;
    idx++;
    while (idx < text.length && bracketDepth > 0) {
      const ch = text[idx];
      if (quote !== null) {
        if (ch === '\\') {
          idx += 2;
          continue;
        }
        if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '[') {
        bracketDepth++;
      } else if (ch === ']') {
        bracketDepth--;
      }
      idx++;
    }
    if (bracketDepth > 0) {
      return -1;
    }
  }
  return idx;
}

function stripNestedTypeDeclarations(classBody) {
  if (!classBody) return '';
  const candidateStartRegex =
    /(?<=^|[;{}\n])\s*(?:\[|(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|new|unsafe|ref|file|class|struct|record|interface|enum)\b)/g;
  const typeHeaderSticky =
    /(?:(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|new|unsafe|ref|file)\s+)*(?:class|struct|record(?:\s+(?:class|struct))?|interface|enum)\s+@?[A-Za-z_][A-Za-z0-9_]*/y;
  let result = '';
  let cursor = 0;
  let match;
  while ((match = candidateStartRegex.exec(classBody)) !== null) {
    const headerIdx = skipLeadingAttributeLists(classBody, match.index);
    if (headerIdx === -1) {
      return '';
    }
    typeHeaderSticky.lastIndex = headerIdx;
    const typeMatch = typeHeaderSticky.exec(classBody);
    if (!typeMatch) {
      candidateStartRegex.lastIndex = Math.max(match.index + match[0].length, headerIdx);
      continue;
    }
    let i = typeHeaderSticky.lastIndex;
    let parenDepth = 0;
    let quote = null;
    let openIdx = -1;
    let terminatedBySemicolon = false;
    while (i < classBody.length) {
      const ch = classBody[i];
      if (quote !== null) {
        if (ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === quote) quote = null;
        i++;
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '(') {
        parenDepth++;
      } else if (ch === ')') {
        if (parenDepth > 0) parenDepth--;
      } else if (parenDepth === 0) {
        if (ch === '{') {
          openIdx = i;
          break;
        }
        if (ch === ';') {
          terminatedBySemicolon = true;
          break;
        }
      }
      i++;
    }

    result += classBody.slice(cursor, match.index);
    if (terminatedBySemicolon) {
      cursor = i + 1;
    } else if (openIdx !== -1) {
      const extracted = extractBalancedBracesFrom(classBody, openIdx);
      cursor = extracted ? extracted.endIdx + 1 : classBody.length;
    } else {
      cursor = classBody.length;
    }
    candidateStartRegex.lastIndex = cursor;
  }
  result += classBody.slice(cursor);
  return result;
}

function hasGenericCallAfterIdent(text, afterIdentIdx) {
  let idx = afterIdentIdx;
  while (idx < text.length && /\s/.test(text[idx])) {
    idx++;
  }
  if (text[idx] === '(') {
    return true;
  }
  if (text[idx] !== '<') {
    return false;
  }
  let angleDepth = 0;
  while (idx < text.length) {
    const ch = text[idx];
    if (ch === '<') {
      angleDepth++;
    } else if (ch === '>') {
      angleDepth--;
      if (angleDepth === 0) {
        idx++;
        while (idx < text.length && /\s/.test(text[idx])) {
          idx++;
        }
        return text[idx] === '(';
      }
    } else if (!/[A-Za-z0-9_.,[\]?@*:\s]/.test(ch)) {
      return false;
    }
    idx++;
  }
  return false;
}

function containsUnresolvedInvocation(code) {
  const withoutLiterals = code.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
  const controlFlowAndOperators = new Set([
    'if',
    'for',
    'foreach',
    'while',
    'switch',
    'lock',
    'using',
    'catch',
    'fixed',
    'typeof',
    'nameof',
    'sizeof',
    'default',
  ]);
  const identRegex = /\b([A-Za-z_][A-Za-z0-9_]*)\b/g;
  let identMatch;
  while ((identMatch = identRegex.exec(withoutLiterals)) !== null) {
    if (
      !controlFlowAndOperators.has(identMatch[1]) &&
      hasGenericCallAfterIdent(withoutLiterals, identMatch.index + identMatch[1].length)
    ) {
      return true;
    }
  }
  return false;
}

function isSafeConstructorBody(ctorBody, allowedLiteralAssignmentRegex) {
  let remaining = ctorBody;
  if (allowedLiteralAssignmentRegex) {
    let prev;
    do {
      prev = remaining;
      remaining = remaining.replace(allowedLiteralAssignmentRegex, '$1;');
    } while (remaining !== prev);
  }
  // Fail closed unless removing only empty statement terminators and whitespace leaves nothing behind;
  // this blocks arbitrary field/property writes (e.g., Enable = true; BurnEnabled = false;), calls, and branches.
  if (remaining.replace(/[;\s]+/g, '').length > 0) {
    return false;
  }
  return !containsUnresolvedInvocation(ctorBody);
}

function findNextExpressionTerminator(source, startIdx) {
  let i = startIdx;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < source.length) {
        if (source[i] === '\\') {
          i += 2;
          continue;
        }
        if (source[i] === ch) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === '(') {
      const ext = extractBalancedParensFrom(source, i);
      if (!ext) return -1;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '[') {
      const ext = extractBalancedDelimiterFrom(source, i, '[', ']');
      if (!ext) return -1;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '{') {
      const ext = extractBalancedBracesFrom(source, i);
      if (!ext) return -1;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === ';') {
      return i;
    }
    i++;
  }
  return -1;
}

function findConstructorBodyStart(source, afterParamsIdx) {
  let i = afterParamsIdx;
  let seenColon = false;
  let initStart = -1;
  while (i < source.length) {
    while (i < source.length && /\s/.test(source[i])) i++;
    if (i >= source.length) return null;
    const ch = source[i];
    if (ch === ':' && !seenColon) {
      seenColon = true;
      initStart = i + 1;
      i++;
      continue;
    }
    if (ch === '(') {
      const ext = extractBalancedParensFrom(source, i);
      if (!ext) return null;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '[') {
      const ext = extractBalancedDelimiterFrom(source, i, '[', ']');
      if (!ext) return null;
      i = ext.endIdx + 1;
      continue;
    }
    if (ch === '{') {
      return {
        kind: 'block',
        startIdx: i,
        initializer: seenColon ? source.slice(initStart, i).trim() : '',
      };
    }
    if (ch === '=' && source[i + 1] === '>') {
      return {
        kind: 'expr',
        startIdx: i + 2,
        initializer: seenColon ? source.slice(initStart, i).trim() : '',
      };
    }
    if (ch === ';') {
      return null;
    }
    i++;
  }
  return null;
}

function hasOnlySafeAutoNetworkEgressProperty(classBody) {
  const propRegex = /\b(?:string|String)\s+@?NetworkEgress\s*(\{|=>)/g;
  let found = false;
  let match;
  while ((match = propRegex.exec(classBody)) !== null) {
    found = true;
    if (match[1] === '=>') {
      return false;
    }
    const braceIdx = propRegex.lastIndex - 1;
    const ext = extractBalancedBracesFrom(classBody, braceIdx);
    if (!ext) {
      return false;
    }
    if (!/^\s*get\s*;\s*(?:(?:private|protected|internal)\s+)?(?:set|init)\s*;\s*$/.test(ext.body)) {
      return false;
    }
    propRegex.lastIndex = ext.endIdx + 1;
  }
  return found;
}

function hasUnsafeMemberInitializerOrStaticTrackedMember(skippedMember) {
  const member = skippedMember.trim().replace(/;+\s*$/, '');
  if (!member) return false;
  if (member.includes('\\')) return true;

  let firstDelimIdx = -1;
  let firstDelim = '';
  for (let i = 0; i < member.length; i++) {
    const ch = member[i];
    if (ch === '"' || ch === "'") {
      i++;
      while (i < member.length) {
        if (member[i] === '\\') {
          i += 2;
          continue;
        }
        if (member[i] === ch) break;
        i++;
      }
      continue;
    }
    if (ch === '=' && member[i + 1] === '>') {
      firstDelimIdx = i;
      firstDelim = '=>';
      break;
    }
    if (ch === '(' || ch === '{' || ch === '=') {
      firstDelimIdx = i;
      firstDelim = ch;
      break;
    }
  }

  const header = firstDelimIdx === -1 ? member : member.slice(0, firstDelimIdx);
  if (
    /\bstatic\b/.test(header) &&
    /\b@?(?:_networkEgress|NetworkEgress|BurnEnabled|Mode|AllowRawPayloads|HasExplicitNetworkEgress)\b/.test(
      header
    )
  ) {
    return true;
  }

  let initRhs = null;
  if (firstDelim === '=') {
    initRhs = member.slice(firstDelimIdx + 1);
  } else if (firstDelim === '{') {
    const ext = extractBalancedBracesFrom(member, firstDelimIdx);
    if (!ext) return true;
    let afterBrace = ext.endIdx + 1;
    while (afterBrace < member.length && /\s/.test(member[afterBrace])) {
      afterBrace++;
    }
    if (member[afterBrace] === '=' && member[afterBrace + 1] !== '>') {
      initRhs = member.slice(afterBrace + 1);
    }
  }

  if (initRhs !== null) {
    const withoutLiterals = initRhs.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
    if (
      containsUnresolvedInvocation(initRhs) ||
      /[{}]/.test(withoutLiterals) ||
      /=>/.test(withoutLiterals) ||
      /(?:^|[^=!<>])=(?![=>])/.test(withoutLiterals)
    ) {
      return true;
    }
  }

  return false;
}

function hasDisallowedNetworkEgressConstructorOverride(
  rawClassBody,
  className,
  allowedLiteralAssignmentRegex = /(^|[;{}])\s*(?:this\.)?(?:@?_networkEgress|@?NetworkEgress)\s*=\s*"deny"\s*(?=[;}]|$)/g
) {
  const classBody = rawClassBody.replace(/\p{Cf}/gu, '');
  if (classBody.includes('\\')) return true;
  const ctorPrefixRegex = new RegExp(
    `(?:(?:public|internal|private|protected|static|unsafe|extern)\\s+)*@?${className}\\s*(?=\\()`,
    'y'
  );
  const unhandledCtorLikeHeaderRegex = new RegExp(`(?:^|[\\s~])@?${className}$`);
  let i = 0;
  while (i < classBody.length) {
    while (i < classBody.length && (/\s/.test(classBody[i]) || classBody[i] === ';')) {
      i++;
    }
    if (i >= classBody.length) break;

    if (classBody[i] === '[') {
      const nextIdx = skipLeadingAttributeLists(classBody, i);
      if (nextIdx === -1) return true;
      i = nextIdx;
      while (i < classBody.length && /\s/.test(classBody[i])) i++;
      if (i >= classBody.length) break;
    }

    ctorPrefixRegex.lastIndex = i;
    const prefixMatch = ctorPrefixRegex.exec(classBody);
    if (prefixMatch) {
      const openParenIdx = ctorPrefixRegex.lastIndex;
      const paramsExt = extractBalancedParensFrom(classBody, openParenIdx);
      if (!paramsExt) return true;
      if (containsUnresolvedInvocation(paramsExt.body)) return true;

      const bodyHeader = findConstructorBodyStart(classBody, paramsExt.endIdx + 1);
      if (!bodyHeader) return true;
      if (bodyHeader.initializer && !/^base\s*\(\s*\)$/.test(bodyHeader.initializer)) {
        return true;
      }

      let ctorBody = '';
      if (bodyHeader.kind === 'block') {
        const bodyExt = extractBalancedBracesFrom(classBody, bodyHeader.startIdx);
        if (!bodyExt) return true;
        ctorBody = bodyExt.body;
        i = bodyExt.endIdx + 1;
      } else {
        const semiIdx = findNextExpressionTerminator(classBody, bodyHeader.startIdx);
        if (semiIdx === -1) return true;
        ctorBody = classBody.slice(bodyHeader.startIdx, semiIdx);
        i = semiIdx + 1;
      }

      if (!isSafeConstructorBody(ctorBody, allowedLiteralAssignmentRegex)) {
        return true;
      }
      continue;
    }

    const nextMemberIdx = skipStatementOrBracedBlock(classBody, i);
    if (nextMemberIdx === -1 || nextMemberIdx <= i) return true;
    const skippedMember = classBody.slice(i, nextMemberIdx);
    const skippedHeaderMatch = skippedMember.match(/^[^=;{(]*/);
    const skippedHeader = skippedHeaderMatch ? skippedHeaderMatch[0].trim() : '';
    if (
      skippedHeaderMatch &&
      skippedMember[skippedHeaderMatch[0].length] === '(' &&
      !/\boperator\b/.test(skippedHeader) &&
      unhandledCtorLikeHeaderRegex.test(skippedHeader)
    ) {
      return true;
    }
    if (hasUnsafeMemberInitializerOrStaticTrackedMember(skippedMember)) {
      return true;
    }
    i = nextMemberIdx;
  }
  return false;
}

export function auditZeroEgress(
  errors = [],
  {
    overrideSrcDir = null,
    overrideAuthorizedExporterPath = null,
    overrideCodeSnippets = null,
    overrideNetOptionsContent = null,
    overrideAdditionalNetOptionsContents = null,
  } = {}
) {
  if (overrideCodeSnippets && Array.isArray(overrideCodeSnippets)) {
    for (const [idx, snippet] of overrideCodeSnippets.entries()) {
      const codeOnly = stripLineComment(snippet);
      const trimmed = codeOnly.trim();
      if (!trimmed || trimmed.startsWith('*')) continue;
      if (testNetworkPrimitive(trimmed)) {
        if (NON_FETCH_NETWORK_REGEX.test(trimmed)) {
          errors.push(`Privacy violation in snippet:${idx + 1}: Forbidden network primitive: ${trimmed}`);
        } else if (FETCH_PRIMITIVE_REGEX.test(trimmed)) {
          errors.push(`Privacy violation in snippet:${idx + 1}: Direct, computed, or aliased fetch detected in non-exporter source: ${trimmed}`);
        } else {
          errors.push(`Privacy violation in snippet:${idx + 1}: Forbidden network primitive: ${trimmed}`);
        }
      }
    }
  }

  const tsSrcDir = overrideSrcDir || resolve(REPO_ROOT, 'packages/privacy-telemetry/src');
  if (!existsSync(tsSrcDir)) {
    errors.push('Missing packages/privacy-telemetry/src directory');
    return;
  }

  const authorizedExporterPath =
    overrideAuthorizedExporterPath ||
    resolve(REPO_ROOT, 'packages/privacy-telemetry/src/exporter.ts');

  function scanDir(dir) {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else if (/\.(ts|tsx)$/.test(entry.name)) {
        const isAuthorizedExporter = fullPath === authorizedExporterPath;
        const rawContent = readFileSync(fullPath, 'utf-8');
        // Strip block comments first to preserve line numbers without discarding inline code
        const contentWithoutBlockComments = rawContent.replace(/\/\*[\s\S]*?\*\//g, (match) =>
          '\n'.repeat((match.match(/\n/g) || []).length)
        );
        const lines = contentWithoutBlockComments.split('\n');
        let inExportToOtlp = false;
        let seenOpeningBrace = false;
        let braceDepth = 0;

        lines.forEach((line, lineIdx) => {
          // Strip line comments
          const codeOnly = stripLineComment(line);
          const trimmed = codeOnly.trim();
          if (!trimmed || trimmed.startsWith('*')) {
            return;
          }

          if (isAuthorizedExporter) {
            if (/\b(?:export\s+)?(?:async\s+)?function\s+exportToOtlp\b/.test(trimmed)) {
              inExportToOtlp = true;
              seenOpeningBrace = false;
              braceDepth = 0;
            }
            if (inExportToOtlp) {
              const openBraces = (trimmed.match(/\{/g) || []).length;
              const closeBraces = (trimmed.match(/\}/g) || []).length;
              if (openBraces > 0) seenOpeningBrace = true;
              braceDepth += openBraces - closeBraces;
              if (seenOpeningBrace && braceDepth <= 0) {
                inExportToOtlp = false;
              }
            }
          }

          // Forbidden network primitives verified via shared core regex:
          if (testNetworkPrimitive(trimmed)) {
            // Check if this line matches forbidden non-fetch network primitives
            // (Workers, dynamic scripts, WebSockets, sendBeacon, Image beacon, import)
            if (NON_FETCH_NETWORK_REGEX.test(trimmed)) {
              errors.push(
                `Privacy violation in ${fullPath.replace(REPO_ROOT + '/', '')}:${lineIdx + 1}: Forbidden network primitive: ${trimmed}`
              );
            } else if (FETCH_PRIMITIVE_REGEX.test(trimmed)) {
              const isExempt = isAuthorizedExporter && inExportToOtlp;
              if (!isExempt) {
                const contextDesc = isAuthorizedExporter
                  ? 'outside exportToOtlp in exporter.ts'
                  : 'in non-exporter source';
                errors.push(
                  `Privacy violation in ${fullPath.replace(REPO_ROOT + '/', '')}:${lineIdx + 1}: Direct, computed, or aliased fetch detected ${contextDesc}: ${trimmed}`
                );
              }
            } else {
              errors.push(
                `Privacy violation in ${fullPath.replace(REPO_ROOT + '/', '')}:${lineIdx + 1}: Forbidden network primitive: ${trimmed}`
              );
            }
          }
        });
      }
    }
  }

  scanDir(tsSrcDir);

  // Check TypeScript TelemetryManager defaults
  const managerPath = resolve(tsSrcDir, 'manager.ts');
  if (!existsSync(managerPath)) {
    errors.push('Missing packages/privacy-telemetry/src/manager.ts');
  } else {
    const mgrContent = readFileSync(managerPath, 'utf-8');
    if (!mgrContent.includes("defaultMode: TelemetryMode = envEndpoint ? 'otlp' : 'memory_only'")) {
      errors.push('TelemetryManager default mode must default to memory_only when no endpoint is configured.');
    }
    if (!mgrContent.includes("networkEgress: defaultMode === 'otlp' ? 'allow_otlp' : 'deny'")) {
      errors.push("TelemetryManager default network egress must default to 'deny' in consumer mode.");
    }
  }

  // Check .NET PrivacyTelemetryOptions defaults across all compiled .cs files
  const netPackageDir = resolve(REPO_ROOT, 'packages/KnowThankYew.Privacy.Telemetry');
  const netOptionsPath = resolve(netPackageDir, 'Configuration/PrivacyTelemetryOptions.cs');
  if (typeof overrideNetOptionsContent !== 'string' && !existsSync(netOptionsPath)) {
    errors.push(
      'Missing packages/KnowThankYew.Privacy.Telemetry/Configuration/PrivacyTelemetryOptions.cs'
    );
  } else {
    const collectCompiledCsFiles = (dir, acc = []) => {
      if (!existsSync(dir)) return acc;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          if (entry.name === 'bin' || entry.name === 'obj') continue;
          collectCompiledCsFiles(resolve(dir, entry.name), acc);
        } else if (entry.name.endsWith('.cs')) {
          acc.push(resolve(dir, entry.name));
        }
      }
      return acc;
    };
    const rawOptSources =
      typeof overrideNetOptionsContent === 'string'
        ? [
            overrideNetOptionsContent,
            ...(Array.isArray(overrideAdditionalNetOptionsContents)
              ? overrideAdditionalNetOptionsContents.filter((s) => typeof s === 'string')
              : []),
          ]
        : [
            netOptionsPath,
            ...collectCompiledCsFiles(netPackageDir).filter((p) => p !== netOptionsPath),
          ].map((p) => readFileSync(p, 'utf-8'));
    const sanitizedOptSources = rawOptSources.map((src) => sanitizeCSharpForAudit(src));
    const hasPreprocessorConditional = sanitizedOptSources.some(
      (src, idx) =>
        (idx === 0 || /\b(?:PrivacyOptions|TelemetryOptions)\b/.test(src)) &&
        /^\s*#\s*(?:if|elif|else|endif|define|undef)\b/m.test(src)
    );
    const targetNamespace = 'KnowThankYew.Privacy.Telemetry.Configuration';
    const privacyOptionsSlice =
      extractCombinedClassBody(sanitizedOptSources, 'PrivacyOptions', targetNamespace) ?? '';
    const telemetryOptionsSlice =
      extractCombinedClassBody(sanitizedOptSources, 'TelemetryOptions', targetNamespace) ?? '';
    const isAutoNetworkEgressProp = hasOnlySafeAutoNetworkEgressProperty(privacyOptionsSlice);
    const hasSafeBackingField_networkEgress =
      /(?:^|[;{}])\s*private\s+(?:readonly\s+)?string\s+@?_networkEgress\s*=\s*"deny"\s*;/.test(
        privacyOptionsSlice
      ) && !/\b(?:string|String)\s+@?_networkEgress\s*(?:\{|=>)/.test(privacyOptionsSlice);
    const allowedPrivacyCtorAssignmentRegex = isAutoNetworkEgressProp
      ? /(^|[;{}])\s*(?:this\.)?@?NetworkEgress\s*=\s*"deny"\s*(?=[;}]|$)/g
      : hasSafeBackingField_networkEgress
        ? /(^|[;{}])\s*(?:this\.)?@?_networkEgress\s*=\s*"deny"\s*(?=[;}]|$)/g
        : /(?!)/g;
    if (
      hasPreprocessorConditional ||
      !/public\s+bool\s+@?BurnEnabled\s*\{\s*get;\s*set;\s*\}\s*=\s*true\s*;/.test(privacyOptionsSlice) ||
      hasDisallowedNetworkEgressConstructorOverride(
        privacyOptionsSlice,
        'PrivacyOptions',
        allowedPrivacyCtorAssignmentRegex
      )
    ) {
      errors.push('PrivacyOptions.BurnEnabled must default to true.');
    }
    const hasDefaultDenyEgress =
      !hasPreprocessorConditional &&
      ((isAutoNetworkEgressProp &&
        /public\s+string\s+@?NetworkEgress\s*\{\s*get;\s*(?:(?:private|protected|internal)\s+)?(?:set|init);\s*\}\s*=\s*"deny"\s*;/.test(
          privacyOptionsSlice
        )) ||
        (hasSafeBackingField_networkEgress &&
          /public\s+string\s+@?NetworkEgress\s*\{\s*get\s*=>\s*@?_networkEgress\s*;/.test(
            privacyOptionsSlice
          ))) &&
      !hasDisallowedNetworkEgressConstructorOverride(
        privacyOptionsSlice,
        'PrivacyOptions',
        allowedPrivacyCtorAssignmentRegex
      );
    if (!hasDefaultDenyEgress) {
      errors.push('PrivacyOptions.NetworkEgress must default to "deny".');
    }
    if (
      hasPreprocessorConditional ||
      !/public\s+string\s+@?Mode\s*\{\s*get;\s*set;\s*\}\s*=\s*"memory_only"\s*;/.test(telemetryOptionsSlice) ||
      hasDisallowedNetworkEgressConstructorOverride(telemetryOptionsSlice, 'TelemetryOptions', null)
    ) {
      errors.push('TelemetryOptions.Mode must default to "memory_only".');
    }
    if (
      hasPreprocessorConditional ||
      !/public\s+bool\s+@?AllowRawPayloads\s*\{\s*get;\s*set;\s*\}\s*=\s*false\s*;/.test(telemetryOptionsSlice) ||
      hasDisallowedNetworkEgressConstructorOverride(telemetryOptionsSlice, 'TelemetryOptions', null)
    ) {
      errors.push('TelemetryOptions.AllowRawPayloads must default to false.');
    }
  }
}

/**
 * Audit 2: Telemetry Allowlist & Redaction Parity
 */
export function auditAllowlistParity(errors = []) {
  const tsAllowlistPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/allowlist.ts');
  const netAllowlistPath = resolve(
    REPO_ROOT,
    'packages/KnowThankYew.Privacy.Telemetry/Core/SafeAllowlist.cs'
  );

  if (!existsSync(tsAllowlistPath)) {
    errors.push('Missing packages/privacy-telemetry/src/allowlist.ts');
    return;
  }
  if (!existsSync(netAllowlistPath)) {
    errors.push('Missing packages/KnowThankYew.Privacy.Telemetry/Core/SafeAllowlist.cs');
    return;
  }

  const tsContent = readFileSync(tsAllowlistPath, 'utf-8');
  const netContent = readFileSync(netAllowlistPath, 'utf-8');

  // Verify no prohibited PII/PHI keys in allowlists
  for (const key of PROHIBITED_ALLOWLIST_KEYS) {
    if (tsContent.includes(`'${key}'`)) {
      errors.push(`Prohibited sensitive attribute '${key}' found in TypeScript DEFAULT_SAFE_ALLOWLIST_KEYS`);
    }
    if (netContent.includes(`"${key}"`)) {
      errors.push(`Prohibited sensitive attribute '${key}' found in .NET SafeAllowlist.DefaultKeys`);
    }
  }

  // Verify required shared keys exist in both allowlists
  for (const key of REQUIRED_SHARED_ALLOWLIST_KEYS) {
    if (!tsContent.includes(`'${key}'`)) {
      errors.push(`Required shared key '${key}' missing from TypeScript DEFAULT_SAFE_ALLOWLIST_KEYS`);
    }
    if (!netContent.includes(`"${key}"`)) {
      errors.push(`Required shared key '${key}' missing from .NET SafeAllowlist.DefaultKeys`);
    }
  }

  // Verify fail-closed redaction tokens start with [REDACTED_
  if (!tsContent.includes('[REDACTED_')) {
    errors.push('TypeScript allowlist sanitizer must produce [REDACTED_ tokens for unverified keys.');
  }
  if (!netContent.includes('[REDACTED_')) {
    errors.push('.NET SafeAllowlist sanitizer must produce [REDACTED_ tokens for unverified keys.');
  }
}

/**
 * Audit 3: Dynamic Claims Single Source of Truth
 */
export function auditDynamicClaims(errors = []) {
  const claimsPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/claims.ts');
  const netServicePath = resolve(
    REPO_ROOT,
    'packages/KnowThankYew.Privacy.Telemetry/Core/PrivacyTelemetryService.cs'
  );

  if (!existsSync(claimsPath)) {
    errors.push('Missing packages/privacy-telemetry/src/claims.ts');
    return;
  }
  if (!existsSync(netServicePath)) {
    errors.push('Missing packages/KnowThankYew.Privacy.Telemetry/Core/PrivacyTelemetryService.cs');
    return;
  }

  const claimsContent = readFileSync(claimsPath, 'utf-8');
  if (!claimsContent.includes('100% Client-Side Local Execution • Zero Network Transmission')) {
    errors.push('getPrivacyClaims missing standard consumer dropzone notice claim.');
  }
  if (!claimsContent.includes('OTLP Operational Metadata Active (Strictly Redacted)')) {
    errors.push('getPrivacyClaims missing standard enterprise dropzone notice disclaimer.');
  }

  const netContent = readFileSync(netServicePath, 'utf-8');
  if (
    !netContent.includes(
      'public bool IsLocalOnlyHonest => _mode != "otlp" && string.IsNullOrEmpty(_otlpEndpoint) && _networkEgress == "deny";'
    )
  ) {
    errors.push('.NET PrivacyTelemetryService missing canonical IsLocalOnlyHonest invariant computation.');
  }
}

/**
 * Audit 4: Cross-Engine Structured Handoff Protocol Parity
 */
export function auditHandoffProtocol(errors = []) {
  const handoffPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/handoff.ts');
  if (!existsSync(handoffPath)) {
    errors.push('Missing packages/privacy-telemetry/src/handoff.ts');
    return;
  }

  const handoffContent = readFileSync(handoffPath, 'utf-8');
  for (const tool of EXPECTED_HANDOFF_TOOLS) {
    if (!handoffContent.includes(`'${tool}'`)) {
      errors.push(`Handoff protocol missing standard destination tool: '${tool}'`);
    }
  }

  const expectedCategories = ['AUTO_RENEWAL', 'ARBITRATION', 'UNILATERAL_CHANGE', 'SURVEILLANCE', 'WARRANTY_DISCLAIMER'];
  for (const cat of expectedCategories) {
    if (!handoffContent.includes(`'${cat}'`)) {
      errors.push(`Handoff protocol missing trap category: '${cat}'`);
    }
  }

  if (!handoffContent.includes('export function validateHandoffPayload')) {
    errors.push('Handoff protocol must export fail-closed validateHandoffPayload function.');
  }
}

/**
 * Audit 5: Vocabulary Guardrails
 */
export function auditVocabulary(errors = []) {
  const docsToCheck = [
    resolve(REPO_ROOT, 'README.md'),
    resolve(REPO_ROOT, 'ROADMAP.md'),
    resolve(REPO_ROOT, 'ARCHITECTURE.md'),
  ];
  const docsDir = resolve(REPO_ROOT, 'docs');
  if (existsSync(docsDir)) {
    for (const entry of readdirSync(docsDir)) {
      if (entry.endsWith('.md')) {
        docsToCheck.push(resolve(docsDir, entry));
      }
    }
  }

  for (const docPath of docsToCheck) {
    if (!existsSync(docPath)) continue;
    const lines = readFileSync(docPath, 'utf-8').split('\n');
    lines.forEach((line, idx) => {
      const lower = line.toLowerCase();
      // Skip lines discussing the rule or quotation disclaimer
      if (
        lower.includes('prohibits unprovable') ||
        lower.includes('prohibited word') ||
        lower.includes('prohibited marketing') ||
        lower.includes('bulletproof') && lower.includes('prohibit')
      ) {
        return;
      }
      for (const pattern of PROHIBITED_WORDS) {
        if (pattern.test(line)) {
          errors.push(
            `Prohibited marketing word '${pattern.source}' found in ${docPath.replace(REPO_ROOT + '/', '')}:${idx + 1}: ${line.trim()}`
          );
        }
      }
    });
  }
}

/**
 * Audit 6: Central Package Management & Build Properties Conformance
 */
export function auditCentralPackageManagement(errors = []) {
  const dirPackages = resolve(REPO_ROOT, 'Directory.Packages.props');
  const dirBuild = resolve(REPO_ROOT, 'Directory.Build.props');
  const rootPkg = resolve(REPO_ROOT, 'package.json');

  if (!existsSync(dirPackages)) {
    errors.push('Missing Directory.Packages.props');
  } else {
    const content = readFileSync(dirPackages, 'utf-8');
    if (!content.includes('<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>')) {
      errors.push('Directory.Packages.props must enable ManagePackageVersionsCentrally.');
    }
  }

  if (!existsSync(dirBuild)) {
    errors.push('Missing Directory.Build.props');
  } else {
    const content = readFileSync(dirBuild, 'utf-8');
    if (!content.includes('<NuGetAudit>true</NuGetAudit>')) {
      errors.push('Directory.Build.props must enable NuGetAudit.');
    }
    if (!content.includes('<WarningsAsErrors>$(WarningsAsErrors);NU1903;NU1904</WarningsAsErrors>')) {
      errors.push('Directory.Build.props must treat NU1903 and NU1904 as build errors.');
    }
  }

  if (existsSync(rootPkg)) {
    const pkgJson = JSON.parse(readFileSync(rootPkg, 'utf-8'));
    if (!pkgJson.scripts?.['audit:claims']) {
      errors.push('Root package.json missing "audit:claims" script.');
    }
  }
}

/**
 * Audit 7: Portfolio Master Brief Parity
 */
export function auditPortfolioMasterBrief(
  errors = [],
  {
    requireBrief = false,
    overrideBriefPath = null,
    overrideTsTestsDir = null,
    overrideNetTestsDir = null,
  } = {}
) {
  const briefCandidates = overrideBriefPath
    ? [overrideBriefPath]
    : [
        resolve(DEV_ROOT, 'KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md'),
        resolve(REPO_ROOT, 'KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md'),
      ];
  const briefPath = briefCandidates.find((p) => existsSync(p));

  if (!briefPath) {
    if (requireBrief) {
      errors.push('KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md not found but required via --require-brief.');
    }
    return false;
  }

  const briefContent = readFileSync(briefPath, 'utf-8');

  // Match: `privacy-telemetry` ... (\d+)/(\d+) tests pass ((\d+) TS + (\d+) .NET)
  const pattern = /`privacy-telemetry`.*?(\d+)\/(\d+)\s+tests pass\s*\((\d+)\s+TS\s*\+\s*(\d+)\s+\.NET\)/i;
  const match = briefContent.match(pattern);
  if (!match) {
    errors.push('Could not find privacy-telemetry test inventory count in KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md');
    return false;
  }

  const documentedPassing = parseInt(match[1], 10);
  const documentedTotal = parseInt(match[2], 10);
  const documentedTs = parseInt(match[3], 10);
  const documentedNet = parseInt(match[4], 10);

  // Count actual TS tests
  const tsTestsDir = overrideTsTestsDir || resolve(REPO_ROOT, 'packages/privacy-telemetry/tests');
  let actualTsCount = 0;
  if (existsSync(tsTestsDir)) {
    const files = readdirSync(tsTestsDir).filter((f) => f.endsWith('.test.ts') || f.endsWith('.test.js'));
    for (const f of files) {
      const code = readFileSync(resolve(tsTestsDir, f), 'utf-8');
      const cleanCode = code
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*/g, '');
      const testMatches = cleanCode.match(/\b(?:it|test)(?:\.only|\.skip)?\s*\(/g) || [];
      actualTsCount += testMatches.length;
    }
  }

  // Count actual .NET tests
  const netTestsDir = overrideNetTestsDir || resolve(REPO_ROOT, 'tests');
  let actualNetCount = 0;
  function scanNetTests(dir) {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        scanNetTests(fullPath);
      } else if (entry.name.endsWith('.cs')) {
        const code = readFileSync(fullPath, 'utf-8');
        const cleanCode = code
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/\/\/.*/g, '');
        const factMatches = cleanCode.match(/\[(?:Fact|Theory)(?:\([^)]*\))?\]/g) || [];
        actualNetCount += factMatches.length;
      }
    }
  }
  if (existsSync(netTestsDir)) {
    scanNetTests(netTestsDir);
  }

  const actualTotal = actualTsCount + actualNetCount;

  if (
    documentedPassing !== documentedTotal ||
    documentedTotal !== actualTotal ||
    documentedTs !== actualTsCount ||
    documentedNet !== actualNetCount
  ) {
    errors.push(
      `Portfolio Brief Drift: KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md documents ${documentedPassing}/${documentedTotal} tests (${documentedTs} TS + ${documentedNet} .NET), but actual test suite has ${actualTotal} tests (${actualTsCount} TS + ${actualNetCount} .NET).`
    );
    return false;
  }

  return true;
}

/**
 * Main execution CLI
 */
export function runAllAudits(options = {}) {
  const errors = [];
  auditZeroEgress(errors);
  auditAllowlistParity(errors);
  auditDynamicClaims(errors);
  auditHandoffProtocol(errors);
  auditVocabulary(errors);
  auditCentralPackageManagement(errors);
  const briefChecked = auditPortfolioMasterBrief(errors, options);

  return { errors, briefChecked };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('=== Privacy Telemetry Claims, Architecture & Parity Audit ===\n');
  const requireBrief = process.argv.includes('--require-brief');
  const { errors, briefChecked } = runAllAudits({ requireBrief });

  if (errors.length > 0) {
    console.error(`[FAIL] Found ${errors.length} claims / architectural invariant violation(s):`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log('[PASS] All privacy-telemetry architectural & claims invariants verified:');
  console.log("  ✓ Zero-egress air-gap verified (memory_only default, networkEgress 'deny', zero unauthorized network primitives)");
  console.log('  ✓ Telemetry allowlist & fail-closed redaction parity verified between TS and .NET');
  console.log('  ✓ Single source of truth for honest dynamic privacy claims verified');
  console.log('  ✓ Cross-engine structured handoff protocol validated against portfolio tools');
  console.log('  ✓ Central Package Management (CPM) & fail-closed NuGet audit properties verified');
  console.log('  ✓ Zero prohibited marketing adjectives detected in documentation');
  if (briefChecked) {
    console.log('  ✓ Portfolio Master Brief parity verified');
  } else {
    console.log('  - Portfolio Master Brief check skipped (isolated CI)');
  }
  process.exit(0);
}
