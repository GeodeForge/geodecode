(function(){
"use strict";

const PLACEHOLDER_PATTERN = /GEODE_[A-Z0-9]+(?:_[A-Z0-9]+)*_\d+/g;
const mayHoldToken = (s) => typeof s === 'string' && s.indexOf('GEODE_') >= 0;

const INV = String.raw`­᠎​-‏⁠-⁤﻿`;
const INV_HEX = '(?:00[aA][dD]|180[eE]|200[b-fB-F]|206[0-4]|[fF][eE][fF][fF])';
const WS_HEX = '(?:000[9aAdD]|0020|00[aA]0|00[aA][dD]|180[eE]|200[0-9a-fA-F]|202[fF]|205[fF]|206[0-4]|3000|[fF][eE][fF][fF])';
const GAP = String.raw`(?:[\s${INV}]|\\+[nrt]|\\+u${WS_HEX}|%(?:20|09|0[aAdD])|%[cC]2%[aA]0|%[eE]2%80%8[b-dB-D]|\+)+`;
const SKIP = String.raw`(?:[${INV}]|\\+u${INV_HEX}|%[eE]2%80%8[b-dB-D])*`;
const MARKS = String.raw`(?:[̀-ͯ᪰-᫿᷀-᷿⃐-⃿︠-︯]|\\+u03[0-6][0-9a-fA-F]|%[cC][cCdD]%[89abAB][0-9a-fA-F])*`;
const WORDISH = /[\p{Lu}\p{Ll}\p{Lt}\p{N}\p{M}_]/u;
const EDGE = /[\p{Lu}\p{Ll}\p{Lt}\p{N}_]/u;
const WORD_GAP = new RegExp(`[\\s${INV}]+`, 'u');
const TOKENS = new RegExp(PLACEHOLDER_PATTERN.source, 'g');
const INVISIBLE_RE = new RegExp(`[${INV}]`, 'gu');
const RANGES = [[0xc0, 0x24f], [0x370, 0x3ff], [0x400, 0x4ff], [0x1e00, 0x1eff], [0x1f00, 0x1fff]];

const esc = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
const classEsc = (ch) => ch.replace(/[\\\][^-]/g, '\\$&');
const hexCi = (h) => h.replace(/[a-fA-F]/g, (c) => `[${c.toLowerCase()}${c.toUpperCase()}]`);
const edged = (c) => c !== undefined && EDGE.test(c);

const unescape = (s) => {
  let out = s.replace(/\\+u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
  if (out.includes('%')) out = out.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch (_) { return m; } });
  return out;
};
const fold = (s) => unescape(String(s)).normalize('NFKD').replace(/\p{M}/gu, '').replace(INVISIBLE_RE, '').toLowerCase();

let BY_BASE = null;
const byBase = () => {
  if (BY_BASE) return BY_BASE;
  BY_BASE = new Map();
  for (const [lo, hi] of RANGES) {
    for (let cp = lo; cp <= hi; cp++) {
      const ch = String.fromCodePoint(cp);
      const base = ch.normalize('NFD').replace(/\p{M}/gu, '');
      if (base.length !== 1 || base === ch) continue;
      const k = base.toLowerCase();
      if (!BY_BASE.has(k)) BY_BASE.set(k, []);
      BY_BASE.get(k).push(ch);
    }
  }
  return BY_BASE;
};

const escapedSource = (f) => {
  let src = '';
  for (let i = 0; i < f.length; i++) {
    const c = f.charCodeAt(i);
    src += c < 0x80 ? esc(f[i]) : String.raw`\\+u` + hexCi(c.toString(16).padStart(4, '0'));
  }
  return src;
};

function charForms(c) {
  const base = c.normalize('NFD').replace(/\p{M}/gu, '');
  const singles = new Set();
  const multis = new Set();
  const addForm = (f, written) => {
    if ([...f].length === 1) singles.add(f); else multis.add(esc(f));
    if (written && /[^\x00-\x7f]/.test(f)) { multis.add(escapedSource(f)); multis.add(hexCi(esc(encodeURIComponent(f)))); }
  };
  for (const k of new Set([c, base.length === 1 ? base : c])) {
    for (const f of [k, k.toLowerCase(), k.toUpperCase()]) {
      addForm(f, true);
      const cp = f.codePointAt(0);
      if (f.length === 1 && cp >= 0x21 && cp <= 0x7e) addForm(String.fromCodePoint(cp + 0xfee0), false);
      for (const v of byBase().get(f.toLowerCase()) || []) addForm(v, false);
    }
  }
  const parts = [];
  if (singles.size) parts.push(`[${[...singles].map(classEsc).join('')}]`);
  parts.push(...[...multis].sort((a, b) => b.length - a.length));
  return `(?:${parts.join('|')})${MARKS}`;
}

const ESCAPED_BEFORE = [[2, /^\\[nrt]$/], [6, /^\\u[0-9a-fA-F]{4}$/], [3, /^%[0-9a-fA-F]{2}$/]];
function standsAlone(text, start, end, e) {
  if (e.before && start > 0) {
    const lo = text.charCodeAt(start - 1);
    const prev = lo >= 0xdc00 && lo <= 0xdfff && start > 1 ? text.slice(start - 2, start) : text[start - 1];
    if (WORDISH.test(prev) && !ESCAPED_BEFORE.some(([n, re]) => start >= n && re.test(text.slice(start - n, start)))) return false;
  }
  if (e.after && end < text.length) {
    const next = String.fromCodePoint(text.codePointAt(end));
    if (WORDISH.test(next)) return false;
  }
  return true;
}

const NUMBER_MIN_PROVENANCE = 'fact-about: not measured on any corpus. A value of only digits and separators with at least 7 digits is matched digit by digit with any separators between, as exact-data-match tools do; shorter numbers keep exact matching so they do not hit dates and amounts.';
const NUMBER_MIN = 7;
const NUMBER_LIKE = /^[+\d\s().\-\/\u2010-\u2015\u2212]+$/u;
const NUM_SEP_MAX_PROVENANCE = 'fact-about: not measured on any corpus. At most 8 separator characters are allowed between two digits of a long number; written phone numbers use 3 or fewer, and the bound keeps the match linear in the length of the text.';
const NUM_SEP_ONE = String.raw`(?:[\s${INV}.\-/()+\u2010-\u2015\u2212]|\\{1,8}[nrt]|\\{1,8}u${WS_HEX}|\\{1,8}u20(?:1[0-5]|12)|%(?:20|09|0[aAdD])|%[cC]2%[aA]0|%[eE]2%80%8[b-dB-D]|%[eE]2%80%9[0-5])`;
const NUM_SEP = `${NUM_SEP_ONE}{0,8}`;

const COUNTRY_CODES_PROVENANCE = 'fact-about: the ITU-T E.164 country calling codes as listed in Google libphonenumber metadata, packaged as libphonenumber-js 1.13.15 (country_calling_codes plus the non-geographic codes; 215 codes), read 2026-11-04. Not measured on any corpus. The set is prefix-free, so the code at the start of a number saved with + or 00 and no separators is read off without guessing. A code assigned after that date is missed only when the number is also saved without separators; refresh from the same source.';
const COUNTRY_CODES = new Set('1 7 20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98 211 212 213 216 218 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 257 258 260 261 262 263 264 265 266 267 268 269 290 291 297 298 299 350 351 352 353 354 355 356 357 358 359 370 371 372 373 374 375 376 377 378 380 381 382 383 385 386 387 389 420 421 423 500 501 502 503 504 505 506 507 508 509 590 591 592 593 594 595 596 597 598 599 670 672 673 674 675 676 677 678 679 680 681 682 683 685 686 687 688 689 690 691 692 800 808 850 852 853 855 856 870 878 880 881 882 883 886 888 960 961 962 963 964 965 966 967 968 970 971 972 973 974 975 976 977 979 992 993 994 995 996 998'.split(' '));
const countryCode = (ds) => { for (let n = 1; n <= 3; n++) if (COUNTRY_CODES.has(ds.slice(0, n))) return ds.slice(0, n); return null; };
const DIGIT = `(?:${[...'0123456789'].map(charForms).join('|')})`;

const NUMBER_FORMS_PROVENANCE = 'fact-about: not measured on any corpus. Over-replacement is the safe direction: a listed number is replaced in its international form (+ or 00, the country code, an optional trunk 0 or (0)), its national form (with or without the trunk 0) and its bare form. A number saved in national form does not say its country, so any 1-3 digit code after + or 00 is accepted.';

function compileNumber(value) {
  const v = String(value).normalize('NFKC').trim();
  if (!NUMBER_LIKE.test(v)) return null;
  const digits = v.replace(/\D/g, '');
  if (digits.length < NUMBER_MIN) return null;
  const join = (ds) => [...ds].map(charForms).join(NUM_SEP);
  const plus = String.raw`(?:\+|${charForms('+')}|%2[bB]|00)`;
  const trunk = `(?:${charForms('0')}${NUM_SEP})`;
  const open = String.raw`(?:\(${NUM_SEP})?`;
  const intl = v.startsWith('+') ? digits : /^\(?\s*00/.test(v) ? digits.slice(2) : null;
  const cc = intl === null ? null : countryCode(intl);
  let prefix;
  let national;
  if (cc) {
    national = intl.slice(cc.length).replace(/^0/, '');
    prefix = `(?:(?:${plus}${NUM_SEP})?${join(cc)}${NUM_SEP}${trunk}?|${trunk})?`;
  } else if (intl === null) {
    national = digits.replace(/^0/, '');
    const anyCc = `${plus}${NUM_SEP}${DIGIT}{1,3}${NUM_SEP}`;
    prefix = digits.startsWith('0') ? `(?:${anyCc}${trunk}?|${trunk})?` : `(?:${anyCc})?`;
  } else {
    national = digits;
    prefix = `(?:${plus}${NUM_SEP})?`;
  }
  return { re: new RegExp(open + prefix + join(national), 'gu'), before: true, after: true, anchor: '', digits: national };
}

const compiled = new Map();
function compile(value) {
  if (compiled.has(value)) return compiled.get(value);
  const number = compileNumber(value);
  if (number) { compiled.set(value, number); return number; }
  let entry = null;
  const words = String(value).normalize('NFC').trim().split(WORD_GAP).filter(Boolean).map((w) => [...w]);
  if (words.length) {
    const source = words.map((cs) => cs.map(charForms).join(SKIP)).join(GAP);
    const runs = fold(value).match(/[a-z0-9]+/g) || [];
    entry = {
      re: new RegExp(source, 'gu'),
      before: edged(words[0][0]),
      after: edged(words[words.length - 1][words[words.length - 1].length - 1]),
      anchor: runs.reduce((a, b) => (b.length > a.length ? b : a), ''),
    };
  }
  compiled.set(value, entry);
  return entry;
}

const digitsOf = (folded) => folded.replace(/[^0-9]/g, '');
const ruledOut = (e, folded, digits) => (e.anchor && !folded.includes(e.anchor)) || (e.digits && !digits().includes(e.digits));

function variantFound(value, text, folded = fold(text)) {
  const e = compile(value);
  let d = null;
  if (!e || ruledOut(e, folded, () => (d !== null ? d : (d = digitsOf(folded))))) return false;
  e.re.lastIndex = 0;
  for (let m; (m = e.re.exec(text));) {
    if (standsAlone(text, m.index, m.index + m[0].length, e)) { e.re.lastIndex = 0; return true; }
    if (!m[0].length) e.re.lastIndex++;
  }
  return false;
}

function variantLengthAt(value, text, at) {
  const e = compile(value);
  if (!e) return -1;
  e.re.lastIndex = at;
  const m = e.re.exec(text);
  e.re.lastIndex = 0;
  if (!m || m.index !== at || !m[0].length) return -1;
  return standsAlone(text, at, at + m[0].length, e) ? m[0].length : -1;
}

function variantMatcher(values) {
  const list = [...new Set((values || []).filter((v) => typeof v === 'string' && v.trim().length))]
    .sort((a, b) => b.length - a.length)
    .map((value) => ({ value, entry: compile(value) }))
    .filter((e) => e.entry);
  const replace = (text, tokenFor, counts) => {
    if (!list.length || typeof text !== 'string' || !text) return text;
    const folded = fold(text);
    let d = null;
    const live = list.filter((e) => !ruledOut(e.entry, folded, () => (d !== null ? d : (d = digitsOf(folded)))));
    if (!live.length) return text;
    let out = text;
    for (const { value, entry } of live) {
      const token = tokenFor(value);
      if (!token) continue;
      const spans = mayHoldToken(out) ? [...out.matchAll(TOKENS)].map((m) => [m.index, m.index + m[0].length]) : [];
      const inToken = (a, b) => {
        let lo = 0, hi = spans.length - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >> 1;
          if (spans[mid][1] <= a) lo = mid + 1; else if (spans[mid][0] >= b) hi = mid - 1; else return true;
        }
        return false;
      };
      out = out.replace(entry.re, (m, ...rest) => {
        const at = rest[rest.length - 2];
        const whole = rest[rest.length - 1];
        if (inToken(at, at + m.length) || !standsAlone(whole, at, at + m.length, entry)) return m;
        if (counts) counts.set(value, (counts.get(value) || 0) + 1);
        return token;
      });
    }
    return out;
  };
  return { replace };
}

const B64_MIN = 16;
const B64_LAYERS = 3;
const B64_RUN = /(?:[A-Za-z0-9_-]|[+/]|%2[BbFf])+(?:=|%3[Dd]){0,2}/g;
const NOT_TEXT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F�]/;
let utf8Strict = null;
const decodeUtf8 = (bytes) => { try { if (!utf8Strict) utf8Strict = new TextDecoder('utf-8', { fatal: true }); return utf8Strict.decode(bytes); } catch (_) { return null; } };
const asBytes = (s) => { const b = new TextEncoder().encode(s); let o = ''; for (let i = 0; i < b.length; i++) o += String.fromCharCode(b[i]); return o; };
const runOk = (raw) => raw.length >= B64_MIN && !mayHoldToken(raw);

function decodeRun(raw) {
  const pairs = [['+', /%2[Bb]/], ['/', /%2[Ff]/], ['=', /%3[Dd]/]];
  for (const [c, re] of pairs) if (raw.indexOf(c) >= 0 && re.test(raw)) return null;
  const plain = raw.replace(/%2[Bb]/g, '+').replace(/%2[Ff]/g, '/').replace(/%3[Dd]/g, '=');
  const body = plain.replace(/=+$/, '');
  if (body.length < B64_MIN || body.indexOf('=') >= 0 || body.length % 4 === 1) return null;
  const safe = /[-_]/.test(body), std = /[+/]/.test(body);
  if (safe && std) return null;
  const b = safe ? body.replace(/-/g, '+').replace(/_/g, '/') : body;
  let bin;
  try { bin = atob(b + '='.repeat((4 - (b.length % 4)) % 4)); } catch (_) { return null; }
  if (btoa(bin).replace(/=+$/, '') !== b) return null;
  return bin;
}

function blockHolds(bin, values, layer) {
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const text = decodeUtf8(bytes);
  if (text !== null && !NOT_TEXT.test(text)) {
    const folded = fold(text);
    for (const v of values) if (variantFound(v, text, folded)) return true;
    return layer < B64_LAYERS && runsHolding(text, values, layer + 1).length > 0;
  }
  for (const v of values) if (bin.indexOf(asBytes(v)) >= 0) return true;
  return false;
}

function runsHolding(text, values, layer) {
  const found = [];
  const re = new RegExp(B64_RUN.source, 'g');
  for (let m; (m = re.exec(text));) {
    if (!runOk(m[0])) continue;
    const bin = decodeRun(m[0]);
    if (bin !== null && bin.length >= 2 && blockHolds(bin, values, layer)) found.push(m[0]);
  }
  return found;
}

function tokenSpans(s) {
  if (!mayHoldToken(s)) return [];
  return [...s.matchAll(TOKENS)].map((m) => [m.index, m.index + m[0].length]);
}
function overlaps(spans, a, b) {
  for (const [s, e] of spans) if (s < b && e > a) return true;
  return false;
}
function firstAt(value, text) {
  let best = text.indexOf(value);
  const e = compile(value);
  if (e) {
    e.re.lastIndex = 0;
    for (let m; (m = e.re.exec(text));) {
      if (standsAlone(text, m.index, m.index + m[0].length, e)) { if (best < 0 || m.index < best) best = m.index; break; }
      if (!m[0].length) e.re.lastIndex++;
    }
    e.re.lastIndex = 0;
  }
  return best;
}

const TOKEN_TRIES = 10000;

function removeListed(text, list, E) {
  text = typeof text === 'string' ? text : (text == null ? '' : String(text));
  const seen = Object.create(null), items = [];
  (Array.isArray(list) ? list : []).forEach((s) => { if (typeof s === 'string' && s.length > 0 && !seen[s]) { seen[s] = 1; items.push(s); } });
  if (!items.length) return { output: text, map: [] };

  let k = 0;
  while (text.indexOf('GEODE_LMQ' + k + '_') >= 0) k++;
  const pre = 'GEODE_LMQ' + k + '_';
  const temp = new Map();
  items.forEach((v, i) => temp.set(v, pre + 'V' + i + '_0'));
  const counts = new Map();

  let out = variantMatcher(items).replace(text, (v) => temp.get(v), counts);

  items.slice().sort((a, b) => b.length - a.length).forEach((v) => {
    if (out.indexOf(v) < 0) return;
    const spans = tokenSpans(out);
    let res = '', from = 0, n = 0;
    for (let at = out.indexOf(v); at >= 0; at = out.indexOf(v, at + 1)) {
      if (at < from || overlaps(spans, at, at + v.length)) continue;
      res += out.slice(from, at) + temp.get(v); from = at + v.length; n++;
    }
    if (n) { out = res + out.slice(from); counts.set(v, (counts.get(v) || 0) + n); }
  });

  const blocks = new Map(), blockCounts = new Map();
  runsHolding(out, items, 1).forEach((raw) => { if (!blocks.has(raw)) blocks.set(raw, pre + 'B' + blocks.size + '_0'); });
  if (blocks.size) {
    out = out.replace(new RegExp(B64_RUN.source, 'g'), (m) => {
      if (!blocks.has(m)) return m;
      blockCounts.set(m, (blockCounts.get(m) || 0) + 1);
      return blocks.get(m);
    });
  }

  const entries = [];
  items.forEach((v) => {
    const pos = firstAt(v, text), c = counts.get(v) || 0;
    if (c > 0 || pos >= 0) entries.push({ value: v, label: E.labelOfLiteral(v), count: c, temp: temp.get(v), pos: pos >= 0 ? pos : Infinity });
  });
  blocks.forEach((t, raw) => {
    const pos = text.indexOf(raw);
    entries.push({ value: raw, label: 'BASE64', count: blockCounts.get(raw) || 0, temp: t, pos: pos >= 0 ? pos : Infinity });
  });
  entries.sort((a, b) => (a.pos !== b.pos ? a.pos - b.pos : b.value.length - a.value.length));

  const counters = Object.create(null), map = [];
  entries.forEach((e) => {
    const comp = E.compressLabel(e.label);
    let n = (counters[comp] || 0) + 1, token = 'GEODE_' + comp + '_' + n, tries = 0;
    while (tries++ < TOKEN_TRIES && (text.indexOf(token) >= 0 || out.indexOf(token) >= 0 || items.some((v) => token.indexOf(v) >= 0))) { n++; token = 'GEODE_' + comp + '_' + n; }
    counters[comp] = n;
    e.token = token;
    map.push({ token: token, value: e.value, label: e.label, count: e.count });
  });
  entries.slice().sort((a, b) => b.temp.length - a.temp.length).forEach((e) => { out = out.split(e.temp).join(e.token); });

  map.forEach((m) => {
    if (m.count !== 0) return;
    if (out.indexOf(m.value) >= 0) { m.leaked = true; return; }
    let by = null;
    map.forEach((o) => { if (o !== m && o.count > 0 && o.value.indexOf(m.value) >= 0 && (!by || o.value.length < by.length)) by = o.value; });
    m.subsumedBy = by;
  });
  return { output: out, map: map };
}

const API = { removeListed: removeListed, fold: fold, variantFound: variantFound, variantLengthAt: variantLengthAt, variantMatcher: variantMatcher };
globalThis.GEODECODE_LISTMATCH = API;
if (typeof module !== 'undefined' && module.exports) { module.exports = API; }
})();
