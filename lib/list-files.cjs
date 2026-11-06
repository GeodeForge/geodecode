(function(){
"use strict";

const PRODUCT = Object.freeze({ name: 'GeodeCode' });
const FIELDS = Object.freeze(['aka', 'family', 'org', 'email', 'phone', 'address', 'other']);
function cleanValue(value) {
  const v = String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!v) return { ok: false, why: 'Type a name or other value first.' };
  if (v.startsWith('#')) return { ok: false, why: 'A value cannot start with #.' };
  return { ok: true, value: v };
}

const uniq = (xs) => {
  const out = [];
  for (const x of xs) { const c = cleanValue(x); if (c.ok && !out.includes(c.value)) out.push(c.value); }
  return out;
};

function cleanEntry(e) {
  const out = { name: '' };
  for (const f of FIELDS) out[f] = uniq(Array.isArray(e && e[f]) ? e[f] : []);
  const n = cleanValue(e && e.name);
  out.name = n.ok ? n.value : (FIELDS.map((f) => out[f][0]).find(Boolean) || '');
  for (const f of FIELDS) out[f] = out[f].filter((v) => v !== out.name);
  return out.name ? out : null;
}

const entryValues = (e) => uniq([e.name, ...FIELDS.flatMap((f) => e[f] || [])]);

const CSV_HEADER = Object.freeze(['List', 'Name', 'Also known as', 'Organization', 'Email', 'Phone', 'Address', 'Other', 'Family name']);
const CSV_FIELDS = Object.freeze([null, 'name', 'aka', 'org', 'email', 'phone', 'address', 'other', 'family']);
const CSV_HEADER_FIRST = CSV_HEADER.slice(0, 8);
const MULTI = ' ::: ';
const PRODID = `-//${PRODUCT.name}//lists//EN`;
const OURS = /\/\/lists\/\/EN$/;
const SHORT_DIGITS_PROVENANCE = 'fact-about: not measured on any corpus. A number of fewer than 7 digits (an extension, a house number) also turns up in ordinary text, so an import points it out; a design choice, not a measurement.';
const SHORT_DIGITS = 7;
const FILE_LIMIT_PROVENANCE = 'fact-about: not measured on any corpus. 20 MB is a ceiling on one contacts or list file read for import; a contacts of thousands of people without photos is far smaller.';
const FILE_LIMIT = 20 * 1024 * 1024;

function decodeText(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8').decode(b.subarray(3));
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.subarray(2));
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.subarray(2));
  try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (_) { return new TextDecoder('windows-1252').decode(b); }
}

const parseCsvRows = (text, sep) => {
  const rows = [];
  let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c;
    } else if (c === '"' && cell === '') q = true;
    else if (c === sep) { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim() !== ''));
};

const firstLine = (text) => {
  let q = false;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"') q = !q;
    else if (!q && (text[i] === '\n' || text[i] === '\r')) return text.slice(0, i);
  }
  return text;
};

const guessSep = (text) => {
  const line = firstLine(text).replace(/"[^"]*"/g, '');
  const count = (ch) => line.split(ch).length - 1;
  return [',', ';', '\t'].map((s) => [s, count(s)]).sort((a, b) => b[1] - a[1])[0][0];
};

const norm = (h) => String(h).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

function columnKind(header) {
  const h = norm(header);
  if (!h) return null;
  if (h === 'list' || h === 'geodemind list') return 'list';
  if (['labels', 'group membership', 'categories', 'groups', 'group'].includes(h)) return 'groups';
  if (/phonetic|yomi/.test(h)) return null;
  if (/\be ?mail\b/.test(h)) return /type|label|display/.test(h) ? null : 'email';
  if (/\b(phone|telephone|tel|mobile|cell|fax|pager)\b/.test(h)) return /type|label/.test(h) ? null : 'phone';
  if (h === 'address' || /\bstreet\b/.test(h)) return 'address';
  if (/\b(company|organization|organisation)\b/.test(h)) return /title|department|job|location|symbol|type|label/.test(h) ? null : 'org';
  if (/\b(nickname|also known as|aka|alias|other names?)\b/.test(h)) return 'aka';
  if (/^(first name|given name)$/.test(h)) return 'given';
  if (/^(middle name|middle names|additional name)$/.test(h)) return 'middle';
  if (/^(last name|family name|surname)$/.test(h)) return 'family';
  if (/^(name|full name|display name|contact name|client name|contact)$/.test(h)) return 'name';
  if (h === 'other' || h === 'other values') return 'other';
  return null;
}

const splitMulti = (v) => String(v || '').split(MULTI).map((s) => s.trim()).filter(Boolean);
const unguard = (v) => (/^'[=+\-@\t\r]/.test(v) ? v.slice(1) : v);

function fromCsv(text) {
  const sep = guessSep(text);
  const rows = parseCsvRows(text, sep);
  if (!rows.length) return { format: 'csv', entries: [], ignored: [], ours: false };
  const head = rows[0];
  const kinds = head.map(columnKind);
  const ours = head.length >= CSV_HEADER_FIRST.length && CSV_HEADER_FIRST.every((h, i) => norm(head[i]) === norm(h));
  if (!kinds.some(Boolean)) {
    const entries = rows.flatMap((r) => r.map((c) => c.trim()).filter(Boolean).map((v) => ({ name: v })));
    return { format: 'csv', entries: entries.map(cleanEntry).filter(Boolean), ignored: [], ours: false, noHeader: true };
  }
  const ignored = head.filter((h, i) => !kinds[i] && String(h).trim()).map((h) => String(h).trim());
  const entries = [];
  for (const r of rows.slice(1)) {
    const e = { name: '', given: [], middle: [], family: [], groups: [], ...Object.fromEntries(FIELDS.map((f) => [f, []])) };
    let full = [];
    r.forEach((raw, i) => {
      const k = kinds[i];
      if (!k) return;
      const cell = ours ? unguard(raw) : raw;
      const parts = k === 'groups' ? cell.split(/ ::: |;|,/).map((s) => s.trim()).filter(Boolean) : splitMulti(cell);
      if (k === 'name') full.push(...parts);
      else if (k === 'list') e.groups.push(...parts);
      else e[k].push(...parts);
    });
    const composed = [e.given[0], e.middle[0], e.family[0]].filter(Boolean).join(' ');
    e.name = full[0] || composed;
    e.aka.push(...full.slice(1));
    if (composed && composed !== e.name && (e.given[0] || e.middle[0])) e.aka.push(composed);
    const groups = e.groups.filter((g) => !g.startsWith('* ') && !/^(mycontacts|starred)$/i.test(g));
    const c = cleanEntry(e);
    if (c) entries.push({ ...c, groups: [...new Set(groups)] });
  }
  return { format: 'csv', entries, ignored, ours };
}

const unescapeV = (s) => s.replace(/\\([nN,;:\\])/g, (m, c) => (c === 'n' || c === 'N' ? ' ' : c));
const splitUnescaped = (s, ch) => {
  const out = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length) { cur += s[i] + s[i + 1]; i++; continue; }
    if (s[i] === ch) { out.push(cur); cur = ''; } else cur += s[i];
  }
  out.push(cur);
  return out;
};

const qpDecode = (s, charset) => {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) { bytes.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; }
    else bytes.push(...new TextEncoder().encode(s[i]));
  }
  try { return new TextDecoder(charset || 'utf-8').decode(new Uint8Array(bytes)); } catch (_) { return new TextDecoder('utf-8').decode(new Uint8Array(bytes)); }
};

function vLines(text) {
  const raw = text.split(/\r\n|\r|\n/);
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i];
    if (/^[ \t]/.test(line) && out.length) { out[out.length - 1] += line.slice(1); continue; }
    if (/QUOTED-PRINTABLE/i.test(line.split(':')[0] || '')) {
      while (line.endsWith('=') && i + 1 < raw.length) { line = line.slice(0, -1) + raw[++i]; }
    }
    out.push(line);
  }
  return out;
}

function fromVcard(text) {
  const entries = [];
  let ours = false;
  let depth = 0;
  let cur = null;
  for (const line of vLines(text)) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const left = line.slice(0, colon);
    const value = line.slice(colon + 1);
    const [nameRaw, ...params] = left.split(';');
    const name = nameRaw.replace(/^[^.]*\./, '').toUpperCase();
    if (name === 'BEGIN' && /^vcard$/i.test(value.trim())) {
      depth++;
      if (depth === 1) cur = { name: '', fn: '', n: '', groups: [], ...Object.fromEntries(FIELDS.map((f) => [f, []])) };
      continue;
    }
    if (name === 'END' && /^vcard$/i.test(value.trim())) {
      depth = Math.max(0, depth - 1);
      if (depth === 0 && cur) {
        cur.name = cur.fn || cur.n;
        if (cur.n && cur.n !== cur.name && cur.n !== cur.family[0]) cur.aka.push(cur.n);
        const c = cleanEntry(cur);
        if (c) entries.push({ ...c, groups: [...new Set(cur.groups)] });
        cur = null;
      }
      continue;
    }
    if (name === 'PRODID' && OURS.test(value.trim())) { ours = true; continue; }
    if (!cur || depth !== 1) continue;
    const p = Object.fromEntries(params.map((x) => { const [k, v] = x.split('='); return [k.toUpperCase(), (v || '').replace(/^"|"$/g, '')]; }));
    const enc = p.ENCODING || ('QUOTED-PRINTABLE' in p ? 'QUOTED-PRINTABLE' : 'BASE64' in p ? 'BASE64' : '');
    if (/^(B|BASE64)$/i.test(enc)) continue;
    const v = /QUOTED-PRINTABLE/i.test(enc) ? qpDecode(value, p.CHARSET) : value;
    if (name === 'FN') cur.fn = unescapeV(v).trim();
    else if (name === 'N') {
      const [family, given, middle] = splitUnescaped(v, ';').map((x) => unescapeV(x).trim());
      cur.n = [given, middle, family].filter(Boolean).join(' ');
      if (family) cur.family.push(family);
    } else if (name === 'NICKNAME') cur.aka.push(...splitUnescaped(v, ',').map(unescapeV));
    else if (name === 'ORG') cur.org.push(unescapeV(splitUnescaped(v, ';')[0]));
    else if (name === 'EMAIL') cur.email.push(unescapeV(v).replace(/^mailto:/i, ''));
    else if (name === 'TEL') cur.phone.push(unescapeV(v).replace(/^tel:/i, ''));
    else if (name === 'ADR') cur.address.push(unescapeV(splitUnescaped(v, ';')[2] || ''));
    else if (name === 'CATEGORIES') cur.groups.push(...splitUnescaped(v, ',').map((g) => unescapeV(g).trim()).filter((g) => g && !/^(mycontacts|starred)$/i.test(g)));
    else if (name === 'X-GEODEMIND-VALUE') cur.other.push(unescapeV(v));
  }
  return { format: 'vcard', entries, ignored: [], ours };
}

function fromText(text) {
  const entries = text.split(/\r\n|\r|\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((v) => cleanEntry({ name: v })).filter(Boolean);
  return { format: 'text', entries, ignored: [], ours: false };
}

function readListFile(buf, fileName = '') {
  if (buf.length > FILE_LIMIT) return { ok: false, why: `That file is larger than ${FILE_LIMIT / 1024 / 1024} MB. Export your contacts without photos, then try again.` };
  const text = decodeText(buf);
  const ext = String(fileName).toLowerCase().split('.').pop();
  let r;
  if (ext === 'vcf' || ext === 'vcard' || /^\s*BEGIN:VCARD/i.test(text)) r = fromVcard(text);
  else if (ext === 'csv' || ext === 'tsv') r = fromCsv(text);
  else if (ext === 'txt' || ext === 'text') r = fromText(text);
  else return { ok: false, why: `${PRODUCT.name} reads contacts files (.vcf), spreadsheet files saved as CSV (.csv) and plain text lists (.txt).` };
  const groups = {};
  for (const e of r.entries) for (const g of e.groups || []) groups[g] = (groups[g] || 0) + 1;
  return { ok: true, ...r, groups, values: new Set(r.entries.flatMap(entryValues)).size };
}

function riskyValues(entries) {
  const out = [];
  for (const e of entries) {
    for (const [field, vals] of [['name', [e.name]], ['aka', e.aka], ['org', e.org], ['phone', e.phone], ['other', e.other]]) {
      for (const v of vals || []) {
        const digits = v.replace(/[^0-9]/g, '');
        const oneWord = !/\s/.test(v) && /^\p{L}[\p{L}'’.-]*$/u.test(v);
        const shortNumber = /^[0-9\s()+.\-/]+$/.test(v) && digits.length > 0 && digits.length < SHORT_DIGITS;
        if ((oneWord && field !== 'phone') || shortNumber) out.push(v);
      }
    }
  }
  return [...new Set(out)];
}

function familyValues(entries) {
  const risky = new Set(riskyValues(entries));
  return [...new Set(entries.flatMap((e) => e.family || []))].filter((v) => !risky.has(v));
}


const API = { readListFile: readListFile, familyValues: familyValues, riskyValues: riskyValues, entryValues: entryValues, columnKind: columnKind, FILE_LIMIT: FILE_LIMIT };
globalThis.GEODECODE_LISTFILES = API;
if (typeof module !== 'undefined' && module.exports) { module.exports = API; }
})();
