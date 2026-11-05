import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const E = require(path.join(HERE, 'lib', 'geodecode-engine.cjs'));
const F = require(path.join(HERE, 'lib', 'folder-scan.cjs'));

function usage(msg) {
  if (msg) console.error(msg);
  console.error('usage: node scan-folder.mjs <folder> [--git] [--include-skipped] [--show-values] [--receipt <file>] [--max-size <MB>]');
  process.exit(2);
}

const args = process.argv.slice(2);
const o = { git: false, includeSkipped: false, showValues: false, receipt: null, maxMB: null, folder: null };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--git') o.git = true;
  else if (a === '--include-skipped') o.includeSkipped = true;
  else if (a === '--show-values') o.showValues = true;
  else if (a === '--receipt') { o.receipt = args[++i]; if (!o.receipt) usage('--receipt needs a file name'); }
  else if (a === '--max-size') { o.maxMB = Number(args[++i]); if (!(o.maxMB > 0)) usage('--max-size needs a number of megabytes above 0'); }
  else if (a === '-h' || a === '--help') usage();
  else if (a.startsWith('--')) usage('unknown option ' + a);
  else if (o.folder === null) o.folder = a;
  else usage('give one folder');
}
if (!o.folder) usage();
const root = path.resolve(o.folder);
let st;
try { st = fs.statSync(root); } catch { usage('cannot open ' + o.folder); }
if (!st.isDirectory()) usage(o.folder + ' is not a folder');

const opts = {};
if (o.maxMB) opts.maxBytes = Math.floor(o.maxMB * 1024 * 1024);
if (o.includeSkipped || o.git) opts.skipDirs = [];
const rep = F.newReport(E, opts);

function readOne(rel) {
  if (F.skippedDirOf(rel, rep.options)) { F.addFile(rep, rel, null); return; }
  const full = path.join(root, rel);
  let ls;
  try { ls = fs.lstatSync(full); } catch { F.addFile(rep, rel, null, 'unreadable'); return; }
  if (ls.isSymbolicLink()) { F.addFile(rep, rel, null, 'link'); return; }
  if (!ls.isFile()) return;
  if (ls.size > rep.options.maxBytes) { F.addFile(rep, rel, null, 'tooLarge', ls.size); return; }
  let bytes;
  try { bytes = fs.readFileSync(full); } catch { F.addFile(rep, rel, null, 'unreadable'); return; }
  F.addFile(rep, rel, bytes, null, bytes.length, crypto.createHash('sha256').update(bytes).digest('hex'));
}

if (o.git) {
  let list;
  try {
    list = execFileSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
      { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    usage('--git needs git installed and ' + o.folder + ' to be inside a git repository' + (e.stderr ? ': ' + String(e.stderr).trim() : ''));
  }
  for (const rel of list.split('\0').filter(Boolean).sort()) readOne(rel);
} else {
  const walk = (relDir) => {
    let ents;
    try { ents = fs.readdirSync(path.join(root, relDir), { withFileTypes: true }); }
    catch { F.addFile(rep, relDir + '/', null, 'unreadable'); return; }
    ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of ents) {
      const rel = relDir ? relDir + '/' + d.name : d.name;
      if (d.isSymbolicLink()) F.addFile(rep, rel, null, 'link');
      else if (d.isDirectory()) walk(rel);
      else if (d.isFile()) readOne(rel);
    }
  };
  walk('');
}

F.finish(rep);
process.stdout.write(F.formatReport(rep, { showValues: o.showValues, title: o.folder + (o.git ? ' (files git would publish)' : '') }));
if (o.receipt) {
  fs.writeFileSync(o.receipt, F.receipt(rep).text);
  console.log('Receipt written to ' + o.receipt + '. It holds counts only.');
}
process.exit(rep.clean ? 0 : 1);

