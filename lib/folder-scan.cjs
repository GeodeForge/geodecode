
(function(){
  "use strict";

  var DEFAULTS = {
    sniffBytes: 8000,
    maxBytes: 50 * 1024 * 1024,
    skipDirs: [".git", "node_modules"]
  };

  function opt(o, k){ return (o && o[k] !== undefined && o[k] !== null) ? o[k] : DEFAULTS[k]; }

  function normPath(p){ return String(p || "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, ""); }

  function skippedDirOf(path, o){
    var dirs = opt(o, "skipDirs"), parts = normPath(path).split("/"), i;
    parts.pop();
    for(i = 0; i < parts.length; i++){ if(dirs.indexOf(parts[i]) >= 0) return parts[i]; }
    return "";
  }

  function isBinary(bytes, o){
    var n = Math.min(bytes.length, opt(o, "sniffBytes")), i;
    for(i = 0; i < n; i++){ if(bytes[i] === 0) return true; }
    return false;
  }

  function decode(bytes){
    var t = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return t.charCodeAt(0) === 0xFEFF ? t.slice(1) : t;
  }

  function maskValue(v){
    v = String(v);
    if(v.length <= 8) return v.charAt(0) + "… (" + v.length + " characters)";
    return v.slice(0, 4) + "… (" + v.length + " characters)";
  }

  function newReport(engine, o){
    return {
      engine: engine,
      options: { sniffBytes: opt(o, "sniffBytes"), maxBytes: opt(o, "maxBytes"), skipDirs: opt(o, "skipDirs").slice() },
      filesSeen: 0, filesRead: 0,
      notRead: { binary: [], tooLarge: [], skippedDir: {}, unreadable: [], links: [] },
      findings: [], longLines: [], digests: []
    };
  }

  function addFile(rep, path, bytes, reason, size, digest){
    var p = normPath(path), sd = skippedDirOf(p, rep.options), E = rep.engine, text, hits, i, long;
    rep.filesSeen++;
    if(sd){ rep.notRead.skippedDir[sd] = (rep.notRead.skippedDir[sd] || 0) + 1; return; }
    if(reason === "unreadable"){ rep.notRead.unreadable.push(p); return; }
    if(reason === "link"){ rep.notRead.links.push(p); return; }
    if(reason === "tooLarge" || (bytes && bytes.length > rep.options.maxBytes)){
      rep.notRead.tooLarge.push({ path: p, bytes: bytes ? bytes.length : (size || 0) }); return;
    }
    if(!bytes){ rep.notRead.unreadable.push(p); return; }
    if(isBinary(bytes, rep.options)){ rep.notRead.binary.push(p); return; }
    text = decode(bytes);
    rep.filesRead++;
    if(digest) rep.digests.push(E.sha256hex(p) + " " + digest); else rep.noDigest = true;
    hits = E.scan(text);
    for(i = 0; i < hits.length; i++){
      rep.findings.push({ path: p, line: hits[i].line, label: hits[i].label, category: hits[i].category, tier: hits[i].tier, value: hits[i].value });
    }
    long = E.unscannedLines(text);
    for(i = 0; i < long.length; i++) rep.longLines.push({ path: p, line: long[i].line, length: long[i].length });
  }

  function byPathLine(a, b){ return a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line; }

  function finish(rep){
    rep.findings.sort(byPathLine);
    rep.longLines.sort(byPathLine);
    rep.notRead.binary.sort(); rep.notRead.unreadable.sort(); rep.notRead.links.sort();
    rep.notRead.tooLarge.sort(function(a, b){ return a.path < b.path ? -1 : 1; });
    var files = {}, i;
    for(i = 0; i < rep.findings.length; i++) files[rep.findings[i].path] = 1;
    rep.filesWithFindings = Object.keys(files).length;
    rep.clean = rep.findings.length === 0;
    return rep;
  }

  function countSkippedDirs(rep){
    var n = 0, k; for(k in rep.notRead.skippedDir) n += rep.notRead.skippedDir[k]; return n;
  }

  function formatReport(rep, o){
    var show = o && o.showValues, out = [], i, f, k, nr = rep.notRead, skipped = countSkippedDirs(rep);
    out.push("GeodeCode folder scan" + (o && o.title ? " of " + o.title : ""));
    out.push("Files read: " + rep.filesRead + " of " + rep.filesSeen + " found.");
    if(rep.clean) out.push("Nothing found. The rules flag nothing in the files that were read.");
    else out.push("Found " + rep.findings.length + " thing" + (rep.findings.length === 1 ? "" : "s") + " in " + rep.filesWithFindings + " file" + (rep.filesWithFindings === 1 ? "" : "s") + ":");
    for(i = 0; i < rep.findings.length; i++){
      f = rep.findings[i];
      out.push("  " + f.path + ", line " + f.line + ": " + f.label + "  " + (show ? f.value : maskValue(f.value)));
    }
    if(rep.longLines.length){
      out.push("Lines too long for the pattern rules (" + rep.longLines.length + "). Check these by hand:");
      for(i = 0; i < rep.longLines.length; i++) out.push("  " + rep.longLines[i].path + ", line " + rep.longLines[i].line);
    }
    if(nr.binary.length) out.push("Not read, binary (" + nr.binary.length + "): " + nr.binary.slice(0, 20).join(", ") + (nr.binary.length > 20 ? ", and " + (nr.binary.length - 20) + " more" : ""));
    for(i = 0; i < nr.tooLarge.length; i++) out.push("Not read, larger than the size limit: " + nr.tooLarge[i].path + " (" + nr.tooLarge[i].bytes + " bytes)");
    for(i = 0; i < nr.unreadable.length; i++) out.push("Not read, could not open: " + nr.unreadable[i]);
    for(i = 0; i < nr.links.length; i++) out.push("Not read, a link to somewhere else (not followed): " + nr.links[i]);
    if(skipped){
      var parts = []; for(k in nr.skippedDir) parts.push(k + " " + nr.skippedDir[k]);
      out.push("Not read, inside skipped folders (" + skipped + " file" + (skipped === 1 ? "" : "s") + ": " + parts.join(", ") + "). Include them if you will share them.");
    }
    return out.join("\n") + "\n";
  }

  function receipt(rep){
    var E = rep.engine, counts = {}, sorted = {}, i, k;
    for(i = 0; i < rep.findings.length; i++){ k = rep.findings[i].category; counts[k] = (counts[k] || 0) + 1; }
    Object.keys(counts).sort().forEach(function(c){ sorted[c] = counts[c]; });
    var d = rep.digests.slice().sort();
    var r = {
      receipt: "GeodeCode folder scan v1",
      tool: { name: E.APP.name, version: E.APP.version },
      ruleset: { name: E.RULESET.name, version: E.RULESET.version, digest: "sha256:" + E.sha256hex(E.rulesetDescriptor()) },
      tree: { files_read: rep.filesRead, sha256: rep.noDigest ? "not available: this browser cannot hash files" : "sha256:" + E.sha256hex(d.join("\n")) },
      not_read: { binary: rep.notRead.binary.length, too_large: rep.notRead.tooLarge.length, unreadable: rep.notRead.unreadable.length, links: rep.notRead.links.length, in_skipped_folders: countSkippedDirs(rep) },
      found: { total: rep.findings.length, by_kind: sorted },
      lines_too_long_for_pattern_rules: rep.longLines.length,
      proves: "which files were read and what the rules found in them, without saying where; not when, and not that anything is safe"
    };
    return { receipt: r, text: JSON.stringify(r, null, 2) + "\n" };
  }

  var API = { DEFAULTS: DEFAULTS, normPath: normPath, skippedDirOf: skippedDirOf, isBinary: isBinary, decode: decode,
    maskValue: maskValue, newReport: newReport, addFile: addFile, finish: finish, formatReport: formatReport, receipt: receipt };
  globalThis.GEODECODE_FOLDER = API;
  if(typeof module !== "undefined" && module.exports){ module.exports = API; }
})();

