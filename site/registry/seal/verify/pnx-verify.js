/* pnx-verify.js — browser verification of a PNX proof (TACET profile crovia.pnx.v1), PNX.md §6.
 *
 * Mirrors tacet/reference/python/tacet/egress.py (salted k-gram hashes, winnowing,
 * detection classes, run-sheet signature, inclusion / non-inclusion paths, verdict
 * recomputation) and pnx.py (verify_any: delivery inside an unmodified crovia.seal.v1).
 * Uses csc1(), ed25519Verify() and verifyChain() from seal-core.js and the sparse Merkle
 * map primitives exported by tacet-verify.js (window.tacetSmt).
 *
 * Accepts a bare proof ({profile, proof_version, sheet, assets, verdict}) or a sealed
 * bundle ({seal, query, proof}). With opts.assets = {label: Uint8Array} the fingerprints
 * of every asset are recomputed here; without them the paths are checked for the keys the
 * prover listed and the result carries the §6 warning: it proves non-inclusion of those
 * keys, not of any asset. No network is used.
 */
"use strict";
(function () {
  const enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: true });
  const PROFILE = "crovia.pnx.v1", PROOF_VERSION = "crovia.pnx.proof.v1";
  const K_GRAM = 32, WINDOW = 16;
  const D = s => enc.encode(s + "\n");
  const D_FP = D("CROVIA-PNX-FP-v1"), D_SHEET = D("CROVIA-PNX-SHEET-v1"), D_LEAF_VALUE = D("CROVIA-PNX-PRESENT-v1");
  const KNOWN_LAYERS = ["json-strings-v1"];
  const ABSENT = "absent", PARTIAL = "absent-partial", PRESENT_V = "present", UNDETECTABLE = "undetectable";

  function cat() { let n = 0; for (const p of arguments) n += p.length; const out = new Uint8Array(n); let o = 0; for (const p of arguments) { out.set(p, o); o += p.length; } return out; }
  async function sha256(b) { return new Uint8Array(await crypto.subtle.digest("SHA-256", b)); }
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  function unhex(h) { if (typeof h !== "string" || !/^[0-9a-f]*$/.test(h) || h.length % 2) throw new Error("invalid hex"); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; }
  function unprefixed(v) { if (typeof v !== "string" || !v.startsWith("sha256:") || v.length !== 71) throw new Error("expected sha256:<64 hex>"); return unhex(v.slice(7)); }
  function eq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
  function cmp(a, b) { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; return a.length - b.length; }
  function strip(obj, drop) { const o = {}; for (const k of Object.keys(obj)) if (!drop.includes(k)) o[k] = obj[k]; return o; }
  const bytesOf = obj => enc.encode(csc1(obj));
  let PRESENT = null;
  async function presentLeaf() { return PRESENT || (PRESENT = await sha256(D_LEAF_VALUE)); }

  /* ---- fingerprints (egress.py §3) ---- */
  async function kgramHashes(data, salt, k) {
    k = k || K_GRAM;
    if (salt.length !== 16) throw new Error("salt must be 16 bytes");
    const out = [];
    for (let i = 0; i + k <= data.length; i++) out.push(await sha256(cat(D_FP, salt, data.subarray(i, i + k))));
    return out;
  }
  // Minimum of every window of w consecutive hashes, rightmost on ties; returned as sorted hex.
  function winnow(hashes, w) {
    w = w || WINDOW;
    const n = hashes.length, out = new Set();
    if (!n) return [];
    if (n < w) { let m = hashes[0]; for (const h of hashes) if (cmp(h, m) < 0) m = h; return [hex(m)]; }
    for (let i = 0; i + w <= n; i++) { let m = hashes[i]; for (let j = i + 1; j < i + w; j++) if (cmp(hashes[j], m) <= 0) m = hashes[j]; out.add(hex(m)); }
    return Array.from(out).sort();
  }
  async function fingerprints(data, salt, k, w) { return winnow(await kgramHashes(data, salt, k), w); }
  // {detection, fingerprints}: guaranteed (winnowed) at >= k+w-1 bytes, partial (every k-gram) at >= k, else undetectable.
  function classForLen(n, k, w) { return n < k ? UNDETECTABLE : n >= k + w - 1 ? "guaranteed" : "partial"; }
  async function assetFingerprints(asset, salt, k, w) {
    k = k || K_GRAM; w = w || WINDOW;
    const detection = classForLen(asset.length, k, w);
    if (detection === UNDETECTABLE) return { detection, fingerprints: [] };
    const hashes = await kgramHashes(asset, salt, k);
    if (detection === "guaranteed") return { detection, fingerprints: winnow(hashes, w) };
    return { detection, fingerprints: Array.from(new Set(hashes.map(hex))).sort() };
  }
  // json-strings-v1: decoded string values of a JSON body, document order, at least minLen bytes.
  function jsonStrings(body, minLen) {
    minLen = minLen || K_GRAM;
    let doc;
    try { doc = JSON.parse(dec.decode(body)); } catch (_) { return []; }
    const out = [];
    (function walk(node) {
      if (typeof node === "string") { const b = enc.encode(node); if (b.length >= minLen) out.push(b); }
      else if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === "object") Object.values(node).forEach(walk);
    })(doc);
    return out;
  }
  async function epochLeafKey(runId) { return sha256(enc.encode("pnx/" + runId)); }

  /* ---- run sheet (egress.py verify_sheet) ---- */
  async function sheetErrors(sheet) {
    const errors = [];
    if (!sheet || typeof sheet !== "object") return ["malformed sheet: not an object"];
    if (sheet.profile !== PROFILE) errors.push("unknown profile '" + sheet.profile + "'");
    try { unprefixed(sheet.root); if (unhex(sheet.salt_hex).length !== 16) throw new Error("salt must be 16 bytes"); }
    catch (e) { errors.push("malformed sheet: " + e.message); return errors; }
    const p = sheet.params || {};
    if (p.hash !== "sha256" || p.threshold !== (p.k_gram || 0) + (p.window || 0) - 1) errors.push("inconsistent params");
    const norm = sheet.normalization === undefined ? [] : sheet.normalization;
    if (!Array.isArray(norm) || norm.some(n => !KNOWN_LAYERS.includes(n))) errors.push("unknown normalization layers " + JSON.stringify(norm));
    let ok = false;
    try { ok = await ed25519Verify(unhex((sheet.signature || {}).sig_hex || ""), cat(D_SHEET, bytesOf(strip(sheet, ["signature"]))), unhex(sheet.witness.pubkey.key_hex)); }
    catch (_) { ok = false; }
    if (!ok) errors.push("witness signature invalid");
    return errors;
  }

  const pnxQuery = proof => ({ profile: PROFILE, run_id: proof.sheet.run_id,
                               assets: (proof.assets || []).map(a => ({ label: a.label, asset_sha256: a.asset_sha256 })) });
  const isPnxProof = obj => !!(obj && typeof obj === "object" && obj.profile === PROFILE && obj.proof_version === PROOF_VERSION && obj.sheet && Array.isArray(obj.assets));
  const isPnxEnvelope = obj => !!(obj && typeof obj === "object" && obj.seal && obj.query && isPnxProof(obj.proof));

  /* ---- entry point (egress.py verify_pnx + pnx.py verify_any) ---- */
  async function verifyPnx(obj, steps, opts) {
    opts = opts || {};
    const errors = [], warnings = [];
    // Step labels read positively in the UI; `fail` is the error text (same wording as egress.py / pnx.py).
    const step = (ok, label, det, fatal, fail) => { steps.push({ ok, label, det: det || "" }); if (!ok) { errors.push(fail || label); if (fatal !== false) throw new Error(fail || label); } return ok; };
    const err = (ok, label, det, fail) => step(ok, label, det, false, fail);
    const note = (label, det) => steps.push({ ok: true, label, det: det || "", soft: true });
    const hdr = (label, det) => steps.push({ ok: true, label, det: det || "", hdr: true });
    const warn = (label, det) => { warnings.push(label); note(label, det); };

    const sealed = isPnxEnvelope(obj);
    const proof = sealed ? obj.proof : obj;
    if (!isPnxProof(proof)) throw new Error("not a " + PROFILE + " proof (" + PROOF_VERSION + ")");
    const sheet = proof.sheet;

    if (sealed) {
      const seal = obj.seal, query = obj.query;
      hdr("— outer seal", (seal && seal.seal_id) || "?");
      await verifyChain([seal], steps);
      hdr("— binding of query and proof to the seal");
      const qb = bytesOf(query), pb = bytesOf(proof);
      err(seal.subject.input_hash === "sha256:" + hex(await sha256(qb)), "subject.input_hash binds the query", qb.length + " canonical bytes",
          "seal.subject.input_hash does not bind the query");
      err(seal.subject.output_hash === "sha256:" + hex(await sha256(pb)), "subject.output_hash binds the proof", pb.length + " canonical bytes",
          "seal.subject.output_hash does not bind the proof");
      err(seal.subject.input_len === qb.length && seal.subject.output_len === pb.length, "subject lengths match canonical byte counts");
      err(csc1(query) === csc1(pnxQuery(proof)), "query describes this proof (profile, run_id, asset labels and hashes)", "",
          "query does not describe this proof");
      const ck = (seal.checks || {}).pnx || {};
      err(ck.verdict === proof.verdict && ck.run_root === sheet.root && ck.assets === (proof.assets || []).length, "checks.pnx repeats the proof's verdict, asset count and run root");
    }

    hdr("— run sheet (profile, parameters, witness signature)", sheet.run_id);
    const sheetErrs = await sheetErrors(sheet);
    for (const e of sheetErrs) err(false, e);
    if (sheetErrs.length) throw new Error(sheetErrs[0]);
    step(true, "sheet signed by witness " + sheet.witness.id, "CROVIA-PNX-SHEET-v1 over the CSC-1 encoding without `signature`");
    note(sheet.egress.bodies + " bodies, " + sheet.egress.bytes + " bytes witnessed; " + sheet.fingerprints + " fingerprints under the run root",
         sheet.egress.first_at + " → " + sheet.egress.last_at + "; normalisation: " + ((sheet.normalization || []).join(", ") || "none"));
    const root = unprefixed(sheet.root), salt = unhex(sheet.salt_hex);
    const k = sheet.params.k_gram, w = sheet.params.window;
    err(proof.profile === PROFILE && proof.proof_version === PROOF_VERSION, "proof is " + PROFILE + " / " + PROOF_VERSION);

    hdr("— assets against the run root", (proof.assets || []).length + " asset(s)");
    const assets = opts.assets || null;
    if (!assets) warn("assets not supplied: fingerprints taken from the proof, not recomputed",
                      "this proves non-inclusion of the listed keys, not of any asset (PNX §6 step 2); paste the asset to recompute");
    const smt = window.tacetSmt, E = await smt.emptyTable(), present = await presentLeaf();
    const computed = {};
    for (const a of proof.assets || []) {
      const label = String(a.label), listed = a.fingerprints || [];
      let klass = a.detection;
      if (assets) {
        if (!(label in assets)) { err(false, label + ": asset bytes not supplied"); continue; }
        const data = assets[label];
        if ("sha256:" + hex(await sha256(data)) !== a.asset_sha256) { err(false, label + ": supplied asset does not match asset_sha256 in the proof"); continue; }
        const r = await assetFingerprints(data, salt, k, w);
        if (r.detection !== a.detection) { err(false, label + ": detection class '" + a.detection + "' does not match recomputed '" + r.detection + "'"); continue; }
        if (listed.map(f => f.key).sort().join() !== r.fingerprints.join()) { err(false, label + ": fingerprint set does not match the asset"); continue; }
        klass = r.detection;
        step(true, label + ": asset bytes recomputed", data.length + " bytes, class " + klass + ", " + r.fingerprints.length + " fingerprint(s)");
      } else if (Number.isInteger(a.asset_len) && classForLen(a.asset_len, k, w) !== klass) {
        // The stated length alone fixes the class: an understated class is visible without the bytes.
        err(false, label + ": detection class '" + klass + "' does not match asset_len"); continue;
      }
      let hits = 0;
      for (const f of listed) {
        let key, full;
        try { key = unhex(f.key); full = smt.fullPath(f.path, E); } catch (e) { err(false, label + ": malformed path (" + e.message + ")"); continue; }
        if (f.present) {
          if (!eq(await smt.rootFromPath(key, await smt.leafHash(key, present), full), root)) err(false, label + ": inclusion path invalid for " + f.key.slice(0, 16));
          hits++;
        } else if (!eq(await smt.rootFromPath(key, E[0], full), root)) err(false, label + ": non-inclusion path invalid for " + f.key.slice(0, 16));
      }
      const v = klass === UNDETECTABLE ? UNDETECTABLE : hits ? PRESENT_V : klass === "guaranteed" ? ABSENT : PARTIAL;
      computed[label] = v;
      const det = v === UNDETECTABLE ? "shorter than " + k + " bytes, cannot be fingerprinted; not counted as clean"
                : v === PARTIAL ? "shorter than the " + (k + w - 1) + "-byte guarantee; exact k-grams absent only"
                : v === PRESENT_V ? hits + " of " + listed.length + " fingerprint(s) present in the witnessed egress"
                : listed.length + " fingerprint(s) proven absent (depth-256 sparse Merkle map)";
      if (v !== a.verdict) err(false, label + ": stated verdict '" + a.verdict + "' differs from recomputed '" + v + "'", det, label + ": stated verdict '" + a.verdict + "', computed '" + v + "'");
      else step(true, label + ": " + v, det);
      if (v === UNDETECTABLE || v === PARTIAL) warn(label + ": " + det);
    }
    const vals = Object.values(computed);
    const overall = vals.some(v => v === PRESENT_V) ? PRESENT_V : vals.length && vals.every(v => v === ABSENT) ? ABSENT : "mixed";
    err(overall === proof.verdict, "overall verdict '" + proof.verdict + "' matches recomputation", "",
        "overall verdict '" + proof.verdict + "' does not match computed '" + overall + "'");

    if (errors.length) throw new Error(errors[0]);
    return { verdict: overall, assets: computed, sealed, hashOnly: !assets, warnings, run: sheet.run_id,
             witness: sheet.witness.id, bodies: sheet.egress.bodies, bytes: sheet.egress.bytes };
  }

  window.verifyPnx = verifyPnx;
  window.isPnxProof = isPnxProof;
  window.isPnxEnvelope = isPnxEnvelope;
  window.tacetPnx = { PROFILE, PROOF_VERSION, K_GRAM, WINDOW, kgramHashes, winnow, fingerprints, assetFingerprints, jsonStrings,
                      epochLeafKey, presentLeaf, sheetErrors, pnxQuery };
})();
