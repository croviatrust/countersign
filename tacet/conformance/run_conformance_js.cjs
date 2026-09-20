#!/usr/bin/env node
/* Run the in-browser TACET verifier (site/registry/seal/verify/{seal-core,tacet-verify}.js)
 * against the v1 conformance vectors, in Node (>= 20, WebCrypto Ed25519).
 *
 *   node tacet/conformance/run_conformance_js.cjs
 *
 * The browser verifier is the second implementation of SPEC §8.5. It must accept
 * wrapped_001 at the claimed strength and reject every case in wrapped_002 while
 * still finding the outer Seal signature valid.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..", "..");
const VEC = path.join(__dirname, "vectors", "v1");
const SITE = path.join(ROOT, "site", "registry", "seal", "verify");

const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, console, BigInt, URL, Number, fetch: undefined };
ctx.window = ctx;
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ["seal-core.js", "ots-verify.js", "tacet-verify.js", "pnx-verify.js"]) vm.runInContext(fs.readFileSync(path.join(SITE, f), "utf8"), ctx, { filename: f });

const load = name => JSON.parse(fs.readFileSync(path.join(VEC, name), "utf8"));
let passed = 0, failed = 0;
function report(ok, label, detail) {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label}${detail && !ok ? " — " + detail : ""}`);
  ok ? passed++ : failed++;
}
async function run(bundle) {
  const steps = [];
  try {
    const r = await ctx.verifyTacetEnvelope({ seal: bundle.seal, query: bundle.query, proof: bundle.proof }, steps, {});
    return { ok: true, result: r, steps };
  } catch (e) {
    return { ok: false, error: e.message, steps };
  }
}
const sealValid = steps => steps.some(s => s.label === "Ed25519 issuer signature" && s.ok);
const failing = steps => steps.filter(s => !s.ok).map(s => s.label).join("; ");

(async () => {
  const w = load("wrapped_001_level3.json");
  let r = await run(w);
  report(r.ok && r.result.verified === w.proof.strength, "browser verifier: wrapped_001 accepted at claimed strength", r.error || (r.ok ? `verified ${r.result.verified}` : ""));
  if (r.ok) {
    report(r.result.silence.silence_seconds === w.proof.silence.silence_seconds, "browser verifier: silence_seconds recomputed", String(r.result.silence.silence_seconds));
    report(r.result.silence.silence_days === w.proof.silence.silence_days, "browser verifier: silence_days byte-identical to the proof (SPEC §9 truncation)", String(r.result.silence.silence_days));
  }

  for (const [name, vec] of Object.entries(load("wrapped_002_invalid.json"))) {
    r = await run(vec);
    report(!r.ok && sealValid(r.steps), `browser verifier: wrapped invalid/${name} rejected with Seal valid`, r.ok ? "accepted" : failing(r.steps));
  }

  // Tampering the outer seal must fail at the seal, before anything else.
  const t = JSON.parse(JSON.stringify(w));
  t.seal.signature.sig_hex = (t.seal.signature.sig_hex[0] === "0" ? "1" : "0") + t.seal.signature.sig_hex.slice(1);
  r = await run(t);
  report(!r.ok && !sealValid(r.steps), "browser verifier: tampered outer signature rejected", r.error || "");

  // SPEC §8.6 — OpenTimestamps anchors of live sheets, parsed in JS and matched to the recorded block header.
  const unhex = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
  const ov = load("ots_001_live_anchors.json");
  const byName = Object.fromEntries(ov.cases.map(c => [c.name, c]));
  for (const c of ov.cases) {
    const data = unhex(c.ots_hex), sh = unhex(c.sheet_hash.slice(7));
    const roots = await ctx.tacetOts.expectedMerkleRoots(data);
    report((roots[c.block_height] || []).includes(c.merkle_root), `browser ots/${c.name}: attestation at block ${c.block_height} names the recorded merkle root`, JSON.stringify(roots));
    const res = await ctx.tacetOts.verifySheetAnchor(data, sh, c.block_height, async h => (h === c.block_height ? c.merkle_root : null));
    report(res.verdict === true, `browser ots/${c.name}: anchor verifies against the block header`, res.detail);
  }
  for (const n of ov.negative) {
    const c = byName[n.case];
    let data = unhex(c.ots_hex);
    if (n.truncate_bytes) data = data.subarray(0, data.length - n.truncate_bytes);
    const sh = unhex((n.sheet_hash || c.sheet_hash).slice(7));
    const src = ("header_source" in n && n.header_source === null) ? null : (async h => (h === c.block_height ? c.merkle_root : null));
    const res = await ctx.tacetOts.verifySheetAnchor(data, sh, n.block_height ?? c.block_height, src);
    report(res.verdict === n.expect, `browser ots/negative/${n.name}: verdict ${n.expect}`, res.detail);
  }

  await pnxCases();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });

/* PNX profile (PNX.md §9): pnx-verify.js is the second implementation of egress.py / pnx.py. */
async function pnxCases() {
  const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const cat = (...ps) => { const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of ps) { out.set(p, o); o += p.length; } return out; };
  const sha256 = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  const stream = async (label, n) => { const parts = []; for (let i = 0, got = 0; got < n; i++) { const d = await sha256(new TextEncoder().encode(`tacet-pnx-fixture:${label}:${i}`)); parts.push(d); got += d.length; } return cat(...parts).subarray(0, n); };
  const assetsOf = vec => Object.fromEntries(Object.entries(vec.assets_hex).map(([k, v]) => [k, unhex(v)]));
  const P = ctx.tacetPnx;
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  async function run(obj, assets) {
    const steps = [];
    try { return { ok: true, result: await ctx.verifyPnx(obj, steps, assets ? { assets } : {}), steps }; }
    catch (e) { return { ok: false, error: e.message, steps }; }
  }
  const sealSigValid = steps => steps.some(s => s.label === "Ed25519 issuer signature" && s.ok);
  const failing = steps => steps.filter(s => !s.ok).map(s => s.label).join("; ");

  let v = load("pnx_001_fingerprints.json");
  const salt = unhex(v.salt_hex);
  report(v.params.k_gram === P.K_GRAM && v.params.window === P.WINDOW && v.params.threshold === P.K_GRAM + P.WINDOW - 1, "browser pnx/001: parameters of crovia.pnx.v1");
  report(hex(await P.presentLeaf()) === v.present_leaf_value, "browser pnx/001: present leaf value is SHA-256 of the domain string");
  report(hex(await stream(v.stream.example.label, v.stream.example.n)) === v.stream.example.hex, "browser pnx/001: fixture byte stream reproduces");
  report(same((await P.kgramHashes(unhex(v.kgram_hashes.data_hex), salt)).map(hex), v.kgram_hashes.hashes), "browser pnx/001: salted k-gram hashes");
  report(same(await P.fingerprints(unhex(v.winnowing.data_hex), salt), v.winnowing.fingerprints), "browser pnx/001: winnowed fingerprints");
  report(same(await P.fingerprints(unhex(v.winnowing_short.data_hex), salt), v.winnowing_short.fingerprints), "browser pnx/001: body shorter than one window selects the single minimum");
  for (const c of v.detection_classes) {
    const r = await P.assetFingerprints(unhex(c.asset_hex), salt);
    report(r.detection === c.detection && same(r.fingerprints, c.fingerprints), `browser pnx/001: ${c.asset_len}-byte asset is ${c.detection}`, r.detection);
  }
  const g = v.guarantee, secret = unhex(g.secret_hex), noise = unhex(g.noise_hex);
  const sfp = (await P.assetFingerprints(secret, salt)).fingerprints;
  report(same(sfp, g.secret_fingerprints), "browser pnx/001: secret fingerprints");
  const missed = [];
  for (const o of g.offsets) { const fps = await P.fingerprints(cat(noise.subarray(0, o), secret, noise.subarray(o)), salt); if (!fps.some(f => sfp.includes(f))) missed.push(o); }
  report(missed.length === 0, `browser pnx/001: winnowing guarantee holds at all ${g.offsets.length} offsets`, `missed at offsets ${missed}`);
  report(same(P.jsonStrings(unhex(v.json_strings.body_hex)).map(hex), v.json_strings.derived_hex), "browser pnx/001: json-strings-v1 derived bodies");
  report(P.jsonStrings(unhex(v.json_strings.non_json_body_hex)).length === 0, "browser pnx/001: non-JSON body yields no derived bodies");
  report(hex(await P.epochLeafKey(v.epoch_leaf_key.run_id)) === v.epoch_leaf_key.key, "browser pnx/001: epoch leaf key pnx/<run_id>");

  v = load("pnx_002_proofs.json");
  report((await P.sheetErrors(v.sheet)).length === 0, "browser pnx/002: run sheet accepted (profile, params, normalisation, witness signature)", (await P.sheetErrors(v.sheet)).join("; "));
  for (const [name, vec] of Object.entries(v.proofs)) {
    let r = await run(vec.proof, assetsOf(vec));
    report(r.ok, `browser pnx/002 ${name}: verifies with asset bytes`, r.error || "");
    if (r.ok) report(r.result.verdict === vec.expect.verdict && same(Object.entries(r.result.assets).sort(), Object.entries(vec.expect.assets).sort()), `browser pnx/002 ${name}: verdicts ${vec.expect.verdict}`, JSON.stringify(r.result.assets));
    r = await run(vec.proof);
    report(r.ok === v.hash_only.expect.ok && r.ok && r.result.hashOnly && r.result.warnings.some(w => w.includes(v.hash_only.expect.warning_contains)), `browser pnx/002 ${name}: hash-only mode accepts and warns`, r.error || "");
  }

  for (const [name, vec] of Object.entries(load("pnx_003_invalid.json"))) {
    let r = await run(vec.proof, assetsOf(vec));
    report(!r.ok && (r.error.includes(vec.expect_error_contains) || failing(r.steps).includes(vec.expect_error_contains)), `browser pnx/003 invalid/${name} rejected`, r.ok ? "accepted" : r.error + " | " + failing(r.steps));
    r = await run(vec.proof);
    report(r.ok === vec.hash_only_ok, `browser pnx/003 invalid/${name}: hash-only verdict ${vec.hash_only_ok ? "accepts" : "rejects"}`, r.error || "accepted");
  }

  v = load("pnx_004_sealed.json");
  for (const [name, vec] of Object.entries({ clean: v.clean, exposure: v.exposure, ...v.invalid })) {
    const r = await run({ seal: vec.seal, query: vec.query, proof: vec.proof }, assetsOf(vec));
    if (vec.expect.ok) report(r.ok && r.result.sealed && r.result.verdict === vec.expect.verdict, `browser pnx/004 ${name}: Seal and PNX proof verify, verdict ${vec.expect.verdict}`, r.error || "");
    else report(!r.ok && sealSigValid(r.steps) === vec.expect.seal_signature_ok && r.error.includes(vec.expect_error_contains),
                `browser pnx/004 invalid/${name} rejected (seal signature ${vec.expect.seal_signature_ok ? "valid" : "invalid"})`, r.ok ? "accepted" : r.error);
  }
  report(!ctx.isTacetEnvelope({ seal: v.clean.seal, query: v.clean.query, proof: v.clean.proof }) && ctx.isPnxEnvelope({ seal: v.clean.seal, query: v.clean.query, proof: v.clean.proof }),
         "browser: a sealed PNX bundle is dispatched to the PNX verifier, not the silence verifier");
}
