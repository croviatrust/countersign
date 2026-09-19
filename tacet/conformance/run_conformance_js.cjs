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
for (const f of ["seal-core.js", "ots-verify.js", "tacet-verify.js"]) vm.runInContext(fs.readFileSync(path.join(SITE, f), "utf8"), ctx, { filename: f });

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

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
