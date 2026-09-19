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

const ctx = { crypto: globalThis.crypto, TextEncoder, console, BigInt, URL, fetch: undefined };
ctx.window = ctx;
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ["seal-core.js", "tacet-verify.js"]) vm.runInContext(fs.readFileSync(path.join(SITE, f), "utf8"), ctx, { filename: f });

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
    report(Math.abs(r.result.silence.silence_days - parseFloat(w.proof.silence.silence_days)) <= 0.005, "browser verifier: silence_days within 0.005 of the proof", String(r.result.silence.silence_days));
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

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
