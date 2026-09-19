/* seal-core.js — crovia.seal.v1 verification primitives shared by the in-browser verifier
 * and tacet-verify.js: CSC-1 canonicalization, WebCrypto Ed25519 (noble fallback),
 * fail-closed seal and chain verification per SPEC v0.5 / draft-crovia-seal-01.
 * Plain script: defines globals csc1, canonString, hexToBytes, sha256hex, ed25519Verify,
 * payloadOf, verifySeal, verifyChain, KNOWN, ID_RE. */
"use strict";
/* ------------------------------------------------------------------ *
 *  CSC-1 canonicalization (strict subset of RFC 8785; floats forbidden)
 * ------------------------------------------------------------------ */
function csc1(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isInteger(value)) throw new Error("NonCanonicalNumber: floats are forbidden in signed payloads");
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) throw new Error("NonCanonicalNumber: outside ±(2^53-1)");
    if (Object.is(value, -0)) throw new Error("NonCanonicalNumber: -0");
    return String(value);
  }
  if (t === "string") return canonString(value);
  if (Array.isArray(value)) return "[" + value.map(csc1).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).sort(); // default sort = UTF-16 code units
    return "{" + keys.map(k => canonString(k) + ":" + csc1(value[k])).join(",") + "}";
  }
  throw new Error("unsupported type " + t);
}
function canonString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 8) out += "\\b";
    else if (c === 12) out += "\\f";
    else if (c === 10) out += "\\n";
    else if (c === 13) out += "\\r";
    else if (c === 9) out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/* ------------------------------------------------------------------ *
 *  Crypto helpers: WebCrypto Ed25519, noble-ed25519 fallback
 * ------------------------------------------------------------------ */
const enc = new TextEncoder();
function hexToBytes(hex) {
  if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
async function sha256hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
let _noble = null;
async function ed25519Verify(sigBytes, msgBytes, pubBytes) {
  try {
    const key = await crypto.subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, sigBytes, msgBytes);
  } catch (_) {
    if (!_noble) _noble = await import("./noble-ed25519.js");
    return await _noble.verifyAsync(sigBytes, msgBytes, pubBytes);
  }
}

/* ------------------------------------------------------------------ *
 *  Seal verification (fail-closed, per SPEC v0.5 / draft-crovia-seal-01)
 * ------------------------------------------------------------------ */
const KNOWN = ["seal_version","seal_id","issuer","subject","generator","timestamp","chain","checks","anchor","signature","witnesses"];
const ID_RE = /^cs_[0-9]{4}_[A-Z2-7]{26}$/;

async function payloadOf(seal) {
  const stripped = {};
  for (const k of Object.keys(seal)) if (k !== "signature" && k !== "witnesses") stripped[k] = seal[k];
  const canon = csc1(stripped);
  const canonBytes = enc.encode(canon);
  const payload = new Uint8Array(15 + canonBytes.length);
  payload.set(enc.encode("CROVIA-SEAL-v1"), 0);
  payload[14] = 0x0A;
  payload.set(canonBytes, 15);
  return payload;
}

async function verifySeal(seal, steps) {
  const step = (ok, label, det) => { steps.push({ ok, label, det }); if (!ok) throw new Error(label); };

  const unknown = Object.keys(seal).filter(k => !KNOWN.includes(k));
  step(unknown.length === 0, "no unknown top-level fields (fail-closed)", unknown.join(", "));
  for (const req of ["seal_version","seal_id","issuer","subject","generator","timestamp","chain","signature"])
    step(req in seal, "required field: " + req, "");
  step(seal.seal_version === "crovia.seal.v1", "seal_version is crovia.seal.v1", String(seal.seal_version));
  step(ID_RE.test(seal.seal_id || ""), "seal_id well-formed (cs_YYYY_ + 26×base32)", seal.seal_id || "");

  const sig = seal.signature || {};
  step(sig.alg === "ed25519", "signature.alg is ed25519", String(sig.alg));
  step(sig.canon === "csc-1", "signature.canon is csc-1", String(sig.canon));
  step(sig.domain === "CROVIA-SEAL-v1", "signature.domain is CROVIA-SEAL-v1", String(sig.domain));

  let payload;
  try { payload = await payloadOf(seal); } catch (e) { step(false, "CSC-1 canonicalization", e.message); }
  step(true, "CSC-1 canonical payload built", payload.length + " bytes, domain-prefixed");
  const phash = await sha256hex(payload);
  step(true, "payload SHA-256 (chains to the next seal)", "sha256:" + phash.slice(0, 24) + "…");

  const pub = hexToBytes((((seal.issuer || {}).pubkey) || {}).key_hex || "");
  step(pub.length === 32, "issuer pubkey is 32 bytes", "");
  const sigBytes = hexToBytes(sig.sig_hex || "");
  step(sigBytes.length === 64, "signature is 64 bytes", "");
  const okSig = await ed25519Verify(sigBytes, payload, pub);
  step(okSig, "Ed25519 issuer signature", okSig ? "valid over P(S)" : "INVALID");

  if (Array.isArray(seal.witnesses)) {
    for (let i = 0; i < seal.witnesses.length; i++) {
      const w = seal.witnesses[i];
      const okW = await ed25519Verify(hexToBytes(w.sig_hex || ""), payload, hexToBytes(((w.pubkey||{}).key_hex) || ""));
      step(okW, "witness " + (i + 1) + " signature (" + (w.id || "unnamed") + ")", okW ? "valid" : "INVALID");
    }
  }
  return phash;
}

async function verifyChain(seals, steps) {
  let expectedSeq = null, expectedPrev = null;
  for (let i = 0; i < seals.length; i++) {
    const s = seals[i];
    steps.push({ ok: true, label: "— seal " + (i + 1) + "/" + seals.length + ": " + (s.seal_id || "?"), det: "sequence " + (s.chain||{}).sequence, hdr: true });
    const phash = await verifySeal(s, steps);
    const seq = (s.chain || {}).sequence;
    const prev = (s.chain || {}).prev_seal_hash ?? null;
    if (i === 0) {
      // First seal: a genesis must have prev=null; a fragment start is accepted as-is.
      if (seq === 0) {
        const okGen = prev === null;
        steps.push({ ok: okGen, label: "genesis seal has prev_seal_hash null", det: okGen ? "" : String(prev) });
        if (!okGen) throw new Error("genesis with non-null prev_seal_hash");
      } else {
        steps.push({ ok: true, label: "chain fragment starts at sequence " + seq, det: "prev link not checkable without the preceding seal" });
      }
    } else {
      const okSeq = seq === expectedSeq;
      steps.push({ ok: okSeq, label: "chain sequence contiguous", det: okSeq ? "" : "expected " + expectedSeq + ", found " + seq });
      if (!okSeq) throw new Error("chain gap or fork");
      const okLink = prev === expectedPrev;
      steps.push({ ok: okLink, label: "chain link (prev_seal_hash)", det: okLink ? "matches previous payload hash" : "MISMATCH — fork or tamper" });
      if (!okLink) throw new Error("chain link broken");
    }
    expectedPrev = "sha256:" + phash;
    expectedSeq = seq + 1;
  }
}
