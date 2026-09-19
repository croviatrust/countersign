/* ots-verify.js — OpenTimestamps proof verification in the browser, TACET SPEC §8.6.
 *
 * Mirrors tacet/reference/python/tacet/ots.py. Parses a detached .ots proof,
 * replays its operation tree from the file digest and collects every
 * BitcoinBlockHeaderAttestation leaf: the 32-byte message at that leaf is the
 * merkle root of the attested block (internal byte order; explorers show it
 * byte-reversed). No Bitcoin node is needed: the caller passes a header source
 * `height -> Promise<merkle_root_hex | null>` (a public explorer, or your own
 * node behind a proxy). A null header means "unchecked", never "failed".
 *
 * Exposes window.tacetOts = { parse, expectedMerkleRoots, verifySheetAnchor, explorerMerkleRoot }.
 */
"use strict";
(function () {
  const MAGIC = new Uint8Array([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
  const OP = { SHA1: 0x02, RIPEMD160: 0x03, SHA256: 0x08, KECCAK256: 0x67, APPEND: 0xf0, PREPEND: 0xf1, REVERSE: 0xf2, HEXLIFY: 0xf3 };
  const ATT_PENDING = "83dfe30d2ef90c8e", ATT_BITCOIN = "0588960d73d71901";
  const MAX_RESULT = 4096, MAX_ATT = 8192;
  const EXPLORERS = ["https://mempool.space/api", "https://blockstream.info/api"];

  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const enc = new TextEncoder();
  function cat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
  function eq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
  async function digest(alg, b) { return new Uint8Array(await crypto.subtle.digest(alg, b)); }

  class OTSError extends Error {}

  class Reader {
    constructor(d) { this.d = d; this.i = 0; }
    bytes(n) { if (this.i + n > this.d.length) throw new OTSError("truncated proof"); const b = this.d.subarray(this.i, this.i + n); this.i += n; return b; }
    byte() { return this.bytes(1)[0]; }
    varuint() { let v = 0n, shift = 0n; for (;;) { const b = this.byte(); v |= BigInt(b & 0x7f) << shift; if (!(b & 0x80)) { if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new OTSError("varuint too large"); return Number(v); } shift += 7n; if (shift > 63n) throw new OTSError("varuint too large"); } }
    varbytes(max) { const n = this.varuint(); if (n > max) throw new OTSError("varbytes too long (" + n + ")"); return this.bytes(n); }
    atEnd() { return this.i >= this.d.length; }
  }

  function digestLen(op) { return { [OP.SHA1]: 20, [OP.RIPEMD160]: 20, [OP.SHA256]: 32, [OP.KECCAK256]: 32 }[op]; }

  async function apply(op, arg, msg) {
    switch (op) {
      case OP.SHA256: return digest("SHA-256", msg);
      case OP.SHA1: return digest("SHA-1", msg);
      case OP.RIPEMD160: throw new OTSError("ripemd160 is not available in this browser");
      case OP.KECCAK256: throw new OTSError("keccak256 operations are not supported");
      case OP.APPEND: return cat(msg, arg);
      case OP.PREPEND: return cat(arg, msg);
      case OP.REVERSE: return Uint8Array.from(msg).reverse();
      case OP.HEXLIFY: return enc.encode(hex(msg));
      default: throw new OTSError("unknown op 0x" + op.toString(16));
    }
  }

  function readOp(r, tag) {
    if (tag === OP.APPEND || tag === OP.PREPEND) return [tag, r.varbytes(MAX_RESULT)];
    if ([OP.SHA1, OP.RIPEMD160, OP.SHA256, OP.KECCAK256, OP.REVERSE, OP.HEXLIFY].includes(tag)) return [tag, null];
    throw new OTSError("unknown op tag 0x" + tag.toString(16));
  }

  function readAttestation(r, msg, out) {
    const tag = hex(r.bytes(8));
    const payload = new Reader(r.varbytes(MAX_ATT));
    if (tag === ATT_BITCOIN) {
      const height = payload.varuint();
      if (msg.length !== 32) throw new OTSError("Bitcoin attestation over a message that is not 32 bytes");
      out.bitcoin.push({ height, merkleRoot: msg, merkleRootHex: hex(Uint8Array.from(msg).reverse()) });
    } else if (tag === ATT_PENDING) {
      out.pending.push(new TextDecoder().decode(payload.varbytes(1000)));
    }
  }

  async function readTimestamp(r, msg, out, depth) {
    if (depth > 256) throw new OTSError("proof nesting too deep");
    const tagOrAtt = async tag => {
      if (tag === 0x00) { readAttestation(r, msg, out); return; }
      const [op, arg] = readOp(r, tag);
      const res = await apply(op, arg, msg);
      if (res.length > MAX_RESULT) throw new OTSError("operation result too long");
      await readTimestamp(r, res, out, depth + 1);
    };
    let tag = r.byte();
    while (tag === 0xff) { await tagOrAtt(r.byte()); tag = r.byte(); }
    await tagOrAtt(tag);
  }

  async function parse(data) {
    const r = new Reader(data instanceof Uint8Array ? data : new Uint8Array(data));
    if (!eq(r.bytes(MAGIC.length), MAGIC)) throw new OTSError("not an OpenTimestamps proof (bad magic)");
    if (r.varuint() !== 1) throw new OTSError("unsupported OpenTimestamps version");
    const op = r.byte();
    if (digestLen(op) === undefined) throw new OTSError("file hash op must be a cryptographic hash");
    const fileDigest = r.bytes(digestLen(op));
    const out = { fileHashOp: op, fileDigest, bitcoin: [], pending: [] };
    await readTimestamp(r, fileDigest, out, 0);
    if (!r.atEnd()) throw new OTSError("trailing bytes after proof");
    return out;
  }

  async function expectedMerkleRoots(data) {
    const p = await parse(data); const out = {};
    for (const a of p.bitcoin) (out[a.height] = out[a.height] || []).push(a.merkleRootHex);
    return out;
  }

  /* Returns {verdict: true|false|null, detail}. */
  async function verifySheetAnchor(otsBytes, sheetHashBytes, blockHeight, headerSource) {
    let p;
    try { p = await parse(otsBytes); } catch (e) { return { verdict: false, detail: "malformed OTS proof: " + e.message }; }
    const want = await digest("SHA-256", sheetHashBytes);
    if (p.fileHashOp !== OP.SHA256 || !eq(p.fileDigest, want)) return { verdict: false, detail: "OTS proof does not stamp SHA-256(sheet_hash bytes)" };
    const at = p.bitcoin.filter(a => a.height === Number(blockHeight));
    if (!at.length) { const hs = [...new Set(p.bitcoin.map(a => a.height))].sort(); return { verdict: false, detail: "no Bitcoin attestation at block " + blockHeight + " (proof has " + (hs.length ? hs.join(",") : "none") + ")" }; }
    const expected = [...new Set(at.map(a => a.merkleRootHex))].sort();
    if (!headerSource) return { verdict: null, detail: "block " + blockHeight + " merkle root should be " + expected[0] + " (unchecked: no header source)" };
    let actual = null, reason = "header source returned nothing";
    try { actual = await headerSource(Number(blockHeight)); } catch (e) { reason = e.message; }
    if (!actual) return { verdict: null, detail: "block " + blockHeight + " merkle root should be " + expected[0] + " (unchecked: " + reason + ")" };
    actual = String(actual).toLowerCase();
    if (expected.includes(actual)) return { verdict: true, detail: "block " + blockHeight + " merkle root " + actual + " matches the proof", merkleRoot: actual };
    return { verdict: false, detail: "block " + blockHeight + " merkle root " + actual + " differs from the proof's " + expected.join(",") };
  }

  /* Header source backed by public explorers (CORS-enabled). Replace with your node for full trust. */
  async function explorerMerkleRoot(height) {
    let lastErr = "explorers unreachable";
    for (const base of EXPLORERS) {
      try {
        const h = await fetch(base + "/block-height/" + height, { cache: "no-store" }); if (!h.ok) throw new Error("HTTP " + h.status);
        const bhash = (await h.text()).trim();
        const b = await fetch(base + "/block/" + bhash, { cache: "no-store" }); if (!b.ok) throw new Error("HTTP " + b.status);
        const j = await b.json();
        const root = j.merkle_root || j.merkleroot;
        if (root) return { root: String(root).toLowerCase(), source: new URL(base).host, time: j.timestamp || j.time || null };
      } catch (e) { lastErr = e.message; }
    }
    throw new Error(lastErr);
  }

  window.tacetOts = { parse, expectedMerkleRoots, verifySheetAnchor, explorerMerkleRoot, OTSError };
})();
