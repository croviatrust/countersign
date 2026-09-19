/* tacet-verify.js — browser verification of a TACET silence proof
 * (crovia.tacet.silence.v1 wrapped in crovia.seal.v1), SPEC §8.5.
 *
 * Mirrors tacet/reference/python/tacet: epoch.py (sheets), smt.py (sparse Merkle
 * map, depth 256), snapshot.py, merkle.py (RFC 6962), silence.py (delta paths,
 * monotonicity rule). Uses csc1() and ed25519Verify() from the host page.
 *
 * What runs here: seal binding, sheet signatures and chaining, non-inclusion of
 * the target slot in every epoch, observer signatures and inclusion of every
 * negative snapshot, silence recomputation, witness quorum. Optional network
 * checks: drand round bytes against api.drand.sh, keys against the published
 * trust root, and the OpenTimestamps anchors (SPEC §8.6, via ots-verify.js):
 * each .ots is parsed here and its merkle root compared with the block header
 * from a public explorer — no Bitcoin node, no ots client.
 */
"use strict";
(function () {
  const enc = new TextEncoder();
  const DEPTH = 256;
  const D = s => enc.encode(s + "\n");
  const D_EMPTY = D("TACET-EMPTY-v1"), D_LEAF = D("TACET-LEAF-v1"), D_NODE = D("TACET-NODE-v1");
  const D_EPOCH = D("TACET-EPOCH-v1"), D_WITNESS = D("TACET-WITNESS-v1"), D_SNAP = D("TACET-SNAPSHOT-v1");
  const DRAND = { chain: "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce", genesis: 1595431050, period: 30, tolerance: 1800 };
  const TRUST_ROOT_URL = "/registry/data/tacet/trust_root.json";
  const PROOF_VERSION = "crovia.tacet.silence.v1", QUERY_VERSION = "crovia.tacet.query.v1";
  const SHEET_VERSION = "crovia.tacet.epoch.v1", SNAP_VERSION = "crovia.tacet.snapshot.v1";
  const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

  function cat() { let n = 0; for (const p of arguments) n += p.length; const out = new Uint8Array(n); let o = 0; for (const p of arguments) { out.set(p, o); o += p.length; } return out; }
  async function sha256(b) { return new Uint8Array(await crypto.subtle.digest("SHA-256", b)); }
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  function unhex(h) { if (typeof h !== "string" || !/^[0-9a-f]*$/.test(h) || h.length % 2) throw new Error("invalid hex"); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; }
  function unprefixed(v) { if (typeof v !== "string" || !v.startsWith("sha256:") || v.length !== 71) throw new Error("expected sha256:<64 hex>"); return unhex(v.slice(7)); }
  function eq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
  function strip(obj, drop) { const o = {}; for (const k of Object.keys(obj)) if (!drop.includes(k)) o[k] = obj[k]; return o; }
  const bytesOf = obj => enc.encode(csc1(obj));
  const isInt = v => Number.isInteger(v) && typeof v === "number";
  const ts = v => Math.floor(Date.parse(v) / 1000);
  const setEq = (a, b) => a.length === b.length && a.every(x => b.includes(x));

  /* ---- sparse Merkle map (smt.py / hashing.py) ---- */
  let EMPTY = null;
  async function emptyTable() {
    if (EMPTY) return EMPTY;
    const t = [await sha256(D_EMPTY)];
    for (let i = 0; i < DEPTH; i++) t.push(await sha256(cat(D_NODE, t[t.length - 1], t[t.length - 1])));
    return (EMPTY = t);
  }
  const nodeHash = (l, r) => sha256(cat(D_NODE, l, r));
  const keyBit = (key, i) => (key[i >> 3] >> (7 - (i % 8))) & 1;
  async function rootFromPath(key, leaf, sibs) {
    if (sibs.length !== DEPTH) throw new Error("a full path has exactly 256 siblings");
    let node = leaf;
    for (let h = 0; h < DEPTH; h++) { const sib = sibs[h]; node = keyBit(key, DEPTH - 1 - h) ? await nodeHash(sib, node) : await nodeHash(node, sib); }
    return node;
  }
  function fullPath(compact, E) {
    if (!compact || typeof compact.bitmap !== "string" || !Array.isArray(compact.siblings)) throw new Error("path must be {bitmap, siblings}");
    const bm = BigInt("0x" + compact.bitmap); const sibs = compact.siblings.map(unhex); let it = 0; const full = [];
    for (let h = 0; h < DEPTH; h++) full.push(((bm >> BigInt(h)) & 1n) ? sibs[it++] : E[h]);
    if (it !== sibs.length) throw new Error("path siblings do not match bitmap");
    return full;
  }
  function decodePaths(encoded, epochs, E) {
    const full = fullPath(encoded.initial, E); const out = [full.slice()];
    const deltas = encoded.deltas || [];
    if (deltas.length !== epochs.length - 1) throw new Error("number of deltas must be number of epochs minus one");
    deltas.forEach((d, i) => {
      if (d.epoch !== epochs[i + 1]) throw new Error("delta epoch " + d.epoch + " does not match sheet epoch " + epochs[i + 1]);
      for (const [h, v] of d.changed) { if (!isInt(h) || h < 0 || h >= DEPTH) throw new Error("delta height out of range"); full[h] = v === null ? E[h] : unhex(v); }
      out.push(full.slice());
    });
    return out;
  }
  async function targetKey(id) { return sha256(enc.encode(id.normalize("NFC").trim())); }

  /* ---- epoch sheets (epoch.py) ---- */
  const sheetHash = s => sha256(bytesOf(strip(s, ["signature", "closed"])));
  async function validateSheet(s) {
    if (!s || typeof s !== "object" || s.sheet_version !== SHEET_VERSION) throw new Error("sheet_version must be " + SHEET_VERSION);
    const req = ["sheet_version", "map_id", "epoch", "epoch_start", "epoch_end", "root", "prev_sheet_hash", "size", "opened", "snapshots_root", "operator", "signature", "closed"];
    if (!setEq(Object.keys(s), req)) throw new Error("sheet fields differ from the specification");
    if (!isInt(s.epoch) || s.epoch < 0) throw new Error("epoch must be a non-negative integer");
    for (const f of ["epoch_start", "epoch_end"]) if (!RFC3339.test(s[f])) throw new Error(f + " must be RFC 3339 UTC seconds");
    if (s.epoch_end <= s.epoch_start) throw new Error("epoch_end must be after epoch_start");
    unprefixed(s.root); unprefixed(s.snapshots_root); if (s.prev_sheet_hash !== null) unprefixed(s.prev_sheet_hash);
    if (!isInt(s.size) || s.size < 0) throw new Error("size must be a non-negative integer");
    const o = s.opened;
    if (!o || o.kind !== "drand") throw new Error("opened must be a drand beacon object");
    for (const k of ["chain_hash", "round", "randomness", "signature"]) if (!(k in o)) throw new Error("opened." + k + " is required");
    if (!isInt(o.round) || o.round < 1) throw new Error("opened.round must be a positive integer");
    const op = s.operator;
    if (!op || !setEq(Object.keys(op), ["id", "pubkey"]) || !setEq(Object.keys(op.pubkey), ["alg", "key_hex"])) throw new Error("operator must be {id, pubkey{alg,key_hex}}");
    const sig = s.signature;
    if (!sig || !setEq(Object.keys(sig), ["alg", "domain", "sig_hex"]) || sig.domain !== "TACET-EPOCH-v1") throw new Error("signature must be {alg, domain='TACET-EPOCH-v1', sig_hex}");
    const ok = await ed25519Verify(unhex(sig.sig_hex), cat(D_EPOCH, bytesOf(strip(s, ["signature", "closed"]))), unhex(op.pubkey.key_hex));
    if (!ok) throw new Error("operator signature invalid for epoch " + s.epoch);
    const c = s.closed;
    if (!c || c.kind !== "ots" || !["pending", "bitcoin"].includes(c.status)) throw new Error("closed must be an ots object with status pending|bitcoin");
    if (!eq(unprefixed(c.anchored_digest), await sheetHash(s))) throw new Error("closed.anchored_digest does not match sheet_hash");
    if (c.status === "bitcoin") for (const k of ["block_height", "block_time", "proof_ref"]) if (!(k in c)) throw new Error("closed." + k + " required when status is bitcoin");
  }
  async function validateChain(sheets) {
    if (!Array.isArray(sheets) || !sheets.length) throw new Error("empty sheet range");
    for (const s of sheets) await validateSheet(s);
    for (let i = 1; i < sheets.length; i++) {
      const p = sheets[i - 1], c = sheets[i];
      if (c.map_id !== p.map_id) throw new Error("map_id changes inside the range");
      if (c.epoch !== p.epoch + 1) throw new Error("epoch gap between " + p.epoch + " and " + c.epoch);
      if (c.prev_sheet_hash === null || !eq(unprefixed(c.prev_sheet_hash), await sheetHash(p))) throw new Error("prev_sheet_hash of epoch " + c.epoch + " does not match epoch " + p.epoch);
      if (c.epoch_start < p.epoch_end) throw new Error("epoch " + c.epoch + " starts before epoch " + p.epoch + " ends");
    }
  }
  function beaconStructural(opened, epochStart) {
    if (opened.chain_hash !== DRAND.chain) return false;
    const t = DRAND.genesis + (opened.round - 1) * DRAND.period, start = ts(epochStart);
    return start - DRAND.period <= t && t <= start + DRAND.tolerance;
  }

  /* ---- snapshots (snapshot.py) and RFC 6962 inclusion (merkle.py) ---- */
  const snapshotHash = snap => sha256(cat(D_SNAP, bytesOf(strip(snap, ["signature"]))));
  async function validateSnapshot(snap) {
    if (!snap || snap.snapshot_version !== SNAP_VERSION) throw new Error("snapshot_version must be " + SNAP_VERSION);
    const req = ["snapshot_version", "target_id", "surface_url", "fetched_at", "epoch", "beacon_round", "http_status", "body_sha256", "body_len", "tls_cert_sha256", "resolved_ip", "predicate", "result", "observer", "signature"];
    if (!setEq(Object.keys(snap), req)) throw new Error("snapshot fields differ from the specification");
    if (typeof snap.result !== "boolean") throw new Error("result must be boolean");
    if (!snap.predicate || !setEq(Object.keys(snap.predicate), ["id", "version", "code_hash"])) throw new Error("predicate must be {id, version, code_hash}");
    let ok = false;
    try { ok = await ed25519Verify(unhex(snap.signature.sig_hex), cat(D_SNAP, bytesOf(strip(snap, ["signature"]))), unhex(snap.observer.pubkey.key_hex)); }
    catch (e) { throw new Error("snapshot signature unreadable: " + e.message); }
    if (!ok) throw new Error("observer signature invalid");
  }
  const mLeaf = d => sha256(cat(new Uint8Array([0]), d)), mNode = (l, r) => sha256(cat(new Uint8Array([1]), l, r));
  async function merkleInclusion(root, leaf, index, size, path) {
    if (!(isInt(index) && isInt(size) && 0 <= index && index < size)) return false;
    let node = await mLeaf(leaf), fn = index, sn = size - 1;
    for (const sib of path) {
      if (fn % 2 === 1 || fn === sn) { node = await mNode(sib, node); while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
      else node = await mNode(node, sib);
      fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
    }
    return sn === 0 && eq(node, root);
  }

  /* ---- silence (silence.py §8.4) ---- */
  function computeSilence(sheets, observed) {
    const by = new Map(sheets.map(s => [s.epoch, s])); let total = 0;
    for (const e of observed) { const s = by.get(e); if (s) total += ts(s.epoch_end) - ts(s.epoch_start); }
    const obs = Array.from(observed).sort((a, b) => a - b);
    return { map_epochs: sheets.length, observed_epochs: observed.size, observed_from: obs.length ? by.get(obs[0]).epoch_start : null,
             observed_to: obs.length ? by.get(obs[obs.length - 1]).epoch_end : null, silence_seconds: total, silence_days: formatSilenceDays(total) };
  }
  // SPEC §9: two decimals, truncated, integer arithmetic — byte-identical to the Python reference.
  function formatSilenceDays(seconds) { const cents = Math.floor((seconds * 100) / 86400); return Math.floor(cents / 100) + "." + String(cents % 100).padStart(2, "0"); }
  function silenceMatches(claimed, expected) {
    if (!claimed || typeof claimed !== "object") return false;
    for (const k of ["map_epochs", "observed_epochs", "observed_from", "observed_to", "silence_seconds"]) if (claimed[k] !== expected[k]) return false;
    return claimed.silence_days === expected.silence_days;
  }

  async function fetchJson(url) { const r = await fetch(url, { cache: "no-store" }); if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }

  /* ---- entry point ---- */
  async function verifyTacetEnvelope(env, steps, opts) {
    opts = opts || {};
    const step = (ok, label, det, fatal) => { steps.push({ ok, label, det: det || "" }); if (!ok && fatal !== false) throw new Error(label); };
    const note = (label, det) => steps.push({ ok: true, label, det: det || "", soft: true });
    const hdr = (label, det) => steps.push({ ok: true, label, det: det || "", hdr: true });
    const seal = env.seal, query = env.query, proof = env.proof;
    const errors = [];
    const err = (ok, label, det) => { steps.push({ ok, label, det: det || "" }); if (!ok) errors.push(label); return ok; };

    hdr("— outer seal", (seal && seal.seal_id) || "?");
    await verifyChain([seal], steps);

    hdr("— binding of query and proof to the seal");
    const qb = bytesOf(query), pb = bytesOf(proof);
    step(seal.subject.input_hash === "sha256:" + hex(await sha256(qb)), "subject.input_hash binds the query", qb.length + " canonical bytes");
    step(seal.subject.output_hash === "sha256:" + hex(await sha256(pb)), "subject.output_hash binds the proof", pb.length + " canonical bytes");
    err(seal.subject.input_len === qb.length && seal.subject.output_len === pb.length, "subject lengths match canonical byte counts");
    step(query.query_version === QUERY_VERSION, "query_version is " + QUERY_VERSION, String(query.query_version));
    step(query.target_id === proof.target_id && query.map_id === proof.map_id, "query and proof agree on target and map", proof.target_id);
    step(proof.proof_version === PROOF_VERSION, "proof_version is " + PROOF_VERSION, String(proof.proof_version));
    const claimed = proof.strength;
    step([1, 2, 3].includes(claimed), "strength is 1, 2 or 3", "claimed " + claimed);

    hdr("— epoch sheets (operator signatures, hash chain, temporal bounds)", proof.from_epoch + " → " + proof.to_epoch);
    const sheets = proof.sheets;
    try { await validateChain(sheets); step(true, sheets.length + " sheet(s) valid and chained", "TACET-EPOCH-v1 signatures, prev_sheet_hash links, anchored_digest"); }
    catch (e) { step(false, "sheets: " + e.message); }
    err(sheets[0].epoch === proof.from_epoch && sheets[sheets.length - 1].epoch === proof.to_epoch, "from_epoch/to_epoch match the sheet range");
    err(sheets.every(s => s.map_id === proof.map_id), "map_id matches every sheet", proof.map_id);
    const opKeys = Array.from(new Set(sheets.map(s => s.operator.pubkey.key_hex)));
    err(opKeys.length === 1, "one operator key across the range", opKeys[0] ? opKeys[0].slice(0, 16) + "…" : "");
    const chains = Array.from(new Set(sheets.map(s => s.opened.chain_hash)));
    if (chains.length === 1 && chains[0] === DRAND.chain) {
      err(sheets.every(s => beaconStructural(s.opened, s.epoch_start)), "drand rounds sit at each epoch start on the pinned chain", "chain " + DRAND.chain.slice(0, 8) + "…, 30 s rounds, tolerance " + DRAND.tolerance + " s");
    } else {
      note("epochs opened by a beacon chain this page does not pin (" + chains.map(c => String(c).slice(0, 8) + "…").join(", ") + ")", "round times not checked; the Python verifier warns the same way without a beacon_check");
    }
    const anchored = new Set(sheets.filter(s => s.closed.status === "bitcoin").map(s => s.epoch));
    const pending = sheets.length - anchored.size;
    note(anchored.size + " of " + sheets.length + " sheet(s) carry a Bitcoin attestation" + (pending ? " (" + pending + " pending)" : ""),
         opts.network ? "each .ots proof is parsed and matched to its Bitcoin block header in the network checks below (SPEC §8.6)"
                      : "enable network checks to parse each .ots proof and match it to its Bitcoin block header (SPEC §8.6); offline, the anchors are taken as claimed");

    hdr("— non-inclusion of the target slot in every epoch");
    const E = await emptyTable();
    const key = unhex(proof.key);
    step(eq(key, await targetKey(proof.target_id)), "key is SHA-256 of the NFC-normalised target_id", proof.key.slice(0, 16) + "…");
    let paths;
    try { paths = decodePaths(proof.paths, sheets.map(s => s.epoch), E); } catch (e) { step(false, "paths: " + e.message); }
    let emptyAll = true;
    for (let i = 0; i < sheets.length; i++) {
      const ok = eq(await rootFromPath(key, E[0], paths[i]), unprefixed(sheets[i].root));
      if (!ok) { emptyAll = false; err(false, "epoch " + sheets[i].epoch + ": slot is not empty (non-inclusion fails)"); }
    }
    if (emptyAll) step(true, "slot empty under the root of all " + sheets.length + " epoch(s)", "depth-256 sparse Merkle map, delta-encoded sibling paths");
    let verified = errors.length ? 0 : 1;

    const observed = new Set();
    let expected;
    if (claimed >= 2 && verified >= 1) {
      hdr("— negative snapshots (observer signatures, inclusion under snapshots_root)");
      const by = new Map(sheets.map(s => [s.epoch, s]));
      let good = 0;
      for (const entry of proof.snapshots || []) {
        const snap = entry.snapshot || {};
        try { await validateSnapshot(snap); } catch (e) { err(false, "snapshot: " + e.message); continue; }
        const sheet = by.get(snap.epoch);
        if (!sheet) { err(false, "snapshot for epoch " + snap.epoch + " outside the range"); continue; }
        if (snap.target_id !== proof.target_id || snap.result !== false) { err(false, "epoch " + snap.epoch + ": snapshot is not a negative snapshot of the target"); continue; }
        if (snap.beacon_round !== sheet.opened.round) { err(false, "epoch " + snap.epoch + ": snapshot beacon_round does not match opened.round"); continue; }
        const inc = await merkleInclusion(unprefixed(sheet.snapshots_root), await snapshotHash(snap), entry.index, entry.size, (entry.path || []).map(unhex));
        if (!inc) { err(false, "epoch " + snap.epoch + ": snapshot not included under snapshots_root"); continue; }
        good++;
        if (anchored.has(snap.epoch)) observed.add(snap.epoch);
      }
      const preds = Array.from(new Set((proof.snapshots || []).map(e => e.snapshot && e.snapshot.predicate && (e.snapshot.predicate.id + "@" + e.snapshot.predicate.version))));
      step(true, good + " negative snapshot(s) signed by the observer and included in their epoch", preds.join(", "));
      expected = computeSilence(sheets, observed);
      err(silenceMatches(proof.silence, expected), "silence block matches recomputation under the monotonicity rule",
          expected.observed_epochs + " anchored observed epoch(s) = " + expected.silence_days + " days; unanchored or unobserved hours count zero");
      if (!errors.length) verified = 2;
    } else {
      expected = computeSilence(sheets, new Set());
      if (claimed === 1) err(silenceMatches(proof.silence, expected), "level-1 proof reports zero observed epochs");
    }

    if (claimed >= 3 && verified >= 2) {
      hdr("— witnesses");
      const ws = proof.witness_set || {}; const ids = new Set(ws.ids || []);
      if (!isInt(ws.k) || !isInt(ws.n) || ws.k < 1 || ws.k > ws.n || ids.size !== ws.n) err(false, "witness_set must be {k, n, ids} with 1 <= k <= n == len(ids)");
      else {
        for (const s of sheets) {
          const sh = await sheetHash(s); const entries = (proof.witnesses || {})["sha256:" + hex(sh)] || [];
          const valid = new Set();
          for (const w of entries) { if (!ids.has(w.id)) continue; try { if (await ed25519Verify(unhex(w.sig_hex), cat(D_WITNESS, sh), unhex(w.pubkey.key_hex))) valid.add(w.id); } catch (_) {} }
          err(valid.size >= ws.k, "epoch " + s.epoch + ": " + valid.size + " valid witness signature(s), need " + ws.k);
        }
      }
      if (!errors.length) verified = 3;
    }

    hdr("— seal checks block");
    const ck = (seal.checks || {}).tacet || {};
    err(ck.strength === proof.strength && ck.silence_days === proof.silence.silence_days && ck.observed_to === proof.silence.observed_to, "checks.tacet repeats the proof's strength and silence");
    step(query.min_strength === undefined || verified >= query.min_strength, "verified strength meets the query's min_strength", "verified " + verified + ", required " + (query.min_strength ?? 1));

    if (opts.network) {
      hdr("— network checks (opt-in)");
      try {
        const tr = await fetchJson(TRUST_ROOT_URL);
        const keys = JSON.stringify(tr);
        const okOp = keys.includes(opKeys[0]), okIss = keys.includes(seal.issuer.pubkey.key_hex);
        err(okOp && okIss, "operator and issuer keys appear in the published trust root", TRUST_ROOT_URL);
      } catch (e) { note("trust root not fetched (" + e.message + ")", "keys were checked for internal consistency only"); }
      let checked = 0, mismatch = 0;
      for (const s of sheets.slice(0, 24)) {
        try {
          const b = await fetchJson("https://api.drand.sh/" + s.opened.chain_hash + "/public/" + s.opened.round);
          checked++; if (b.randomness !== s.opened.randomness || b.signature !== s.opened.signature) mismatch++;
        } catch (_) {}
      }
      if (checked) err(mismatch === 0, "drand round bytes match api.drand.sh for " + checked + " sheet(s)" + (sheets.length > 24 ? " (first 24)" : ""), mismatch ? mismatch + " mismatch(es)" : "randomness and BLS signature bytes identical");
      else note("drand API not reachable from this browser", "round times were checked against the chain's genesis and period");

      /* SPEC §8.6 — Bitcoin anchors, without a node: parse each .ots, compare its merkle root with the block header. */
      if (window.tacetOts) {
        const anchoredSheets = sheets.filter(s => s.closed && s.closed.status === "bitcoin").slice(0, 24);
        let okN = 0, badN = 0, unN = 0, src = null; const bad = [], un = [];
        const headerSource = async h => { const r = await window.tacetOts.explorerMerkleRoot(h); src = src || r.source; return r.root; };
        for (const s of anchoredSheets) {
          let verdict = null, detail = "";
          try {
            const r = await fetch(s.closed.proof_ref, { cache: "no-store" }); if (!r.ok) throw new Error("HTTP " + r.status);
            const res = await window.tacetOts.verifySheetAnchor(new Uint8Array(await r.arrayBuffer()), await sheetHash(s), s.closed.block_height, headerSource);
            verdict = res.verdict; detail = res.detail;
          } catch (e) { detail = "proof not fetched (" + e.message + ")"; }
          if (verdict === true) okN++; else if (verdict === false) { badN++; bad.push("epoch " + s.epoch + ": " + detail); } else { unN++; un.push("epoch " + s.epoch + ": " + detail); }
        }
        if (anchoredSheets.length) {
          if (badN) err(false, "OpenTimestamps anchor differs from the Bitcoin block header for " + badN + " sheet(s)", bad.join(" · "));
          if (okN) step(true, "OpenTimestamps anchors replayed in this browser and matched to Bitcoin block headers for " + okN + " sheet(s)" + (sheets.length > 24 ? " (first 24)" : ""), "merkle roots from " + (src || "explorer") + "; blocks " + [...new Set(anchoredSheets.map(s => s.closed.block_height))].sort().join(", "));
          if (unN) note("Bitcoin anchors unchecked for " + unN + " sheet(s)", un[0] + (unN > 1 ? " …" : ""));
        }
      }
    }

    if (errors.length) throw new Error(errors[0]);
    return { verified, claimed, silence: expected, anchored: anchored.size, sheets: sheets.length, target: proof.target_id };
  }

  window.verifyTacetEnvelope = verifyTacetEnvelope;
  window.isTacetEnvelope = obj => !!(obj && typeof obj === "object" && obj.seal && obj.proof && obj.query && !obj.seal_version);
})();
