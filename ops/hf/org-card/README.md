---
title: README
emoji: 🔐
colorFrom: gray
colorTo: gray
sdk: static
pinned: false
---

<style>
  .cv-dark { background: #0b0b0d; color: #f4f4f2; border-radius: 14px; }
  .cv-dark a { color: #f4f4f2; }
  .cv-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .cv-num { font-size: 1.7rem; line-height: 1.05; font-weight: 600; letter-spacing: -0.02em; }
  .cv-tile { border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; }
  .cv-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.12em; color: #6b7280; }
  .cv-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 6px; vertical-align: middle; }
  .cv-btn { display: inline-block; border: 1px solid #f4f4f2; border-radius: 6px; padding: 7px 13px; font-size: 0.85rem; text-decoration: none; }
  .cv-btn-solid { background: #f4f4f2; color: #0b0b0d !important; }
  .cv-h { font-size: 2rem; line-height: 1.1; font-weight: 700; letter-spacing: -0.03em; }
  .cv-card table { width: 100%; font-size: 0.85rem; border-collapse: collapse; }
  .cv-card th { text-align: left; font-weight: 500; }
  .cv-card tr { border-top: 1px solid #f0f0f0; }
  .cv-pre { background: #0b0b0d; color: #f4f4f2; border-radius: 8px; padding: 12px 14px; font-size: 0.78rem; white-space: pre-wrap; word-break: break-word; }
</style>
<div class="cv-card">
<div class="cv-dark p-6 md:p-8 mb-5">
  <div class="cv-mono text-sm opacity-70 mb-3">∴ Crovia Trust</div>
  <div class="cv-h mb-3">Crovia proves what did not happen.</div>
  <p class="text-base opacity-90 max-w-3xl">Every hour, Crovia fetches the public model cards of AI models on this Hub, asks one published
  question — <em>does this card disclose its training data?</em> — and signs what it saw. The hour is opened by a public randomness beacon
  (drand) and closed by a Bitcoin anchor. Anyone can verify the record without an account and without a Crovia server.</p>
  <div class="mt-5 flex flex-wrap gap-2">
    <a class="cv-btn cv-btn-solid" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger">Open the ledger</a>
    <a class="cv-btn" href="https://croviatrust.com/registry/tacet/spec/">Read the specification</a>
    <a class="cv-btn" href="https://croviatrust.com">croviatrust.com</a>
  </div>
</div>
<p class="cv-label mb-2"><span class="cv-dot"></span>Live from the log · updated 2026-09-26 14:06 UTC · <a class="underline" href="https://croviatrust.com/registry/data/tacet/latest.json">latest.json</a></p>
<div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
  <div class="cv-tile"><div class="cv-num cv-mono">164</div><div class="cv-label mt-1">current epoch · since 2026-09-19</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">15,525</div><div class="cv-label mt-1">signed observations</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">153</div><div class="cv-label mt-1">hours anchored in Bitcoin · last block 968,669</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">6,331</div><div class="cv-label mt-1">models in the target list</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">8,058</div><div class="cv-label mt-1">observations that found no disclosure</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">19</div><div class="cv-label mt-1">featured silence proofs</div></div>
</div>
<div class="grid md:grid-cols-2 gap-6 mb-6">
  <div>
    <div class="cv-label mb-1">Dataset · updated hourly</div>
    <h3 class="text-lg font-semibold mb-2"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger">TACET disclosure ledger</a></h3>
    <p class="text-sm">Every observation since 2026-09-19, byte for byte as served at croviatrust.com: the
    signed rows, the hourly epoch sheets, the map changes, the OpenTimestamps anchors and the featured proofs. Three tables in the viewer
    (<em>observations</em>, <em>epochs</em>, <em>targets</em>), CC-BY-4.0.</p>
    <p class="text-sm mt-3"><span class="cv-label">Verify a proof yourself</span></p>
<pre class="cv-pre cv-mono">pip install crovia-tacet-operator
tacet-operator verify proofs/&lt;slug&gt;.seal.json \
  --operator-pubkey &lt;operator key from trust_root.json&gt;</pre>
    <p class="text-xs text-gray-500 mt-1">Checks signatures, chaining, non-inclusion paths, snapshot hashes; drand rounds and Bitcoin blocks against public relays.</p>
  </div>
  <div>
    <div class="cv-label mb-1">Weekly report · open method</div>
    <h3 class="text-lg font-semibold mb-2"><a class="underline" href="https://causari.dev">Survival Report (causari)</a></h3>
    <p class="text-sm">How much AI-tagged code is still at HEAD, repository by repository, against the same repository's untagged code of the
    same age. Built with <code>causari</code>, one open-source Rust binary, no cloud: counts, not grades, and every number in the report
    can be recomputed with the command the report prints and verified offline.</p>
    <p class="text-sm mt-3"><span class="cv-label">Latest</span><br><a class="underline" href="https://causari.dev/reports/survival/2026/02/">Survival Report #2 · 2026-09-23 · 54 repositories · 58,061 AI-tagged commits · method v2</a></p>
<pre class="cv-pre cv-mono mt-3">npx causari audit &lt;owner/repo&gt;
pipx run causari audit &lt;owner/repo&gt;</pre>
  </div>
</div>
<div class="mb-6">
  <div class="cv-label mb-1">Featured proofs · 19 model cards, silence documented hour by hour</div>
  <p class="text-sm mb-2">A <em>silence</em> is a run of anchored hours in which every observation of a model card found no training-data
  disclosure on that surface. It is a statement about a web page over time — not about fraud, bad faith, or what the provider disclosed elsewhere.</p>
  <table>
    <thead><tr><th class="pb-1">Model card</th><th class="pb-1 text-right">Hours observed</th><th class="pb-1 text-right">Silence (days)</th><th class="pb-1 text-right">Proof</th></tr></thead>
    <tbody><tr><td class="py-1.5 pr-4 cv-mono">black-forest-labs/FLUX.1-dev</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/black-forest-labs__FLUX.1-dev.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">black-forest-labs/FLUX.1-schnell</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/black-forest-labs__FLUX.1-schnell.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">deepseek-ai/DeepSeek-R1</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/deepseek-ai__DeepSeek-R1.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">deepseek-ai/DeepSeek-V3</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/deepseek-ai__DeepSeek-V3.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">microsoft/TRELLIS-image-large</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/microsoft__TRELLIS-image-large.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">mistralai/Mistral-7B-v0.1</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/mistralai__Mistral-7B-v0.1.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">mistralai/Mistral-Small-3.2-24B-Instruct-2506</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/mistralai__Mistral-Small-3.2-24B-Instruct-2506.seal.json">proof</a></td></tr><tr><td class="py-1.5 pr-4 cv-mono">mistralai/Mixtral-8x7B-v0.1</td><td class="py-1.5 pr-4 text-right cv-mono">137</td><td class="py-1.5 pr-4 text-right cv-mono">5.70</td><td class="py-1.5 text-right"><a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/mistralai__Mixtral-8x7B-v0.1.seal.json">proof</a></td></tr></tbody>
  </table>
  <p class="text-xs text-gray-500 mt-2">and 11 more in <a class="underline" href="https://huggingface.co/datasets/CroviaTrust/tacet-disclosure-ledger/blob/main/proofs/index.json">proofs/index.json</a></p>
</div>
<div class="text-xs text-gray-500 border-t pt-3">
  <a class="underline" href="https://croviatrust.com/registry/tacet/spec/">TACET specification</a> (Internet-Draft <span class="cv-mono">draft-crovia-tacet</span>) ·
  <a class="underline" href="https://croviatrust.com/registry/lacuna/">LACUNA</a> ·
  <a class="underline" href="https://croviatrust.com/registry/seal/">Crovia Seal</a> ·
  <a class="underline" href="https://github.com/croviatrust">github.com/croviatrust</a> ·
  <a class="underline" href="https://causari.dev">causari.dev</a> ·
  <a class="underline" href="mailto:info@croviatrust.com">info@croviatrust.com</a><br>
  Data CC-BY-4.0, code Apache-2.0. Hours not observed count toward nothing. Corrections are made by revision, never by rewriting an anchored epoch.
  This card is regenerated hourly by the same script that publishes the dataset.
</div>
</div>
