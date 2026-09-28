# crovia-tacet (reference implementation)

Reference Python implementation of [TACET](../../SPEC.md): sparse Merkle map,
epoch sheets, surface snapshots, delta-encoded silence proofs, and delivery as
an unmodified `crovia.seal.v1`.

Dependencies: `cryptography` (Ed25519). The Seal wrapper additionally needs the
Crovia Seal reference package (`crovia_seal`).

```bash
pip install -e .
python3 -m pytest
```

## PNX command line

`pip install crovia-tacet` also installs `tacet-pnx`, the Proof of
Non-Exfiltration tool (profile `crovia.pnx.v1`, see `../../PNX.md`):

```bash
tacet-pnx keygen  --id urn:example:pnx:witness --out witness.key.json
tacet-pnx witness egress/ logs/gateway.jsonl --run-id run-42 --key witness.key.json \
                  --sheet run.sheet.json --state run.state.json      # state is private
tacet-pnx prove   --state run.state.json --sheet run.sheet.json \
                  --asset api_key=secret.txt --assets-dir protected/ --asset-env OPENAI_API_KEY \
                  --out pnx.proof.json [--seal-key issuer.key.json]  # deliver as crovia.seal.v1
tacet-pnx verify  pnx.proof.json --asset api_key=secret.txt --assets-dir protected/
```

Where the run connected (the reach record, PNX §4a) is added at witness time
from a connection log and checked against the policy document:

```bash
tacet-pnx witness egress/ --reach logs/connect.jsonl --policy egress-policy.json \
                  --reach-mode enforce [--reach-salted] ...                  # one {"at","host","port",...} per line
tacet-pnx verify  pnx.proof.json --policy egress-policy.json [--name api.github.com]
tacet-pnx verify  run.sheet.json --policy egress-policy.json   # a sheet alone: reach receipt, no asset judged
```

Exit codes: 0 valid and every asset absent (or a sheet alone) · 1 valid but present, undetectable,
partial or outside-policy · 2 invalid. The GitHub Action `croviatrust/pnx-action` wraps the same
three steps for CI (`../../action/`).
