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
