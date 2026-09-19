# Contributing

TACET is small on purpose: a specification, a reference implementation, conformance
vectors, and one production operator. Contributions that keep it that way are the most
welcome.

## Where help matters most

1. **A second implementation.** Port `tacet/conformance/run_conformance.py` to Go, Rust
   or TypeScript and make all 28 vectors pass. That is how a protocol becomes real.
2. **Independent witnesses.** Run a witness that countersigns epoch sheets from your own
   vantage point (level-3 proofs). Open an issue titled `witness: <org>` and we will
   publish your key in the trust root.
3. **Predicates.** A predicate is a pure `bytes -> bool` with a version and real-card
   vectors under `tacet/operator/tests/`. New predicates (EU AI Act Art. 53 summary
   template, GitHub READMEs, provider documentation pages) go through the same
   vector discipline. Permissive by default: TACET records absence, it does not grade.
4. **Verifier UX.** A browser verifier for `.seal.json` proofs (drag, drop, verified).

## Rules of the road

- The Seal format (`crovia.seal.v1`, IETF draft) is frozen. TACET is a profile of it;
  never modify the envelope.
- `tacet/SPEC.md` changes need a matching change in the reference and, if a wire
  format moves, regenerated vectors (`generate_vectors.py`) in the same PR.
- Wording follows `CANON.md §7`: observation facts, never intent. "Hid", "refused",
  "violated" do not appear in this repository.
- Every number on a public surface must be readable from a public file. If you add a
  number to `site/`, add its source to `CANON.md §4`.

## Local checks

```bash
pip install -e ../crovia-seal/reference/python -e "tacet/reference/python[test]" -e tacet/operator
(cd tacet/reference/python && python -m pytest -q)
(cd tacet/operator && python -m pytest -q)
python tacet/conformance/run_conformance.py
ruff check tacet
```

CI runs the same plus a weekly audit of the live site against the canon.

## Security

Cryptographic issues: see `SECURITY.md`. Please do not open public issues for key or
signature problems.

## Licence

Code Apache-2.0; specification texts CC0; public data CC-BY-4.0. By contributing you
agree your contribution is licensed the same way.
