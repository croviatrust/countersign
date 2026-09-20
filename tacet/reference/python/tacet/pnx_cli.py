"""``tacet-pnx``: Proof of Non-Exfiltration from the command line.

    tacet-pnx keygen  --id urn:example:witness:ci --out witness.key.json
    tacet-pnx witness --run-id run-42 --key witness.key.json egress/ --sheet run.sheet.json --state run.state.json
    tacet-pnx prove   --state run.state.json --sheet run.sheet.json --asset api_key=secret.txt --assets-dir protected/ --out pnx.proof.json
    tacet-pnx verify  pnx.proof.json --asset api_key=secret.txt

Exit codes of ``verify`` (and of ``prove --fail-on-present``):
    0  proof valid, every asset absent
    1  proof valid, at least one asset present, undetectable or only partially covered
    2  proof invalid or unverifiable
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__ as TACET_VERSION
from .egress import NORMALIZE_JSON_STRINGS, THRESHOLD, VERDICT_ABSENT, EgressWitness
from .keys import SigningKey
from .pnx import (
    collect_assets,
    iter_bodies,
    key_from_env,
    load_key,
    load_state,
    save_key,
    save_state,
    seal_pnx,
    verify_any,
)

EXIT_OK, EXIT_PRESENT, EXIT_INVALID = 0, 1, 2


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label_path(s: str) -> tuple[str, Path]:
    if "=" not in s:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    label, path = s.split("=", 1)
    return label, Path(path)


def _witness_key(a: argparse.Namespace) -> SigningKey:
    if a.key_env:
        return key_from_env(a.key_id or "urn:crovia:pnx:witness", a.key_env)
    if a.key:
        return load_key(a.key)
    raise SystemExit("a witness key is required: --key FILE or --key-env VAR")


def _emit(obj, path: Path | None) -> None:
    text = json.dumps(obj, indent=1, ensure_ascii=False) + "\n"
    if path is None or str(path) == "-":
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


# --------------------------------------------------------------------------- commands

def cmd_keygen(a: argparse.Namespace) -> int:
    key = SigningKey.generate(a.id)
    save_key(key, a.out)
    print(f"witness key {a.id}\n  pubkey  {key.public_hex}\n  written {a.out} (0600)")
    return EXIT_OK


def cmd_witness(a: argparse.Namespace) -> int:
    key = _witness_key(a)
    norm = () if a.raw_bytes_only else (NORMALIZE_JSON_STRINGS,)
    w = load_state(a.state) if a.append and a.state.exists() else EgressWitness(run_id=a.run_id, normalization=norm)
    if w.run_id != a.run_id:
        raise SystemExit(f"state belongs to run {w.run_id!r}, not {a.run_id!r}")
    n = 0
    for body, at, _src in iter_bodies(a.paths, raw=a.raw):
        w.ingest(body, at)
        n += 1
    sheet = w.sheet(key, a.closed_at or _now())
    save_state(w, a.state)
    _emit(sheet, a.sheet)
    print(f"run {a.run_id}: {n} bodies this pass, {w.bodies} total, {w.bytes_seen:,} bytes, "
          f"{len(w._map)} fingerprints\n  root   {sheet['root']}\n  sheet  {a.sheet}\n  state  {a.state} (private)",
          file=sys.stderr)
    return EXIT_OK


def cmd_prove(a: argparse.Namespace) -> int:
    w = load_state(a.state)
    sheet = json.loads(a.sheet.read_text())
    assets = collect_assets(a.asset or [], a.assets_dir or [], a.asset_env or [])
    if not assets:
        raise SystemExit("no assets: use --asset LABEL=PATH, --assets-dir DIR or --asset-env VAR")
    proof = w.prove(sheet, assets)
    out = proof
    if a.seal_key or a.seal_key_env:
        issuer = key_from_env(a.seal_issuer_id, a.seal_key_env) if a.seal_key_env else load_key(a.seal_key)
        out = seal_pnx(proof, issuer, tacet_version=TACET_VERSION)
    _emit(out, a.out)
    per = {v: sum(1 for x in proof["assets"] if x["verdict"] == v) for v in ("absent", "absent-partial", "present", "undetectable")}
    print(f"run {sheet['run_id']}: verdict {proof['verdict']} over {len(assets)} assets "
          f"(absent {per['absent']}, partial {per['absent-partial']}, present {per['present']}, undetectable {per['undetectable']})"
          + (" · sealed" if out is not proof else ""), file=sys.stderr)
    for x in proof["assets"]:
        if x["verdict"] != VERDICT_ABSENT:
            print(f"  {x['verdict']:<14} {x['label']} ({x['asset_len']} bytes)", file=sys.stderr)
    if a.fail_on_present and proof["verdict"] != VERDICT_ABSENT:
        return EXIT_PRESENT
    return EXIT_OK


def cmd_verify(a: argparse.Namespace) -> int:
    obj = json.loads(Path(a.proof).read_text())
    supplied: dict[str, bytes] | None = None
    if a.asset or a.assets_dir or a.asset_env:
        supplied = dict(collect_assets(a.asset or [], a.assets_dir or [], a.asset_env or []))
    res, outer = verify_any(obj, supplied)
    report = {"ok": res.ok, "verdict": res.verdict, "assets": res.assets, "errors": res.errors, "warnings": res.warnings, **outer}
    if a.json:
        print(json.dumps(report, indent=1))
    else:
        proof = obj["proof"] if outer["sealed"] else obj
        sheet = proof.get("sheet", {})
        status = "VALID" if res.ok else "INVALID"
        print(f"{status} · verdict {res.verdict} · run {sheet.get('run_id')} · witness {sheet.get('witness', {}).get('id')}"
              + (f" · sealed by {outer.get('issuer_id')}" if outer["sealed"] else ""))
        eg = sheet.get("egress", {})
        print(f"  egress {eg.get('bodies')} bodies, {eg.get('bytes'):,} bytes, {eg.get('first_at')} → {eg.get('last_at')}; "
              f"guarantee for shared substrings ≥ {sheet.get('params', {}).get('threshold', THRESHOLD)} bytes")
        for label, v in res.assets.items():
            print(f"  {v:<14} {label}")
        for e in res.errors:
            print(f"  error    {e}")
        for wmsg in res.warnings:
            print(f"  warning  {wmsg}")
    if not res.ok:
        return EXIT_INVALID
    if res.verdict != VERDICT_ABSENT:
        return EXIT_PRESENT
    if a.strict and res.warnings:
        return EXIT_PRESENT
    return EXIT_OK


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tacet-pnx", description="PNX — Proof of Non-Exfiltration (TACET profile crovia.pnx.v1)")
    ap.add_argument("--version", action="version", version=f"tacet-pnx {TACET_VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create a witness or issuer key file (Ed25519, 0600)")
    k.add_argument("--id", required=True, help="key id, e.g. urn:example:pnx:witness:ci")
    k.add_argument("--out", type=Path, required=True)
    k.set_defaults(fn=cmd_keygen)

    w = sub.add_parser("witness", help="fingerprint captured egress bodies and sign the run sheet")
    w.add_argument("paths", nargs="+", type=Path, help="files (one body each), directories, or .jsonl capture logs")
    w.add_argument("--run-id", required=True)
    w.add_argument("--key", type=Path, help="witness key file from keygen")
    w.add_argument("--key-env", help="environment variable holding the witness seed as hex (CI secret)")
    w.add_argument("--key-id", help="witness id when --key-env is used")
    w.add_argument("--sheet", type=Path, required=True, help="where to write the signed run sheet (public)")
    w.add_argument("--state", type=Path, required=True, help="where to write the witness state (private, needed by prove)")
    w.add_argument("--append", action="store_true", help="add to an existing state for the same run")
    w.add_argument("--raw", action="store_true", help="treat .jsonl files as bodies, not capture logs")
    w.add_argument("--raw-bytes-only", action="store_true",
                   help="disable json-strings-v1: do not also fingerprint the decoded string values of JSON bodies")
    w.add_argument("--closed-at", help="RFC 3339 close time (default: now)")
    w.set_defaults(fn=cmd_witness)

    def asset_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--asset", action="append", type=_label_path, metavar="LABEL=PATH", help="a protected asset file")
        p.add_argument("--assets-dir", action="append", type=Path, metavar="DIR", help="every file under DIR is an asset (label = relative path)")
        p.add_argument("--asset-env", action="append", metavar="VAR", help="the value of environment variable VAR is an asset (label = env:VAR)")

    p = sub.add_parser("prove", help="prove that assets never appeared in the run's egress")
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--sheet", type=Path, required=True)
    asset_args(p)
    p.add_argument("--out", type=Path, help="proof file (default: stdout)")
    p.add_argument("--seal-key", type=Path, help="issuer key file: deliver the proof inside a crovia.seal.v1")
    p.add_argument("--seal-key-env", help="issuer seed as hex from this environment variable")
    p.add_argument("--seal-issuer-id", default="urn:crovia:seal-issuer:pnx", help="issuer id when --seal-key-env is used")
    p.add_argument("--fail-on-present", action="store_true", help="exit 1 unless every asset is absent")
    p.set_defaults(fn=cmd_prove)

    v = sub.add_parser("verify", help="verify a proof (bare or sealed) offline")
    v.add_argument("proof", type=Path)
    asset_args(v)
    v.add_argument("--strict", action="store_true", help="exit 1 on warnings too (partial coverage, assets not supplied)")
    v.add_argument("--json", action="store_true", help="machine-readable report")
    v.set_defaults(fn=cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"tacet-pnx: {e}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
