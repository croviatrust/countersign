"""Countersign CLI.

Commands::

    countersign init   --log DIR                      create a witness log + keypair
    countersign witness --log DIR (FILE | --digest H | --jsonl F) [--note TEXT]
    countersign prove  --log DIR --digest H [--out F] build an offline-verifiable proof
    countersign verify BUNDLE [--pubkey HEX]          verify a proof bundle offline
    countersign audit  --log DIR                      full self-check of a log
    countersign sth    --log DIR                      print the latest signed tree head
    countersign list   --log DIR [--limit N]          list witnessed entries

All commands print JSON to stdout and exit 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import adapters
from .log import LogError, WitnessLog
from .proof import ProofError, build_proof, load_bundle, verify_proof

DEFAULT_LOG_DIR = Path.home() / ".countersign" / "log"


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _fail(message: str) -> int:
    print(json.dumps({"ok": False, "error": message}), file=sys.stderr)
    return 1


def cmd_init(args: argparse.Namespace) -> int:
    try:
        log = WitnessLog.init(Path(args.log))
    except (LogError, FileExistsError) as exc:
        return _fail(str(exc))
    key = log.key()
    _print(
        {
            "ok": True,
            "log": str(log.dir),
            "public_key": key.public_hex,
            "key_id": key.key_id,
            "hint": "publish the public key; keep witness.key secret and backed up",
        }
    )
    return 0


def cmd_witness(args: argparse.Namespace) -> int:
    log = WitnessLog(Path(args.log))
    note = args.note or ""
    try:
        if args.digest:
            receipts = [log.witness(args.digest.lower(), note=note)]
        elif args.jsonl:
            receipts = []
            for lineno, digest in adapters.iter_jsonl_digests(Path(args.jsonl)):
                line_note = f"{Path(args.jsonl).name}#L{lineno}"
                if note:
                    line_note = f"{note} {line_note}"
                receipts.append(log.witness(digest, note=line_note))
            if not receipts:
                return _fail(f"no non-empty lines in {args.jsonl}")
        elif args.file:
            digest = adapters.digest_file(Path(args.file))
            receipts = [log.witness(digest, note=note or Path(args.file).name)]
        else:
            return _fail("provide FILE, --digest, or --jsonl")
    except (LogError, OSError) as exc:
        return _fail(str(exc))

    _print(
        {
            "ok": True,
            "witnessed": [r.to_dict() for r in receipts],
            "count": len(receipts),
            "sth": receipts[-1].sth,
        }
    )
    return 0


def cmd_prove(args: argparse.Namespace) -> int:
    log = WitnessLog(Path(args.log))
    try:
        bundle = build_proof(log, args.digest.lower(), index=args.index)
    except (LogError, ProofError) as exc:
        return _fail(str(exc))
    if args.out:
        Path(args.out).write_text(
            json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _print({"ok": True, "proof": str(args.out), "digest": args.digest.lower()})
    else:
        _print(bundle)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        bundle = load_bundle(Path(args.bundle))
    except ProofError as exc:
        return _fail(str(exc))
    report = verify_proof(bundle, expected_public_key=args.pubkey)
    _print(report)
    return 0 if report["ok"] else 1


def cmd_audit(args: argparse.Namespace) -> int:
    log = WitnessLog(Path(args.log))
    try:
        report = log.audit()
    except (LogError, FileNotFoundError) as exc:
        return _fail(str(exc))
    _print(report)
    return 0 if report["ok"] else 1


def cmd_sth(args: argparse.Namespace) -> int:
    log = WitnessLog(Path(args.log))
    try:
        _print(log.latest_sth())
    except LogError as exc:
        return _fail(str(exc))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    log = WitnessLog(Path(args.log))
    try:
        entries = log.entries()
    except LogError as exc:
        return _fail(str(exc))
    if args.limit:
        entries = entries[-args.limit :]
    _print({"ok": True, "count": len(entries), "entries": entries})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="countersign",
        description="Independent witnessing for AI agent evidence: "
        "append-only Merkle log, signed tree heads, offline-verifiable proofs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_log_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--log",
            default=str(DEFAULT_LOG_DIR),
            help=f"witness log directory (default: {DEFAULT_LOG_DIR})",
        )

    p = sub.add_parser("init", help="create a new witness log and keypair")
    add_log_arg(p)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("witness", help="witness a file, digest, or JSONL stream")
    add_log_arg(p)
    p.add_argument("file", nargs="?", help="file to digest and witness")
    p.add_argument("--digest", help="precomputed sha256 hex digest to witness")
    p.add_argument("--jsonl", help="witness every line of a JSONL evidence file")
    p.add_argument("--note", help="free-text label stored with the entry")
    p.set_defaults(func=cmd_witness)

    p = sub.add_parser("prove", help="build an offline-verifiable proof bundle")
    add_log_arg(p)
    p.add_argument("--digest", required=True, help="digest to prove")
    p.add_argument("--index", type=int, help="specific entry index (optional)")
    p.add_argument("--out", help="write the bundle to this file")
    p.set_defaults(func=cmd_prove)

    p = sub.add_parser("verify", help="verify a proof bundle (offline)")
    p.add_argument("bundle", help="path to a proof bundle JSON file")
    p.add_argument("--pubkey", help="pin the expected witness public key (hex)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("audit", help="verify the internal consistency of a log")
    add_log_arg(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("sth", help="print the latest signed tree head")
    add_log_arg(p)
    p.set_defaults(func=cmd_sth)

    p = sub.add_parser("list", help="list witnessed entries")
    add_log_arg(p)
    p.add_argument("--limit", type=int, help="show only the last N entries")
    p.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
