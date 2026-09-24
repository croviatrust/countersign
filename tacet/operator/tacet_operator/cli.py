"""tacet-operator: run-epoch | refresh-anchors | publish | prove | verify | build-targets | keys"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import Settings
from .keys import load_all


def _settings(args) -> Settings:
    s = Settings.from_env()
    if args.state:
        s.paths.state = Path(args.state)
    if args.public:
        s.paths.public = Path(args.public)
    if getattr(args, "targets", None):
        s.targets_file = Path(args.targets)
    if getattr(args, "budget", None):
        s.per_epoch_budget = args.budget
    s.paths.ensure()
    return s


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tacet-operator")
    p.add_argument("--state", help="state directory (default $TACET_STATE or /opt/crovia/tacet/state)")
    p.add_argument("--public", help="public directory (default $TACET_PUBLIC or /var/www/registry/data/tacet)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run-epoch", help="emit the current epoch (and back-fill missed ones)")
    r.add_argument("--targets", help="newline-separated target ids")
    r.add_argument("--budget", type=int)
    r.add_argument("--no-ots", action="store_true", help="do not stamp (tests)")

    sub.add_parser("refresh-anchors", help="stamp missing proofs; close sheets confirmed in Bitcoin")

    pb = sub.add_parser("publish", help="rewrite trust_root/index/latest/targets (+ featured proofs)")
    pb.add_argument("--proofs", action="store_true")

    pr = sub.add_parser("prove", help="build a silence proof for one target, wrapped in crovia.seal.v1")
    pr.add_argument("target")
    pr.add_argument("--from-epoch", type=int, default=0)
    pr.add_argument("--to-epoch", type=int)
    pr.add_argument("--strength", type=int, default=2, choices=(1, 2))
    pr.add_argument("-o", "--out")

    vf = sub.add_parser("verify", help="verify a wrapped silence proof (signatures, chaining, non-inclusion, "
                                       "snapshots, silence: from the file; drand bytes and Bitcoin anchors: via network unless --offline)")
    vf.add_argument("file")
    vf.add_argument("--operator-pubkey", help="expected operator key_hex (from trust_root.json)")
    vf.add_argument("--offline", action="store_true",
                    help="no network: drand rounds checked for chain and schedule only, anchors taken as claimed (both reported as warnings)")
    vf.add_argument("--no-beacon", action="store_true", help="skip the drand checks entirely (reported as a warning)")
    vf.add_argument("--no-ots", action="store_true", help="skip the anchor checks entirely (reported as a warning)")

    bt = sub.add_parser("build-targets", help="derive the target list from public registry files")
    bt.add_argument("--candidates", required=True)
    bt.add_argument("--silence")
    bt.add_argument("-o", "--out", required=True)

    sub.add_parser("keys", help="print public keys (creating seeds if absent)")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    if args.cmd == "verify":
        # Third parties run this on any machine: it must not touch operator state or keys.
        from .prove import verify_file
        res = verify_file(Path(args.file), expected_operator_pubkey_hex=args.operator_pubkey,
                          check_beacon=not args.no_beacon, check_ots=not args.no_ots, offline=args.offline)
        print(json.dumps(res, indent=1))
        return 0 if res["ok"] else 1

    s = _settings(args)

    if args.cmd == "keys":
        keys = load_all(s.paths.keys)
        print(json.dumps({r: {"id": k.id, "pubkey": k.pubkey_json()} for r, k in keys.items()}, indent=1))
        return 0

    if args.cmd == "run-epoch":
        from .publish import publish_all
        from .runner import EpochRunner
        keys = load_all(s.paths.keys)
        runner = EpochRunner(s, keys)
        if args.no_ots:
            runner.ots_stamp = None
        sheet = runner.run()
        publish_all(s, keys)
        print(json.dumps({"emitted": sheet["epoch"] if sheet else None}))
        return 0

    if args.cmd == "refresh-anchors":
        from .publish import publish_all
        from .runner import refresh_anchors
        counts = refresh_anchors(s)
        # A newly closed sheet changes every silence figure; re-issue the featured proofs at once.
        publish_all(s, load_all(s.paths.keys), with_proofs=counts.get("closed", 0) > 0)
        print(json.dumps(counts))
        return 0

    if args.cmd == "publish":
        from .publish import publish_all
        latest = publish_all(s, load_all(s.paths.keys), with_proofs=args.proofs)
        print(json.dumps(latest, indent=1))
        return 0

    if args.cmd == "prove":
        from .prove import build
        keys = load_all(s.paths.keys)
        bundle = build(s, keys["issuer"], args.target, from_epoch=args.from_epoch, to_epoch=args.to_epoch, strength=args.strength)
        text = json.dumps(bundle, indent=1, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text + "\n")
            print(json.dumps({"out": args.out, "silence": bundle["proof"]["silence"], "seal_id": bundle["seal"]["seal_id"]}))
        else:
            print(text)
        return 0

    if args.cmd == "build-targets":
        from .targets import build_from_public
        ids = build_from_public(Path(args.candidates), Path(args.silence) if args.silence else None)
        Path(args.out).write_text("\n".join(ids) + "\n")
        print(json.dumps({"targets": len(ids), "out": args.out}))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
