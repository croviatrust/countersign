"""Reproducible end-to-end demo of Countersign.

Run:  python examples/demo.py

Simulates the full lifecycle with a temporary witness log:

1. an "agent operator" produces a receipts file (self-signed evidence),
2. every receipt is witnessed by an independent Countersign log,
3. a proof bundle is exported for one receipt,
4. a third party verifies the bundle OFFLINE with only the public key,
5. the operator tries to tamper with the evidence — and gets caught.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from countersign.adapters import iter_jsonl_digests  # noqa: E402
from countersign.log import WitnessLog  # noqa: E402
from countersign.proof import build_proof, verify_proof  # noqa: E402


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="countersign-demo-"))
    print(f"demo workspace: {tmp}\n")

    # 1. The operator's agent produced evidence (any format; here, receipts).
    receipts = tmp / "agent_receipts.jsonl"
    lines = [
        {"tool": "send_email", "agent": "billing-bot", "status": "ok", "n": 1},
        {"tool": "refund", "agent": "billing-bot", "amount_cents": 1999, "n": 2},
        {"tool": "db_write", "agent": "billing-bot", "table": "invoices", "n": 3},
    ]
    receipts.write_text(
        "\n".join(json.dumps(line, sort_keys=True) for line in lines) + "\n",
        encoding="utf-8",
    )
    print(f"[operator] wrote {len(lines)} receipts to {receipts.name}")

    # 2. Independent witness: append each receipt digest to the Merkle log.
    log = WitnessLog.init(tmp / "witness-log")
    public_key = log.key().public_hex
    print(f"[witness]  new log, public key {public_key[:16]}…")
    for lineno, digest in iter_jsonl_digests(receipts):
        r = log.witness(digest, note=f"receipts#L{lineno}")
        print(f"[witness]  L{lineno} -> index {r.index}, tree_size {r.sth['tree_size']}")

    # 3. Export a proof for receipt #2 (the refund).
    refund_line = json.dumps(lines[1], sort_keys=True).encode()
    refund_digest = hashlib.sha256(refund_line).hexdigest()
    bundle = build_proof(log, refund_digest)
    bundle_path = tmp / "refund_proof.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\n[operator] exported offline proof: {bundle_path.name}")

    # 4. A third party verifies OFFLINE, trusting only the pinned public key.
    report = verify_proof(
        json.loads(bundle_path.read_text(encoding="utf-8")),
        expected_public_key=public_key,
    )
    assert report["ok"], report["problems"]
    print(f"[auditor]  proof VERIFIED offline: refund receipt existed by {report['sth_timestamp']}")

    # 5. Tamper attempt: the operator rewrites the refund amount after the fact.
    tampered = dict(lines[1], amount_cents=19)
    tampered_digest = hashlib.sha256(
        json.dumps(tampered, sort_keys=True).encode()
    ).hexdigest()
    forged = json.loads(json.dumps(bundle))
    forged["entry"]["digest"] = tampered_digest
    report2 = verify_proof(forged, expected_public_key=public_key)
    assert not report2["ok"]
    print(f"[auditor]  tampered evidence REJECTED: {report2['problems'][0]}")

    # Bonus: the log audits itself.
    audit = log.audit()
    assert audit["ok"], audit["problems"]
    print(f"\n[witness]  self-audit ok: {audit['tree_size']} entries, root {audit['root_hash'][:16]}…")
    print("\nDemo passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
