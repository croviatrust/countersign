"""The reach record of a PNX run sheet (``crovia.pnx.reach.v1``, PNX.md §4a).

The fingerprints of a run sheet say what did not leave. The reach record says
*where* the run connected: every destination the witness saw the run try to
reach, with the outcome, and the policy the witness applied, bound by hash
before the run. It is an optional member ``reach`` of the run sheet, covered
by the sheet signature like every other member.

This module builds the record from a connection log (``ReachLog``), evaluates
a policy document (``Policy``), and verifies a record (``verify_reach``),
with or without the policy document. Verdicts: ``within-policy``,
``outside-policy``, ``unchecked`` (observe mode, document not supplied),
``unpoliced`` (no policy).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonicalize
from .hashing import prefixed, sha256

REACH_VERSION = "crovia.pnx.reach.v1"
POLICY_VERSION = "crovia.pnx.policy.v1"
DOMAIN_REACH = b"CROVIA-PNX-REACH-v1\n"

CAPTURES = ("proxy-connect", "proxy-http", "socket")
DISCLOSURES = ("clear", "salted")
OUTCOMES = ("allowed", "blocked", "failed")
POLICY_KINDS = ("allowlist", "none")
POLICY_MODES = ("enforce", "observe")

VERDICT_WITHIN = "within-policy"
VERDICT_OUTSIDE = "outside-policy"
VERDICT_UNCHECKED = "unchecked"
VERDICT_UNPOLICED = "unpoliced"


# --------------------------------------------------------------------------- policy

def _split_rule(rule: str) -> tuple[str, int | None]:
    host, sep, port = rule.rpartition(":")
    if sep and port.isdigit():
        return host.lower(), int(port)
    return rule.lower(), None


def rule_matches(rule: str, host: str, port: int) -> bool:
    """One rule of a policy document against one destination.

    ``host`` or ``host:port``; a host beginning with ``*.`` matches any name
    that ends with the rest of the rule (one or more labels), never the apex
    itself. Case-insensitive; a rule without a port matches any port.
    """
    rhost, rport = _split_rule(rule)
    host = host.lower()
    if rport is not None and rport != port:
        return False
    if rhost.startswith("*."):
        suffix = rhost[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == rhost


@dataclass(frozen=True)
class Policy:
    """A ``crovia.pnx.policy.v1`` document: the allowlist the witness applies."""

    allow: tuple[str, ...]

    @classmethod
    def from_json(cls, doc: dict[str, Any]) -> Policy:
        if doc.get("version") != POLICY_VERSION:
            raise ValueError(f"unknown policy version {doc.get('version')!r}")
        allow = doc.get("allow")
        if not isinstance(allow, list) or not all(isinstance(r, str) and r for r in allow):
            raise ValueError("policy.allow must be a list of non-empty strings")
        return cls(tuple(allow))

    def to_json(self) -> dict[str, Any]:
        return {"version": POLICY_VERSION, "allow": list(self.allow)}

    @property
    def hash(self) -> str:
        """``sha256:`` + SHA-256 of the CSC-1 encoding of the document."""
        return prefixed(sha256(canonicalize(self.to_json())))

    def allows(self, host: str, port: int) -> bool:
        return any(rule_matches(r, host, port) for r in self.allow)

    def has_wildcards(self) -> bool:
        return any(_split_rule(r)[0].startswith("*.") for r in self.allow)


def host_hash(salt: bytes, host: str) -> str:
    """Salted disclosure of a host name: hex SHA-256 of domain ‖ salt ‖ lower-cased host."""
    return sha256(DOMAIN_REACH + salt + host.lower().encode("utf-8")).hex()


# --------------------------------------------------------------------------- log → record

@dataclass
class _Dest:
    host: str
    port: int
    outcome: str
    connections: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    ips: set[str] = field(default_factory=set)
    first_at: str | None = None
    last_at: str | None = None


@dataclass
class ReachLog:
    """Connection attempts of one run, as the witness saw them, aggregated per destination.

    Feed it one ``attempt`` per connection: host, port, RFC 3339 time, and
    either the outcome the witness decided (``allowed`` / ``blocked`` /
    ``failed``) or, when a ``policy`` is set and no outcome is given, the
    outcome the policy implies for the given ``mode`` (``enforce``: refused
    destinations are ``blocked``; ``observe``: everything is ``allowed`` and
    the record shows what the policy would have said only through the
    verifier). Attempts to the same ``(host, port)`` merge; the outcome of a
    destination is ``blocked`` if any attempt was blocked, else ``failed`` if
    none was relayed, else ``allowed``.
    """

    capture: str = "proxy-connect"
    policy: Policy | None = None
    mode: str = "enforce"
    _dests: dict[tuple[str, int], _Dest] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.capture not in CAPTURES:
            raise ValueError(f"unknown capture {self.capture!r}")
        if self.mode not in POLICY_MODES:
            raise ValueError(f"unknown policy mode {self.mode!r}")
        if self.policy is None:
            self.mode = "observe"

    def decide(self, host: str, port: int) -> str:
        """What the witness does with a connection to host:port under its policy and mode."""
        if self.policy is None or self.mode == "observe" or self.policy.allows(host, port):
            return "allowed"
        return "blocked"

    def attempt(self, host: str, port: int, at: str, outcome: str | None = None, *,
                bytes_out: int = 0, bytes_in: int = 0, ip: str | None = None) -> str:
        host = host.lower()
        if outcome is None:
            outcome = self.decide(host, port)
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        if self.policy is None and outcome == "blocked":
            raise ValueError("blocked outcome without a policy")
        d = self._dests.get((host, port))
        if d is None:
            d = self._dests[(host, port)] = _Dest(host, port, outcome)
        else:
            d.outcome = _merge_outcome(d.outcome, outcome)
        d.connections += 1
        d.bytes_out += bytes_out if outcome != "blocked" else 0
        d.bytes_in += bytes_in if outcome != "blocked" else 0
        if ip:
            d.ips.add(ip)
        d.first_at = min(d.first_at, at) if d.first_at else at
        d.last_at = max(d.last_at, at) if d.last_at else at
        return outcome

    def record(self, salt: bytes, disclosure: str = "clear") -> dict[str, Any]:
        """The ``reach`` member of the run sheet."""
        if disclosure not in DISCLOSURES:
            raise ValueError(f"unknown disclosure {disclosure!r}")
        entries = []
        for d in sorted(self._dests.values(), key=lambda d: (d.host, d.port)):
            e: dict[str, Any] = {"port": d.port, "outcome": d.outcome, "connections": d.connections,
                                 "bytes_out": d.bytes_out, "bytes_in": d.bytes_in, "ips": sorted(d.ips),
                                 "first_at": d.first_at, "last_at": d.last_at}
            if disclosure == "salted":
                e["host_hash"] = host_hash(salt, d.host)
            else:
                e["host"] = d.host
            entries.append(e)
        if disclosure == "salted":
            entries.sort(key=lambda e: (e["host_hash"], e["port"]))
        policy = ({"kind": "allowlist", "mode": self.mode, "hash": self.policy.hash, "rules": len(self.policy.allow)}
                  if self.policy is not None else {"kind": "none", "mode": "observe", "hash": None, "rules": 0})
        return {"version": REACH_VERSION, "capture": self.capture, "disclosure": disclosure, "policy": policy,
                "destinations": entries, "summary": summarize(entries)}


def _merge_outcome(a: str, b: str) -> str:
    if "blocked" in (a, b):
        return "blocked"
    if "allowed" in (a, b):
        return "allowed"
    return "failed"


def summarize(entries: Iterable[dict[str, Any]]) -> dict[str, int]:
    entries = list(entries)
    return {"destinations": len(entries),
            "connections": sum(int(e.get("connections", 0)) for e in entries),
            "allowed": sum(1 for e in entries if e.get("outcome") == "allowed"),
            "blocked": sum(1 for e in entries if e.get("outcome") == "blocked"),
            "failed": sum(1 for e in entries if e.get("outcome") == "failed")}


# --------------------------------------------------------------------------- verification

@dataclass
class ReachVerifyResult:
    ok: bool
    verdict: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    outside: list[str] = field(default_factory=list)  # "host:port" of allowed/failed destinations no rule matches
    reached: dict[str, bool] = field(default_factory=dict)  # salted disclosure: name held by the verifier -> reached


def _is_rfc3339(s: Any) -> bool:
    return isinstance(s, str) and len(s) >= 20 and s.endswith("Z") and s[10] == "T"


def verify_reach(reach: dict[str, Any], salt: bytes, policy: Policy | None = None,
                 names: Iterable[str] = ()) -> ReachVerifyResult:
    """Verify a reach record (PNX.md §6 step 1b).

    ``salt`` is the run salt of the sheet (for salted disclosure). With the
    policy document the hash is recomputed and, under clear disclosure, every
    destination is matched against it. ``names`` are host names the verifier
    holds and wants checked under salted disclosure.
    """
    res = ReachVerifyResult(ok=False, verdict="?")
    err = res.errors.append
    if reach.get("version") != REACH_VERSION:
        err(f"unknown reach version {reach.get('version')!r}")
        return res
    capture, disclosure = reach.get("capture"), reach.get("disclosure")
    if capture not in CAPTURES:
        err(f"unknown capture {capture!r}")
    if disclosure not in DISCLOSURES:
        err(f"unknown disclosure {disclosure!r}")
        return res
    pol = reach.get("policy") or {}
    kind, mode, phash, rules = pol.get("kind"), pol.get("mode"), pol.get("hash"), pol.get("rules")
    if kind not in POLICY_KINDS:
        err(f"unknown policy kind {kind!r}")
    if mode not in POLICY_MODES:
        err(f"unknown policy mode {mode!r}")
    if kind == "none" and (phash is not None or rules != 0 or mode != "observe"):
        err("policy kind none must have hash null, rules 0, mode observe")
    if kind == "allowlist" and not (isinstance(phash, str) and phash.startswith("sha256:") and len(phash) == 71
                                    and isinstance(rules, int) and rules >= 0):
        err("policy kind allowlist must carry a sha256: hash and a rule count")

    entries = reach.get("destinations")
    if not isinstance(entries, list):
        err("destinations must be a list")
        return res
    keys: list[tuple[str, int]] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            err(f"destination {i}: not an object")
            continue
        name_key = "host_hash" if disclosure == "salted" else "host"
        other = "host" if disclosure == "salted" else "host_hash"
        name = e.get(name_key)
        if other in e:
            err(f"destination {i}: {other} not allowed under {disclosure} disclosure")
        if not isinstance(name, str) or not name:
            err(f"destination {i}: missing {name_key}")
            continue
        if disclosure == "salted" and (len(name) != 64 or any(c not in "0123456789abcdef" for c in name)):
            err(f"destination {i}: host_hash is not 64 lowercase hex characters")
        if disclosure == "clear" and name != name.lower():
            err(f"destination {i}: host must be lower-cased")
        port = e.get("port")
        if not isinstance(port, int) or not 0 < port < 65536:
            err(f"destination {i}: port out of range")
            continue
        if e.get("outcome") not in OUTCOMES:
            err(f"destination {i}: unknown outcome {e.get('outcome')!r}")
        if kind == "none" and e.get("outcome") == "blocked":
            err(f"destination {i}: blocked without a policy")
        if mode == "observe" and e.get("outcome") == "blocked":
            err(f"destination {i}: blocked under observe mode")
        for k in ("connections", "bytes_out", "bytes_in"):
            if not isinstance(e.get(k), int) or e[k] < 0:
                err(f"destination {i}: {k} must be a non-negative integer")
        if not isinstance(e.get("connections"), int) or e.get("connections", 0) < 1:
            err(f"destination {i}: connections must be at least 1")
        if e.get("outcome") == "blocked" and (e.get("bytes_out") or e.get("bytes_in")):
            err(f"destination {i}: bytes relayed on a blocked destination")
        ips = e.get("ips")
        if not isinstance(ips, list) or ips != sorted(ips) or len(set(ips)) != len(ips):
            err(f"destination {i}: ips must be a sorted list without duplicates")
        if not _is_rfc3339(e.get("first_at")) or not _is_rfc3339(e.get("last_at")) or e["first_at"] > e["last_at"]:
            err(f"destination {i}: first_at/last_at must be RFC 3339 UTC and ordered")
        keys.append((name, port))
    if keys != sorted(keys):
        err("destinations are not sorted by host then port")
    if len(set(keys)) != len(keys):
        err("duplicate destination")
    summary = reach.get("summary")
    if summary != summarize(e for e in entries if isinstance(e, dict)):
        err("summary does not match the destinations")
    if res.errors:
        return res

    # Policy conformance.
    if kind == "none":
        res.verdict = VERDICT_UNPOLICED
        if policy is not None:
            res.warnings.append("policy document supplied but the record was made without a policy")
    elif policy is None:
        if mode == "enforce":
            res.verdict = VERDICT_WITHIN
            res.warnings.append("policy document not supplied: the outcomes rest on the witness; only the policy hash is bound")
        else:
            res.verdict = VERDICT_UNCHECKED
            res.warnings.append("policy document not supplied and the witness observed only: conformance cannot be checked")
    else:
        if policy.hash != phash or len(policy.allow) != rules:
            err(f"policy document does not match the record: hash {policy.hash} vs {phash}, {len(policy.allow)} rules vs {rules}")
            return res
        if disclosure == "clear":
            for e in entries:
                allowed = policy.allows(e["host"], e["port"])
                if e["outcome"] in ("allowed", "failed") and not allowed:
                    res.outside.append(f"{e['host']}:{e['port']}")
                if e["outcome"] == "blocked" and allowed:
                    err(f"{e['host']}:{e['port']}: blocked although the policy allows it (inconsistent witness)")
            if res.errors:
                return res
            res.verdict = VERDICT_OUTSIDE if res.outside else VERDICT_WITHIN
        else:
            res.verdict = VERDICT_WITHIN if mode == "enforce" else VERDICT_UNCHECKED
            res.warnings.append("salted disclosure: the policy hash matches; destinations cannot be matched against the rules"
                                + (" (the policy has wildcard rules)" if policy.has_wildcards() else ""))
    if disclosure == "salted":
        hashes = {e["host_hash"] for e in entries}
        for n in names:
            res.reached[n] = host_hash(salt, n) in hashes
    res.ok = not res.errors
    return res
