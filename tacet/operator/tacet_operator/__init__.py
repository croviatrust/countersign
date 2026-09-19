"""TACET operator: turns the reference primitives into a running log.

Layout (SPEC §12):

    state/                      private, on the operator host
      keys/                     32-byte Ed25519 seeds (operator, observer, issuer)
      map.json                  {key_hex: value_hash_hex} current map
      values/<key_hex>.json     slot value objects (kind disclosure/retraction)
      cursor.json               rotation cursor over the target list
    public/                     served at /registry/data/tacet/
      trust_root.json           map_id, genesis, keys, drand chain, predicates
      sheets/<epoch>.json       signed epoch sheets (closed once OTS confirms)
      snapshots/<epoch>.jsonl   signed surface snapshots taken in the epoch
      changes/<epoch>.json      [[key_hex, value_hash_hex], ...] applied in the epoch
      ots/<epoch>.ots           OpenTimestamps proof of the sheet hash
      proofs/<slug>.seal.json   featured silence proofs wrapped in crovia.seal.v1
      latest.json, index.json   discovery
"""

__version__ = "0.1.0"
