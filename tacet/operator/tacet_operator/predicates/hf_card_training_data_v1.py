"""crovia.pred.hf-card-training-data 1.0.0

Decides whether a Hugging Face model card (raw README.md markdown, or the
rendered model page HTML for gated repositories) carries a training-data
disclosure. Pure function of the bytes; no network, no clock, no randomness.

The card DISCLOSES training data (returns True) when at least one holds:

  A. YAML front-matter has a non-empty `datasets:` entry
     (`datasets: [x]`, `datasets:\n  - x`, or `datasets: x`).
  B. The text contains a training-data heading or lead phrase
        training data | training dataset(s) | training corpus/corpora |
        training (data )?mixture | pre-training data | pretraining data |
        data provenance | datasets used to train | trained on the ... dataset
     followed, within the same section, by at least 80 characters of prose.
     "Trained on 8 GPUs" and similar do not match: the phrase must name data.
  C. The rendered HTML page (gated repos) shows the "Datasets used to train"
     panel, i.e. contains `datasets used to train` as text.

Everything else, including an empty card, a card that only mentions license,
architecture or evaluation, or a card that says "training data: undisclosed",
returns False. Rule B deliberately accepts a disclosure that is thin; TACET
records absence, it does not grade quality.

This file is hashed byte-for-byte to produce `predicate.code_hash`. Any change
requires a new VERSION and a new module.
"""
from __future__ import annotations

import html
import re

PREDICATE_ID = "crovia.pred.hf-card-training-data"
VERSION = "1.0.0"

_FRONT_MATTER = re.compile(rb"\A---\r?\n(.*?)\r?\n---", re.S)
_DATASETS_BLOCK = re.compile(r"^datasets:\s*(.*)$", re.M)
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_HEADING_SPLIT = re.compile(r"(?m)^(?=#{1,6}\s)|(?=<h[1-6][ >])", re.I)

_LEAD = re.compile(
    r"(pre-?training\s+data|training\s+data(?:set)?s?|training\s+corp(?:us|ora)|"
    r"training\s+(?:data\s+)?mixture|data\s+provenance|datasets?\s+used\s+to\s+train|"
    r"trained\s+on\s+(?:the\s+)?[\w\-/ ]{1,60}?\s+(?:dataset|corpus|data))",
    re.I,
)
_UNDISCLOSED = re.compile(r"(not|un)\s*disclosed|undisclosed|proprietary\s+and\s+not\s+released", re.I)


def _front_matter_datasets(body: bytes) -> bool:
    m = _FRONT_MATTER.match(body)
    if not m:
        return False
    try:
        fm = m.group(1).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return False
    dm = _DATASETS_BLOCK.search(fm)
    if not dm:
        return False
    inline = dm.group(1).strip()
    if inline and inline not in ("[]", "~", "null", "''", '""'):
        return True
    # block list: following lines starting with "- "
    rest = fm[dm.end():]
    for line in rest.splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith("-"):
            return line.lstrip("- ").strip() not in ("", "''", '""')
        break
    return False


def _text(body: bytes) -> str:
    s = body.decode("utf-8", "replace")
    s = _TAG.sub(" ", s)
    s = html.unescape(s)
    return s


def _lead_with_prose(text: str) -> bool:
    for section in _HEADING_SPLIT.split(text):
        m = _LEAD.search(section)
        if not m:
            continue
        tail = _WS.sub(" ", section[m.end():]).strip()
        # skip table-of-contents style hits: need real prose after the phrase
        if len(tail) >= 80 and not _UNDISCLOSED.search(tail[:160]):
            return True
    return False


def evaluate(body: bytes) -> bool:
    if not body:
        return False
    if _front_matter_datasets(body):
        return True
    text = _text(body)
    if re.search(r"datasets used to train", text, re.I):
        return True
    return _lead_with_prose(text)
