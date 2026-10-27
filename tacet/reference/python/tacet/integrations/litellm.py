"""PNX egress witness for LiteLLM (SDK and proxy).

Every request LiteLLM is about to send to a model provider is appended, as the
exact provider request body, to a capture log that ``tacet-pnx witness`` reads
directly (one ``{"at", "body", "dest"}`` object per line, PNX.md §3)::

    import litellm
    from tacet.integrations.litellm import PNXEgressLogger
    litellm.callbacks = [PNXEgressLogger("pnx/egress.jsonl")]

LiteLLM proxy (``config.yaml``), log path from ``PNX_EGRESS_LOG``::

    litellm_settings:
      callbacks: tacet.integrations.litellm.pnx_egress_logger

Then, once per run::

    tacet-pnx witness pnx/egress.jsonl --run-id run-42 --key witness.key.json \\
                      --sheet run.sheet.json --state run.state.json
    tacet-pnx prove --state run.state.json --sheet run.sheet.json --asset-env OPENAI_API_KEY ...

The log holds what left, so it is as sensitive as the traffic: keep it with the
private witness state, never with the proof.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from litellm.integrations.custom_logger import CustomLogger as _Base
except ImportError:  # usable (and testable) without litellm installed
    _Base = object

DEFAULT_LOG = "pnx/egress.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def outbound_body(model: Any, messages: Any, kwargs: dict[str, Any]) -> str:
    """The request body LiteLLM sends to the provider, as JSON text."""
    body = (kwargs.get("additional_args") or {}).get("complete_input_dict")
    if body is None:
        body = {"model": model, "messages": messages}
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", "replace")
    if isinstance(body, str):
        return body
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), default=str)


class PNXEgressLogger(_Base):
    """Append each outbound LiteLLM request to a PNX capture log."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        if _Base is not object:
            super().__init__()
        self.path = Path(path or os.environ.get("PNX_EGRESS_LOG") or DEFAULT_LOG)
        self._lock = threading.Lock()

    def record(self, model: Any, messages: Any, kwargs: dict[str, Any]) -> None:
        rec = {"at": _now(), "body": outbound_body(model, messages, kwargs)}
        dest = kwargs.get("api_base") or (kwargs.get("litellm_params") or {}).get("api_base")
        if dest:
            rec["dest"] = str(dest)
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())

    def log_pre_api_call(self, model, messages, kwargs):
        self.record(model, messages, kwargs)


pnx_egress_logger = PNXEgressLogger()
