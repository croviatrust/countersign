"""Target list and per-epoch rotation.

Targets are Hugging Face model ids (`org/model`). The list is a plain text file
so that what is monitored is explicit, diffable and itself published in the
map under the `surfaces/` namespace (SPEC §7.1). Featured targets are observed
in every epoch; the rest rotate through the remaining budget.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Tuple

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")

FEATURED_DEFAULT = [
    "meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.3-70B-Instruct", "meta-llama/Llama-4-Scout-17B-16E-Instruct",
    "mistralai/Mistral-7B-v0.1", "mistralai/Mixtral-8x7B-v0.1", "mistralai/Mistral-Small-3.2-24B-Instruct-2506",
    "google/gemma-2-9b", "google/gemma-3-27b-it", "google/flan-t5-xxl",
    "Qwen/Qwen2.5-7B", "Qwen/Qwen3-32B", "Qwen/Qwen2.5-Coder-32B-Instruct",
    "deepseek-ai/DeepSeek-V3", "deepseek-ai/DeepSeek-R1", "deepseek-ai/deepseek-coder-33b-instruct",
    "openai/gpt-oss-120b", "openai/gpt-oss-20b", "openai/whisper-large-v3",
    "microsoft/phi-4", "microsoft/Phi-3-mini-4k-instruct", "microsoft/TRELLIS-image-large",
    "stabilityai/stable-diffusion-3.5-large", "stabilityai/stable-diffusion-xl-base-1.0",
    "black-forest-labs/FLUX.1-dev", "black-forest-labs/FLUX.1-schnell",
    "tiiuae/falcon-180B", "tiiuae/Falcon3-10B-Instruct",
    "bigscience/bloom", "EleutherAI/gpt-neox-20b", "EleutherAI/pythia-12b",
    "allenai/OLMo-2-1124-13B", "allenai/Llama-3.1-Tulu-3-8B",
    "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF", "nvidia/Nemotron-4-340B-Instruct",
    "CohereLabs/c4ai-command-r-plus", "01-ai/Yi-1.5-34B", "THUDM/glm-4-9b-chat",
    "moonshotai/Kimi-K2-Instruct", "zai-org/GLM-4.5", "xai-org/grok-1",
]


def is_model_id(s: str) -> bool:
    return bool(_ID.match(s)) and not s.startswith(("datasets/", "spaces/"))


def load_list(path: Path) -> List[str]:
    out: List[str] = []
    seen = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t or t.startswith("#") or not is_model_id(t) or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def surfaces_for(target_id: str) -> Tuple[str, str]:
    """(primary, fallback) surfaces. Fallback is used when the primary needs auth (gated repos)."""
    return (f"https://huggingface.co/{target_id}/raw/main/README.md",
            f"https://huggingface.co/{target_id}")


def plan_epoch(all_targets: List[str], featured: List[str], cursor: int, budget: int, featured_budget: int) -> Tuple[List[str], int]:
    """Featured first (bounded by featured_budget), then rotate through the rest from `cursor`."""
    feat = list(dict.fromkeys(featured))[:min(featured_budget, budget)]
    feat_set = set(feat)
    rest = [t for t in all_targets if t not in feat_set]
    picked: List[str] = list(feat)
    n = max(0, budget - len(picked))
    if rest and n:
        start = cursor % len(rest)
        for i in range(n):
            picked.append(rest[(start + i) % len(rest)])
        cursor = (start + n) % len(rest)
    return picked, cursor


def build_from_public(candidates_json: Path, silence_json: Path | None, extra: Iterable[str] = ()) -> List[str]:
    """Derive the target list from the public lacuna_candidates.json / silence_index.json files."""
    ids: List[str] = []
    try:
        d = json.loads(candidates_json.read_text())
        rows = d.get("candidates") or d.get("items") or d
        for r in rows:
            t = r.get("target_id") or r.get("target") or r.get("model")
            if t:
                ids.append(t)
    except Exception:  # noqa: BLE001
        pass
    if silence_json and silence_json.exists():
        try:
            d = json.loads(silence_json.read_text())
            for r in d.get("top_100") or d.get("top") or []:
                t = r.get("target_id") or r.get("model") or r.get("target")
                if t:
                    ids.append(t)
        except Exception:  # noqa: BLE001
            pass
    ids.extend(extra)
    out, seen = [], set()
    for t in ids:
        if is_model_id(t) and t not in seen:
            seen.add(t)
            out.append(t)
    return out
