#!/usr/bin/env python3
"""Read-only checks for the Crovia MCP tool contracts.

The path cases at the bottom are a deterministic fixture. They are not a
model's choice and they are not a person's feedback.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
import unittest
import urllib.request
from pathlib import Path


def load_server(data: Path, web: Path):
    os.environ["CROVIA_DATA"] = str(data)
    os.environ["CROVIA_WEB"] = str(web)
    path = Path(__file__).with_name("mcp_server.py")
    spec = importlib.util.spec_from_file_location("crovia_mcp_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.data = root / "data"
        cls.web = root / "web"
        proof_url = "https://croviatrust.com/registry/data/tacet/proofs/qwen.json"
        write(cls.data / "model_records.json", {
            "predicate": "fixture",
            "records": {
                "Qwen/Qwen3-32B": {
                    "url": "https://croviatrust.com/m/Qwen/Qwen3-32B",
                    "live": {"last_result": False, "negative": 3, "anchored": 2, "observations": 4,
                             "first_seen": "2026-09-01", "last_seen": "2026-09-02", "surface": "hf"},
                },
                "mistralai/Mistral-7B-v0.3": {"url": "https://croviatrust.com/m/mistral-7b", "live": {"last_result": False, "negative": 1}},
                "mistralai/Mistral-Small": {"url": "https://croviatrust.com/m/mistral-small", "live": {}},
            },
        })
        write(cls.data / "tacet/latest.json", {
            "generated_at": "2026-10-01T00:00:00Z", "map_id": "fixture", "epochs": 10,
            "anchored_epochs": 8, "snapshots_total": 40, "negative_snapshots_total": 30,
            "latest_epoch": "2026-10-01T00",
        })
        write(cls.data / "tacet/targets.json", {"count": 3})
        write(cls.data / "tacet/proofs/index.json", {"proofs": [{
            "target_id": "Qwen/Qwen3-32B", "silence_days": 4, "observed_from": "2026-09-01",
            "observed_to": "2026-09-02", "observed_epochs": 4, "seal_id": "cs_fixture", "url": proof_url,
        }]})
        write(cls.data / "tacet/proofs/qwen.json", {"seal": {"fixture": True}, "query": {}, "proof": {}})
        write(cls.data / "seal/plain.json", {"not_a_seal": True})
        write(cls.web / "report/report.json", {
            "latest": "2026-W38", "url": "https://croviatrust.com/report/2026-W38/",
            "top_proofs": [{"target_id": "Qwen/Qwen3-32B", "silence_days": 4,
                            "observed_from": "2026-09-01", "observed_to": "2026-09-02", "url": proof_url}],
        })
        write(cls.web / "report/2026-W38/facts.json", {"week": "2026-W38", "models_observed": 3})
        cls.mcp = load_server(cls.data, cls.web)
        cls.calls = []

        def refuse(req, timeout=15):
            cls.calls.append(getattr(req, "full_url", req))
            raise AssertionError(f"network fetch is not part of this test: {req}")

        urllib.request.urlopen = refuse

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_unknown_term_is_an_error_and_names_the_allowed_terms(self):
        out = self.mcp.tool_explain({"term": "blockchain"})
        self.assertIn("error", out)
        self.assertIn("unknown term: blockchain", out["error"])
        self.assertEqual(out["allowed_terms"], sorted(self.mcp.TERMS))
        self.assertNotIn("definition", out)
        self.assertNotIn("terms", out)
        rpc = self.mcp.rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "explain", "arguments": {"term": "blockchain"}}})
        self.assertTrue(rpc["result"]["isError"])

    def test_missing_and_blank_term_still_return_every_definition(self):
        for args in ({}, {"term": None}, {"term": ""}, {"term": "  "}):
            out = self.mcp.tool_explain(args)
            self.assertEqual(set(out["terms"]), set(self.mcp.TERMS), args)
            self.assertNotIn("error", out)
        known = self.mcp.tool_explain({"term": " LACUNA "})
        self.assertEqual(known["term"], "lacuna")
        self.assertIn("not an accusation", known["definition"])

    def test_search_separates_returned_matched_catalog_and_limit(self):
        out = self.mcp.tool_search_models({"query": "mistral", "limit": 1})
        self.assertEqual(len(out["results"]), 1)
        self.assertEqual(out["returned"], 1)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["matched"], 2)
        self.assertEqual(out["catalog_total"], 3)
        self.assertEqual(out["total_records"], 3)
        self.assertEqual(out["limit"], 1)
        self.assertEqual(out["count"], out["returned"])
        self.assertEqual(out["total_records"], out["catalog_total"])
        self.assertGreater(out["matched"], out["count"])
        self.assertGreater(out["total_records"], out["matched"])

    def test_empty_query_matches_the_catalog_and_still_respects_the_limit(self):
        out = self.mcp.tool_search_models({})
        self.assertEqual(out["query"], "")
        self.assertEqual(out["matched"], 3)
        self.assertEqual(out["catalog_total"], 3)
        self.assertEqual(out["returned"], 3)
        self.assertEqual(out["limit"], 25)
        zero = self.mcp.tool_search_models({"query": "", "limit": 0})
        self.assertEqual(zero["limit"], 25)
        self.assertEqual(zero["count"], zero["returned"])
        self.assertEqual(zero["total_records"], zero["catalog_total"])
        self.assertEqual(self.mcp.tool_search_models({"limit": 500})["limit"], 100)
        self.assertEqual(self.mcp.tool_search_models({"limit": -5})["limit"], 1)
        self.assertEqual(self.mcp.tool_search_models({"limit": "10"})["limit"], 10)
        self.assertEqual(self.mcp.tool_search_models({"limit": 1.5})["limit"], 1)
        self.assertEqual(self.mcp.tool_search_models({"limit": True})["limit"], 1)
        self.assertEqual(self.mcp.tool_search_models({"limit": False})["limit"], 25)

    def test_a_limit_int_cannot_parse_searches_nothing(self):
        self.assertEqual(self.mcp.tool_search_models({"limit": {}})["limit"], 25)
        for bad in ("nope", {"n": 1}, [1]):
            with self.assertRaises((ValueError, TypeError)):
                self.mcp.tool_search_models({"query": "mistral", "limit": bad})
        rpc = self.mcp.rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "search_models", "arguments": {"limit": "nope"}}})
        self.assertTrue(rpc["result"]["isError"])
        self.assertNotIn("results", rpc["result"]["content"][0]["text"])

    def test_annotations_match_the_network_behavior(self):
        listed = self.mcp.rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        by_name = {t["name"]: t for t in listed}
        self.assertEqual(set(by_name), set(self.mcp.TOOL_BY_NAME))
        for name, tool in by_name.items():
            ann = tool["annotations"]
            self.assertTrue(ann["readOnlyHint"], name)
            self.assertNotIn("destructiveHint", ann, name)
            self.assertNotIn("idempotentHint", ann, name)
            self.assertEqual(ann["openWorldHint"], name == "verify_seal", name)
        import inspect
        for name, tool in self.mcp.TOOL_BY_NAME.items():
            body = inspect.getsource(tool["_fn"])
            reaches = "_fetch_site_json" in body or "urlopen" in body or "urllib" in body or "check_anchors" in body
            self.assertEqual(reaches, name == "verify_seal", name)
        seal = by_name["verify_seal"]
        self.assertIn("network", seal["description"])
        self.assertFalse(seal["inputSchema"]["properties"]["check_anchors"]["default"])
        limit_schema = by_name["search_models"]["inputSchema"]["properties"]["limit"]
        self.assertEqual(limit_schema["default"], 25)
        self.assertNotIn("minimum", limit_schema)
        self.assertNotIn("maximum", limit_schema)
        self.assertEqual(self.mcp.SERVER_INFO["version"], "2.0.1")
        init = self.mcp.rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(self.mcp.SUPPORTED_PROTOCOLS, ("2025-06-18", "2025-03-26", "2024-11-05"))

    def test_verify_seal_rejects_other_hosts_without_a_fetch(self):
        before = len(self.calls)
        foreign = self.mcp.tool_verify_seal({"url": "https://example.com/seal.json"})
        self.assertIn("error", foreign)
        self.assertEqual(len(self.calls), before)
        missing = self.mcp.tool_verify_seal({})
        self.assertIn("error", missing)
        self.assertEqual(len(self.calls), before)
        local = self.mcp.tool_verify_seal({
            "url": "https://croviatrust.com/registry/data/seal/plain.json",
            "check_anchors": False,
        })
        self.assertEqual(len(self.calls), before)
        self.assertIn(local.get("ok"), (False, None))

    def test_proof_index_week_and_model_stay_distinct(self):
        index = self.mcp.tool_get_silence_proof({})
        self.assertIn("proofs", index)
        self.assertNotIn("bundle", index)
        bundle = self.mcp.tool_get_silence_proof({"model": "Qwen/Qwen3-32B", "include_bundle": True})
        self.assertEqual(bundle["bundle"]["seal"]["fixture"], True)
        self.assertIsNone(self.mcp.tool_get_silence_proof({"model": "Qwen/Qwen3-32B"}).get("bundle"))
        week = self.mcp.tool_silence_report({"week": "2026-W38"})
        self.assertEqual(week["models_observed"], 3)
        latest = self.mcp.tool_silence_report({})
        self.assertEqual(latest["latest"], "2026-W38")
        self.assertNotIn("models_observed", latest)
        bad = self.mcp.tool_silence_report({"week": "last"})
        self.assertIn("error", bad)
        empty = self.mcp.tool_lookup_model({"model": ""})
        self.assertIn("error", empty)

    def test_question_to_interpretation_path(self):
        """Fixture router only. Not a model, and not a person."""
        cases = [
            ("What does lacuna mean?", "explain", {"term": "lacuna"},
             lambda r: "definition" in r and "accusation" in r["definition"]),
            ("What does blockchain mean?", "explain", {"term": "blockchain"},
             lambda r: r["error"].startswith("unknown term") and "tacet" in r["allowed_terms"]),
            ("How many models are on the map right now?", "crovia_status", {},
             lambda r: r["tacet"]["models_on_map"] == 3 and "week" not in r),
            ("What did the weekly Silence Report say for 2026-W38?", "silence_report", {"week": "2026-W38"},
             lambda r: r["week"] == "2026-W38" and r["models_observed"] == 3),
            ("What has Crovia observed about Qwen/Qwen3-32B?", "lookup_model", {"model": "Qwen/Qwen3-32B"},
             lambda r: r["model"] == "Qwen/Qwen3-32B" and r["verdict"] == "no_disclosure_found"),
            ("Give me the proof bundle for Qwen/Qwen3-32B", "get_silence_proof",
             {"model": "Qwen/Qwen3-32B", "include_bundle": True},
             lambda r: r["bundle"]["seal"]["fixture"] is True and r["proof"]["seal_id"] == "cs_fixture"),
            ("Find mistral models, at most one", "search_models", {"query": "mistral", "limit": 1},
             lambda r: r["returned"] == 1 and r["matched"] == 2 and r["catalog_total"] == 3 and r["limit"] == 1),
        ]
        readings = []
        for question, tool, args, accept in cases:
            chosen, chosen_args = fixture_router(question)
            self.assertEqual((chosen, chosen_args), (tool, args), question)
            result = self.mcp.TOOL_BY_NAME[chosen]["_fn"](chosen_args)
            self.assertTrue(accept(result), (question, result))
            readings.append({
                "question": question,
                "tool": chosen,
                "arguments": chosen_args,
                "reading": reading(chosen, result),
            })
        self.assertEqual(len(readings), len(cases))
        self.assertEqual(self.calls, [])


def fixture_router(question: str) -> tuple[str, dict]:
    """Map one fixture question to one tool. This is not a model and not a person."""
    q = question.lower()
    term = re.search(r"what does (\w+) mean", q)
    if term:
        return "explain", {"term": term.group(1)}
    if "right now" in q or "on the map" in q:
        return "crovia_status", {}
    week = re.search(r"(\d{4})-w(\d{2})", q)
    if "weekly" in q or week:
        if not week:
            return "silence_report", {}
        return "silence_report", {"week": f"{week.group(1)}-W{week.group(2)}"}
    if "bundle" in q:
        model = question.split("for ", 1)[1].strip()
        return "get_silence_proof", {"model": model, "include_bundle": True}
    if "observed about" in q:
        model = question.split("about ", 1)[1].strip(" ?")
        return "lookup_model", {"model": model}
    if q.startswith("find "):
        return "search_models", {"query": "mistral", "limit": 1}
    raise AssertionError(f"fixture has no route for {question!r}")


def reading(tool: str, result: dict) -> str:
    if tool == "explain" and "definition" in result:
        return "lacuna is a recorded interval of observation, not an accusation"
    if tool == "explain":
        return "blockchain is not a Crovia term; the allowed list is the answer"
    if tool == "crovia_status":
        return "three models are on the live map; this is not a weekly report"
    if tool == "silence_report":
        return "week 2026-W38 observed 3 models; this is not the live map"
    if tool == "lookup_model":
        return "the last check of Qwen/Qwen3-32B found no disclosure on the monitored surface"
    if tool == "get_silence_proof":
        return "the response is that model's seal bundle, not the weekly report"
    if tool == "search_models":
        return "one row was returned, two ids match, and the catalog has three records"
    raise AssertionError(tool)


if __name__ == "__main__":
    unittest.main()
