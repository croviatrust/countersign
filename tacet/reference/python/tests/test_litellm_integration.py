import json

from tacet.egress import EgressWitness
from tacet.integrations.litellm import PNXEgressLogger, outbound_body
from tacet.keys import SigningKey
from tacet.pnx import iter_bodies

SECRET = "sk-live-" + "7f3a9c" * 8


def test_outbound_body_prefers_provider_request():
    kw = {"additional_args": {"complete_input_dict": {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}}}
    assert json.loads(outbound_body("x", [], kw))["model"] == "gpt-4o"
    assert json.loads(outbound_body("m", [{"role": "user", "content": "x"}], {}))["model"] == "m"


def test_capture_log_feeds_witness_and_proves_exposure(tmp_path):
    log = tmp_path / "egress.jsonl"
    lg = PNXEgressLogger(log)
    lg.log_pre_api_call("gpt-4o", [], {"api_base": "https://api.openai.com/v1", "additional_args": {"complete_input_dict": {
        "model": "gpt-4o", "messages": [{"role": "user", "content": f"debug this: OPENAI_KEY={SECRET}"}]}}})
    lg.log_pre_api_call("gpt-4o", [], {"additional_args": {"complete_input_dict": {
        "model": "gpt-4o", "messages": [{"role": "user", "content": "summarise the README"}]}}})
    recs = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(recs) == 2 and recs[0]["dest"] == "https://api.openai.com/v1" and "at" in recs[1]

    w = EgressWitness(run_id="litellm-test")
    for body, at, _ in iter_bodies([log]):
        w.ingest(body, at)
    sheet = w.sheet(SigningKey.generate("urn:test:witness"), "2026-10-27T00:00:00Z")
    proof = w.prove(sheet, [("leaked", SECRET.encode()), ("kept", ("never-sent-" + "q" * 60).encode())])
    verdicts = {a["label"]: a["verdict"] for a in proof["assets"]}
    assert verdicts == {"leaked": "present", "kept": "absent"}
