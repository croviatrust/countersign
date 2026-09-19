import hashlib
from pathlib import Path

from tacet_operator.predicates import load
from tacet_operator.predicates import hf_card_training_data_v1 as pred

VECTORS = Path(__file__).parent / "vectors"


def test_registry_hashes_source_file():
    ev, version, code_hash = load("crovia.pred.hf-card-training-data")
    assert version == "1.0.0"
    assert code_hash == hashlib.sha256(Path(pred.__file__).read_bytes()).digest()
    assert ev is pred.evaluate


def test_front_matter_datasets_inline_and_block():
    assert pred.evaluate(b"---\nlicense: mit\ndatasets: [wikitext]\n---\n# M\n")
    assert pred.evaluate(b"---\ndatasets:\n  - allenai/c4\n  - openwebtext\n---\n")
    assert not pred.evaluate(b"---\ndatasets: []\n---\n# M\n")
    assert not pred.evaluate(b"---\nlicense: mit\n---\n# M\nJust a model.\n")


def test_training_data_section_with_prose():
    card = (b"---\nlicense: apache-2.0\n---\n# Model\n\n## Training Data\n\n"
            b"The model was pre-trained on a mixture of publicly available web text, books and code, "
            b"filtered for quality and deduplicated. See the paper for the composition.\n\n## Eval\n")
    assert pred.evaluate(card)


def test_heading_only_or_undisclosed_is_negative():
    assert not pred.evaluate(b"# Model\n\n## Training Data\n\n## Evaluation\nscores...\n")
    assert not pred.evaluate(b"# Model\n\n## Training data\n\nThe training data is not disclosed. "
                             b"This section intentionally left blank for competitive reasons and so on and on.\n")
    assert not pred.evaluate(b"# Model\nTrained on 8 GPUs for 3 days with a batch size of 1024 and cosine schedule.\n")


def test_empty_and_binary():
    assert not pred.evaluate(b"")
    assert not pred.evaluate(bytes(range(256)) * 10)


def test_html_rendered_page():
    html = (b"<html><body><h2>Training Data</h2><p>Llama 3.1 was pretrained on ~15 trillion tokens of data "
            b"from publicly available sources. The fine-tuning data includes publicly available instruction datasets.</p>"
            b"</body></html>")
    assert pred.evaluate(html)
    assert pred.evaluate(b"<div>Datasets used to train <a href='/datasets/x'>x</a></div>")


def test_real_vectors():
    for f in sorted(VECTORS.glob("*.expect")):
        body = (VECTORS / f.stem).read_bytes()
        expected = f.read_text().strip() == "true"
        assert pred.evaluate(body) is expected, f.stem
