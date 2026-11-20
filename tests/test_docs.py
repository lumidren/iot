import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_feature_reference_matches_the_code():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "gen_features_doc.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    on_disk = (ROOT / "docs" / "FEATURES.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert on_disk == gen.render(), "run: python scripts/gen_features_doc.py"
