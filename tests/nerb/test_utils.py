import yaml

from nerb import load_yaml_config


def test_load_yaml_config_falls_back_without_c_loader(monkeypatch, tmp_path):
    """YAML loading should work when PyYAML is installed without its C loader."""
    config_path = tmp_path / "entities.yaml"
    config_path.write_text("ENTITY:\n  Example: example\n")

    monkeypatch.delattr(yaml, "CSafeLoader", raising=False)

    assert load_yaml_config(config_path) == {"ENTITY": {"Example": "example"}}
