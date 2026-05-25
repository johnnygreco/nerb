# NERB Examples

Run these commands from the repository root. They use the source checkout so they work before the CLI release is
available on PyPI. After installing a release that includes the CLI, use `nerb` instead of `uv run nerb`.

```shell
uv run nerb validate --config examples/music_entities.yaml
uv run nerb doctor --config examples/music_entities.yaml
uv run nerb extract ARTIST examples/prog_rock_wiki.txt --config examples/music_entities.yaml --format json
uv run nerb extract --all examples/prog_rock_wiki.txt --config examples/music_entities.yaml --format jsonl
uv run python examples/prog_wiki.py
```

`music_entities.yaml` demonstrates multiple entities and entity-level `_flags`. `prog_wiki.py` is the same workflow
through the Python API.
