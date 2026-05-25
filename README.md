# Named Entity Regex Builder (NERB)

[![CI](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/johnnygreco/nerb/blob/main/LICENSE)

NERB extracts named entities with regex detector configs. The command line is the primary interface: create and check
detector configs, extract records from text or documents, and test detector patterns before saving them. The Python API
is still available for applications that need compiled regex objects directly.

## Installation

Install or upgrade the released package:

```shell
pip install --upgrade nerb
```

After installing a release that includes CLI support, verify the command:

```shell
nerb --help
```

The `nerb` CLI and `nerb-mcp` entry points are part of the next release containing these docs. If that release is not
available on PyPI yet, run the CLI through a source checkout:

```shell
git clone https://github.com/johnnygreco/nerb.git
cd nerb
uv sync --all-extras
uv run nerb --help
```

You can also install from source:

```shell
pip install "git+https://github.com/johnnygreco/nerb.git"
nerb --help
```

The command examples below use `nerb`. From a source checkout before the CLI release is published, use `uv run nerb`
instead.

## Detector Configs

A detector config is YAML. Top-level keys are entity names, and each entity maps detector names to regex patterns.
`_flags` is reserved for regex flags on an entity.

```yaml
ARTIST:
  Pink Floyd: 'Pink\sFloyd'
  The Who: '[Tt]he\sWho'

GENRE:
  _flags: IGNORECASE
  Rock: '(?:progressive\s)?rock'
```

NERB resolves the config path in this order:

1. explicit `--config`
2. `NERB_CONFIG_PATH`
3. the platform user config path, such as `~/Library/Application Support/nerb/detectors.yaml` on macOS,
   `$XDG_CONFIG_HOME/nerb/detectors.yaml` or `~/.config/nerb/detectors.yaml` on Linux, and
   `%APPDATA%\nerb\detectors.yaml` on Windows

## CLI Quickstart

Use the default config path:

```shell
nerb init
nerb add ARTIST "Pink Floyd" 'Pink\sFloyd'
nerb add GENRE Rock rock --flag IGNORECASE
nerb extract --all --text "Pink Floyd played progressive rock." --format json
```

Output:

```json
[{"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10}, {"entity": "GENRE", "name": "Rock", "string": "rock", "start": 30, "end": 34}]
```

Use an explicit config file when you want project-local detectors:

```shell
nerb init --config ./detectors.yaml
nerb add ARTIST "Pink Floyd" 'Pink\sFloyd' --config ./detectors.yaml
nerb extract ARTIST --text "Pink Floyd played progressive rock." --config ./detectors.yaml --format json
```

Use the checked-in example config from this repository:

```shell
nerb validate --config examples/music_entities.yaml
nerb extract ARTIST examples/prog_rock_wiki.txt --config examples/music_entities.yaml --format json
```

`extract` accepts exactly one input source: a document path, `--text`, or `--stdin`. Use `ENTITY` for one entity or
`--all` for every entity in the config.

## Inline Extraction

For one-shot extraction, pass detectors directly on the command line. This does not require a saved config on a clean
install.

```shell
nerb extract ARTIST --text "Pink Floyd played progressive rock." --pattern 'Pink Floyd=Pink\sFloyd' --format json
```

Output:

```json
[{"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10}]
```

Use `--detector ENTITY:NAME=REGEX` when extracting all inline entities:

```shell
nerb extract --all --text "Pink Floyd played progressive rock." \
  --detector 'ARTIST:Pink Floyd=Pink\sFloyd' \
  --detector 'GENRE:Rock=rock' \
  --format jsonl
```

Output:

```jsonl
{"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10}
{"entity": "GENRE", "name": "Rock", "string": "rock", "start": 30, "end": 34}
```

## Authoring Commands

Use these commands while building and debugging detector configs:

```shell
nerb test ARTIST "Pink Floyd" 'Pink\sFloyd' --text "Pink Floyd played progressive rock."
nerb test ARTIST "Pink Floyd" --config examples/music_entities.yaml --document examples/prog_rock_wiki.txt --format json
nerb compile ARTIST --config examples/music_entities.yaml
nerb doctor --config examples/music_entities.yaml
nerb doctor --config examples/music_entities.yaml --format json
```

`test` checks a literal pattern or a saved detector against text. `compile` prints the final named-capture regex for an
entity. `doctor` validates YAML, detector names, regex compilation, duplicate compiled group names, and other authoring
issues. `init`, `add`, `list`, `show`, `remove`, and `validate` cover the basic config lifecycle.

## Output Formats

Extraction commands support `--format table`, `--format json`, and `--format jsonl`. Table output is the default for
humans. JSON and JSONL return records with stable fields: `entity`, `name`, `string`, `start`, and `end`.

JSON:

```json
[{"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10}]
```

JSONL:

```jsonl
{"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10}
{"entity": "GENRE", "name": "Rock", "string": "rock", "start": 30, "end": 34}
```

## Examples

The `examples/` directory contains a detector config, a sample document, a short Python API script, and an examples
README. From a source checkout:

```shell
uv run nerb validate --config examples/music_entities.yaml
uv run nerb extract ARTIST examples/prog_rock_wiki.txt --config examples/music_entities.yaml --format json
uv run python examples/prog_wiki.py
```

After installing a release that includes the CLI, use `nerb` instead of `uv run nerb`.

## Python API

Use the Python API when you need compiled regex objects or want extraction inside another Python program:

```python
from pathlib import Path

from nerb import NERB

config_path = Path("examples/music_entities.yaml")
document = Path("examples/prog_rock_wiki.txt").read_text(encoding="utf-8")

extractor = NERB(config_path, add_word_boundaries=True)
artist_records = extractor.extract_named_entity("ARTIST", document).to_records()
all_records = extractor.extract_named_entities(document).to_records()

print(artist_records[0])
print(len(all_records))
```

Compiled entity regexes are also available as attributes, such as `extractor.ARTIST`.

## MCP Server

NERB includes a local stdio MCP server on Python 3.10 and newer:

```shell
uv run nerb-mcp
```

Minimal MCP client config:

```json
{
  "mcpServers": {
    "nerb": {
      "command": "uv",
      "args": ["run", "nerb-mcp"],
      "cwd": "/path/to/nerb"
    }
  }
}
```

MCP tools require explicit `config_path` values for config reads and writes. See `AGENTS.md` and
`.agents/skills/nerb-mcp-tools/SKILL.md` for the local agent workflow details.

## Development

```shell
make sync
make check
make build
```

`make check` runs Ruff linting and formatting checks, `mypy src/nerb`, `ty check`, and pytest.
