from __future__ import annotations

import json
from pathlib import Path

from nerb import NERB

EXAMPLE_DIR = Path(__file__).resolve().parent

config_path = EXAMPLE_DIR / "music_entities.yaml"
document_path = EXAMPLE_DIR / "prog_rock_wiki.txt"
document = document_path.read_text(encoding="utf-8")

extractor = NERB(config_path, add_word_boundaries=True)
artist_records = extractor.extract_named_entity("ARTIST", document).to_records()
all_records = extractor.extract_named_entities(document).to_records()

print(json.dumps(artist_records[:5], indent=2))
print(f"{len(artist_records)} ARTIST matches")
print(f"{len(all_records)} total matches")
