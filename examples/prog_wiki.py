from __future__ import annotations

import json
from pathlib import Path

from nerb import Bank, load_config

EXAMPLE_DIR = Path(__file__).resolve().parent

config_path = EXAMPLE_DIR / "music_entities.yaml"
document_path = EXAMPLE_DIR / "prog_rock_wiki.txt"
document = document_path.read_text(encoding="utf-8")

bank = Bank.from_config(load_config(config_path), word_boundaries=True)
all_records = bank.scan_text(document)
artist_records = [record for record in all_records if record["entity"] == "ARTIST"]

print(json.dumps(artist_records[:5], indent=2))
print(f"{len(artist_records)} ARTIST matches")
print(f"{len(all_records)} total matches")
