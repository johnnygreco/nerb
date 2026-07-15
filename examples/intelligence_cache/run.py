from __future__ import annotations

import json
from pathlib import Path

from nerb import Bank, anonymize_text, load_bank
from nerb.replacements import create_replacement_db

ROOT = Path(__file__).parent


def main() -> None:
    bank_path = ROOT / "bank.json"
    message = (ROOT / "new-message.txt").read_text(encoding="utf-8").strip()
    bank_data = load_bank(bank_path)

    # Compile once, then retain this object for every message handled by the process.
    compiled = Bank.from_path(bank_path, format_hint="json")
    records = compiled.scan_text(message)
    redacted = anonymize_text(
        bank_data,
        message,
        create_replacement_db(reversible=False, store_originals=False),
        options={"mode": "redact"},
    )

    print(
        json.dumps(
            {
                "records": records,
                "redacted_text": redacted["text"],
                "note": "Rowan Birch remains because that identity was absent from the reviewed source bank.",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
