import argparse
import json
import sqlite3
from pathlib import Path

import config


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_ioc_table() -> None:
    conn = _get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ioc_cache (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            cached_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            ioc               TEXT,
            ioc_type          TEXT,
            threat_type       TEXT,
            malware_printable TEXT,
            confidence_level  INTEGER,
            reporter          TEXT,
            raw_json          TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def _load_input(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Input must be a JSON array of IOC records")
    rows: list[dict] = []
    for row in data:
        if isinstance(row, dict) and row.get("ioc"):
            rows.append(row)
    return rows


def preseed(path: Path, clear_existing: bool = False) -> int:
    _init_ioc_table()
    rows = _load_input(path)
    conn = _get_conn()

    if clear_existing:
        conn.execute("DELETE FROM ioc_cache")

    inserted = 0
    for r in rows:
        conn.execute(
            """
            INSERT INTO ioc_cache
            (ioc, ioc_type, threat_type, malware_printable, confidence_level, reporter, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(r.get("ioc", "")),
                str(r.get("ioc_type", "")),
                str(r.get("threat_type", "")),
                str(r.get("malware_printable", "")),
                int(r.get("confidence_level", 0) or 0),
                str(r.get("reporter", "offline_seed")),
                json.dumps(r.get("raw_json", r), ensure_ascii=True),
            ),
        )
        inserted += 1

    conn.commit()
    conn.close()
    return inserted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Pre-seed DARKSPACE IOC cache for offline-only operation"
    )
    parser.add_argument("--input", required=True, help="Path to IOC JSON file")
    parser.add_argument("--clear", action="store_true", help="Clear existing cache first")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")

    count = preseed(path, clear_existing=args.clear)
    print(f"Pre-seed complete. Inserted {count} IOC record(s) into {config.DB_PATH}.")
