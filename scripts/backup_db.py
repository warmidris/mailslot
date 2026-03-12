#!/usr/bin/env python3
"""
Create a consistent SQLite backup of the live Stackmail DB.

Usage:
  python3 scripts/backup_db.py /data/stackmail.db /backups/stackmail-YYYYMMDD-HHMMSS.db
"""

from __future__ import annotations

import pathlib
import sqlite3
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: backup_db.py <source.db> <dest.db>", file=sys.stderr)
        return 2

    source = pathlib.Path(sys.argv[1]).resolve()
    dest = pathlib.Path(sys.argv[2]).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    src = sqlite3.connect(str(source))
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    print(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
