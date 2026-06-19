#!/usr/bin/env python3
"""
reset_admin_password.py - Reset a LogBoost Web admin account password.

Use this when you've forgotten the admin password and can no longer log in.
Hashes the new password using the same PBKDF2-SHA256 (100k iterations) scheme
as the live application (admin.py::hash_password) and writes it directly to
the SQLite admin database.

Usage:
  ./scripts/reset_admin_password.py                                 # interactive
  ./scripts/reset_admin_password.py --username admin                # prompt only for password
  ./scripts/reset_admin_password.py --username admin --password PW  # fully non-interactive
  ./scripts/reset_admin_password.py --list                          # list admin accounts and exit

In a running container:
  docker exec -it logboost-web /app/scripts/reset_admin_password.py
  docker exec    logboost-web /app/scripts/reset_admin_password.py --username admin --password 'NEW_PW'

The DB path is taken from the LOGBOOST_DB_PATH env var
(default: /data/db/logboost_admin.db).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import secrets
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB_PATH = "/data/db/logboost_admin.db"
PBKDF2_ITERATIONS = 100_000  # must match admin.py::hash_password
MIN_PASSWORD_LEN = 8         # must match admin.py setup validation
ADMIN_ROLE = "admin"


def hash_password(password: str) -> str:
    """Match admin.py::hash_password — salt:pbkdf2_sha256(100k)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f"{salt}:{digest.hex()}"


def open_db(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        sys.exit(f"ERROR: admin DB not found at {db_path}. "
                 f"Set LOGBOOST_DB_PATH or pass --db.")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def list_admins(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, role FROM users WHERE role = ? ORDER BY id",
        (ADMIN_ROLE,),
    ).fetchall()


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset a LogBoost admin password.")
    parser.add_argument("--username", "-u", help="Account username to reset.")
    parser.add_argument("--password", "-p", help="New password (omit to be prompted).")
    parser.add_argument("--db", help=f"Path to admin DB (default: {DEFAULT_DB_PATH} or $LOGBOOST_DB_PATH).")
    parser.add_argument("--list", "-l", action="store_true", help="List admin accounts and exit.")
    args = parser.parse_args()

    db_path = Path(args.db or os.environ.get("LOGBOOST_DB_PATH", DEFAULT_DB_PATH))
    conn = open_db(db_path)

    admins = list_admins(conn)
    if not admins:
        print(f"No admin accounts found in {db_path}.", file=sys.stderr)
        print("Tip: delete the DB file and restart the container to trigger first-time setup.",
              file=sys.stderr)
        return 1

    if args.list:
        print(f"Admin accounts in {db_path}:")
        for row in admins:
            print(f"  id={row['id']:<3} username={row['username']}")
        return 0

    # Resolve target username
    username = args.username
    if not username:
        if len(admins) == 1:
            username = admins[0]["username"]
            print(f"Resetting the only admin account: {username}")
        else:
            print("Multiple admin accounts — pick one:")
            for row in admins:
                print(f"  - {row['username']}")
            try:
                username = input("Username: ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                return 1
    target = next((r for r in admins if r["username"] == username), None)
    if target is None:
        print(f"ERROR: no admin account named '{username}'. Use --list to see available accounts.",
              file=sys.stderr)
        return 1

    # Resolve new password
    password = args.password
    if not password:
        try:
            password = getpass.getpass(f"New password for '{username}': ")
            confirm = getpass.getpass("Confirm new password: ")
        except (KeyboardInterrupt, EOFError):
            print()
            return 1
        if password != confirm:
            print("ERROR: passwords do not match.", file=sys.stderr)
            return 1

    if len(password) < MIN_PASSWORD_LEN:
        print(f"ERROR: password must be at least {MIN_PASSWORD_LEN} characters.", file=sys.stderr)
        return 1

    # Apply update
    conn.execute(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (hash_password(password), target["id"]),
    )
    conn.commit()
    conn.close()

    print(f"OK: password for admin '{username}' (id={target['id']}) has been reset.")
    print("You can log in now. Existing browser sessions are unaffected; logout to re-test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
