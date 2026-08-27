# allow: SIZE_OK — one concept (the totp_keys store): schema + its nine
# CRUD operations, mirroring core domains/totp/commands.py (419 lines).
# Splitting per-command would fragment the single schema they all share.
"""SQLite secret storage for the stitch-totp plugin.

The plugin owns its own SQLite database at ``db_path`` (received in the
``plugin.init`` handshake).  Schema mirrors the core ``totp_keys`` /
``totp_group_shares`` tables; secrets are Fernet-encrypted at rest via
``crypto.py`` (same scheme as core — tokens stay interchangeable).

Migration-window simplifications (documented, deliberate):
  - Visibility is owner-based only (``owner_id IS NULL OR owner_id = uid``).
    Group-share rows are stored, but the plugin cannot resolve core group
    membership/names, so they do not extend visibility here.
  - ``unshare_group`` authorises the key owner only (the built-in also
    allows the group owner; groups live in the core DB).
"""

# _generated_by: stitch_plugin_tools scaffold v3

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Any

from . import crypto


def _connect(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode for concurrent reads."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def migrate(db_path: str) -> None:
    """Create the totp tables if they do not exist (raw_sql migration)."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS totp_keys (
                id TEXT PRIMARY KEY,
                owner_id INTEGER,
                label TEXT NOT NULL,
                secret TEXT NOT NULL,
                issuer TEXT,
                account_id TEXT,
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS totp_group_shares (
                totp_key_id TEXT NOT NULL
                    REFERENCES totp_keys(id) ON DELETE CASCADE,
                group_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (totp_key_id, group_id)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# ── Serialisation ─────────────────────────────────────────────────────────


def _key_to_dict(
    row: sqlite3.Row,
    *,
    secret: str,
    uid: int | None,
) -> dict[str, Any]:
    """Serialize a totp_keys row (camelCase, mirrors core _key_to_dict)."""
    result: dict[str, Any] = {
        "id": row["id"],
        "label": row["label"],
        "issuer": row["issuer"],
        "accountId": row["account_id"],
        "digits": row["digits"],
        "period": row["period"],
        "algorithm": row["algorithm"],
        "enabled": bool(row["enabled"]),
        "createdAt": row["created_at"],
        "ownerId": row["owner_id"],
        "secret": secret,
    }
    if uid is not None:
        result["mine"] = row["owner_id"] == uid
        result["shared"] = row["owner_id"] is None
    result["sharedGroupNames"] = []
    return result


def _visible_where(uid: int | None) -> tuple[str, list[Any]]:
    """WHERE clause: own OR instance-shared (NULL owner)."""
    if uid is None:
        return "owner_id IS NULL", []
    return "owner_id IS NULL OR owner_id = ?", [uid]


def _fetch_visible(conn: sqlite3.Connection, key_id: str, uid: int | None):
    where, args = _visible_where(uid)
    return conn.execute(
        f"SELECT * FROM totp_keys WHERE id = ? AND ({where})",
        [key_id, *args],
    ).fetchone()


# ── Commands ──────────────────────────────────────────────────────────────


def list_keys(db_path: str, uid: int | None) -> list[dict[str, Any]]:
    """Return all TOTP keys visible to *uid* (secrets decrypted)."""
    where, args = _visible_where(uid)
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            f"SELECT * FROM totp_keys WHERE {where} ORDER BY created_at",
            args,
        ).fetchall()
        return [
            _key_to_dict(
                row, secret=crypto.decrypt_lenient(row["secret"]), uid=uid
            )
            for row in rows
        ]
    finally:
        conn.close()


def count_owned_keys(db_path: str, owner_id: int | None) -> int:
    """Count TOTP keys owned by *owner_id* (mirrors _BuiltinTotp).

    owner_id=None counts keys with NULL owner (instance-shared),
    matching ``SELECT COUNT(*) WHERE owner_id IS NULL``.
    """
    conn = _connect(db_path)
    try:
        if owner_id is None:
            row = conn.execute(
                "SELECT COUNT(*) FROM totp_keys WHERE owner_id IS NULL"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM totp_keys WHERE owner_id = ?",
                (owner_id,),
            ).fetchone()
        return int(row[0])
    finally:
        conn.close()


def add_key(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Add a new TOTP key; returns the created key (with secret)."""
    label = params.get("label") or params.get("Label") or "Unnamed"
    secret = str(params.get("secret") or params.get("Secret") or "").strip().upper()
    issuer = params.get("issuer") or params.get("Issuer") or None
    account_id = params.get("accountId") or params.get("account_id") or None
    digits = int(params.get("digits", 6))
    period = int(params.get("period", 30))
    algorithm = str(params.get("algorithm") or "SHA1").upper()

    if not secret:
        return {"success": False, "error": "TOTP secret is required"}

    key_id = str(uuid.uuid4())
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO totp_keys "
            "(id, owner_id, label, secret, issuer, account_id, "
            " digits, period, algorithm, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (
                key_id, uid, label, crypto.encrypt(secret), issuer,
                account_id, digits, period, algorithm,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (key_id,)
        ).fetchone()
        return _key_to_dict(row, secret=secret, uid=uid)
    finally:
        conn.close()


def update_key(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Update label, issuer, accountId, or enabled for an existing key."""
    key_id = params.get("id") or params.get("keyId") or params.get("key_id")
    if not key_id:
        return {"success": False, "error": "Key id is required"}

    conn = _connect(db_path)
    try:
        row = _fetch_visible(conn, str(key_id), uid)
        if row is None:
            raise ValueError(f"TOTP key not found: {key_id}")

        label = params["label"] if "label" in params else row["label"]
        if "issuer" in params:
            issuer = params["issuer"] or None
        else:
            issuer = row["issuer"]
        if "accountId" in params:
            account_id = params["accountId"] or None
        elif "account_id" in params:
            account_id = params["account_id"] or None
        else:
            account_id = row["account_id"]
        if "enabled" in params:
            enabled = 1 if params["enabled"] else 0
        else:
            enabled = row["enabled"]

        conn.execute(
            "UPDATE totp_keys SET label = ?, issuer = ?, account_id = ?, "
            "enabled = ? WHERE id = ?",
            (label, issuer, account_id, enabled, str(key_id)),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(key_id),)
        ).fetchone()
        return _key_to_dict(
            row, secret=crypto.decrypt_lenient(row["secret"]), uid=uid
        )
    finally:
        conn.close()


def remove_key(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Delete a TOTP key by id (and its group shares)."""
    key_id = params.get("id") or params.get("keyId") or params.get("key_id")
    if not key_id:
        return {"success": False, "error": "Key id is required"}

    conn = _connect(db_path)
    try:
        row = _fetch_visible(conn, str(key_id), uid)
        if row is None:
            raise ValueError(f"TOTP key not found: {key_id}")
        conn.execute(
            "DELETE FROM totp_group_shares WHERE totp_key_id = ?",
            (str(key_id),),
        )
        conn.execute("DELETE FROM totp_keys WHERE id = ?", (str(key_id),))
        conn.commit()
    finally:
        conn.close()
    return {"success": True, "id": str(key_id)}


def link_key(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Link a TOTP key to an account (or unlink if accountId is null)."""
    key_id = params.get("id") or params.get("keyId") or params.get("key_id")
    account_id = params.get("accountId") or params.get("account_id") or None
    if not key_id:
        return {"success": False, "error": "Key id is required"}

    conn = _connect(db_path)
    try:
        row = _fetch_visible(conn, str(key_id), uid)
        if row is None:
            raise ValueError(f"TOTP key not found: {key_id}")
        conn.execute(
            "UPDATE totp_keys SET account_id = ? WHERE id = ?",
            (str(account_id) if account_id else None, str(key_id)),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(key_id),)
        ).fetchone()
        return _key_to_dict(
            row, secret=crypto.decrypt_lenient(row["secret"]), uid=uid
        )
    finally:
        conn.close()


def claim_key(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Claim a shared (owner NULL) TOTP key for the caller."""
    if uid is None:
        raise ValueError("Authentication required to claim a shared key")
    key_id = params.get("id") or params.get("keyId") or params.get("key_id")
    if not key_id:
        return {"success": False, "error": "Key id is required"}

    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(key_id),)
        ).fetchone()
        if row is None:
            raise ValueError(f"TOTP key not found: {key_id}")
        if row["owner_id"] is not None:
            raise ValueError("not shared")
        conn.execute(
            "UPDATE totp_keys SET owner_id = ? WHERE id = ?",
            (uid, str(key_id)),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(key_id),)
        ).fetchone()
        return _key_to_dict(
            row, secret=crypto.decrypt_lenient(row["secret"]), uid=uid
        )
    finally:
        conn.close()


def share_group(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Share a TOTP key to a group (key owner; idempotent)."""
    totp_id = params.get("totpId") or params.get("totp_id")
    group_id = params.get("groupId") or params.get("group_id")
    if not totp_id:
        return {"success": False, "error": "totpId is required"}
    if not group_id:
        return {"success": False, "error": "groupId is required"}

    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(totp_id),)
        ).fetchone()
        if row is None:
            raise ValueError("TOTP key not found")
        if uid is not None and row["owner_id"] != uid:
            raise ValueError("Only the key owner can share it")
        conn.execute(
            "INSERT OR IGNORE INTO totp_group_shares (totp_key_id, group_id) "
            "VALUES (?, ?)",
            (str(totp_id), group_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {"success": True}


def unshare_group(db_path: str, params: dict[str, Any], uid: int | None) -> dict[str, Any]:
    """Unshare a TOTP key (key owner; idempotent)."""
    totp_id = params.get("totpId") or params.get("totp_id")
    group_id = params.get("groupId") or params.get("group_id")
    if not totp_id:
        return {"success": False, "error": "totpId is required"}
    if not group_id:
        return {"success": False, "error": "groupId is required"}

    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM totp_keys WHERE id = ?", (str(totp_id),)
        ).fetchone()
        if row is None:
            raise ValueError("TOTP key not found")
        if uid is not None and row["owner_id"] != uid:
            raise ValueError("Only the key owner can unshare it")
        conn.execute(
            "DELETE FROM totp_group_shares "
            "WHERE totp_key_id = ? AND group_id = ?",
            (str(totp_id), group_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {"success": True}


def import_secrets(db_path: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Upsert core ``totp_keys`` rows (migration; idempotent by key id).

    Rows arrive with plaintext secrets (core ORM decrypts on read); they
    are re-encrypted with the plugin's Fernet key before storage.
    """
    conn = _connect(db_path)
    try:
        for row in rows:
            secret = str(row.get("secret") or "").strip().upper()
            if not secret:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO totp_keys "
                "(id, owner_id, label, secret, issuer, account_id, "
                " digits, period, algorithm, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                " COALESCE(?, datetime('now')))",
                (
                    str(row.get("id") or uuid.uuid4()),
                    row.get("ownerId"),
                    row.get("label") or "Unnamed",
                    crypto.encrypt(secret),
                    row.get("issuer"),
                    row.get("accountId"),
                    int(row.get("digits", 6)),
                    int(row.get("period", 30)),
                    str(row.get("algorithm") or "SHA1").upper(),
                    1 if row.get("enabled", True) else 0,
                    row.get("createdAt"),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return {"imported": len(rows)}
