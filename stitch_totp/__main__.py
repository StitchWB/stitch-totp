"""RPC entry point for the stitch-totp service plugin.

Spawned by ``ServicePluginHost`` as ``python -m stitch_totp``.
Implements the JSON-RPC 2.0 line protocol via ``RpcPluginServer``
(imported from ``autoreg.plugin.rpc`` when available, otherwise from
the vendored ``_vendor/rpc_server.py`` copy).

Protocol methods handled by ``RpcPluginServer``:
  - ``plugin.init``    → stores handshake params, resolves the Fernet key.
  - ``plugin.call``    → dispatches to command handlers.
  - ``plugin.ping``    → returns ``"pong"``.
  - ``plugin.shutdown``→ returns ``None`` and exits.

Commands mirror the built-in ``domains/totp`` command names without the
totp prefix (``list_keys``, ``add_key``, ``update_key``, ``remove_key``,
``link_key``, ``claim_key``, ``share_group``, ``unshare_group``), plus
``import_secrets`` (core → plugin migration, idempotent) and the
TotpProvider code methods (``generate_secret``, ``generate_code``,
``verify_code``, ``count_owned_keys``).
"""

# _generated_by: stitch_plugin_tools scaffold v3

from __future__ import annotations

from typing import Any

from . import crypto, storage, totp

try:
    from autoreg.plugin.rpc import RpcPluginServer
except ImportError:
    from ._vendor.rpc_server import RpcPluginServer


# ── State received in plugin.init handshake ───────────────────────────────


class _Ctx:
    """Mutable container for plugin.init handshake state."""

    db_path: str = ""
    data_dir: str = ""


ctx = _Ctx()


def _uid(params: dict[str, Any]) -> int | None:
    """Caller user id forwarded by the dual-format router or SPI proxy.

    Reads ``caller_user_id`` (dual/namespaced routes) first, then
    ``owner_id`` (SPI proxy path).  None = guest.
    """
    uid = params.get("caller_user_id")
    if uid is None:
        uid = params.get("owner_id")
    return int(uid) if uid is not None else None


def _handle_init(params: dict[str, Any]) -> dict[str, Any]:
    """Store handshake params, resolve the Fernet key, return init result."""
    ctx.db_path = str(params.get("db_path", ""))
    ctx.data_dir = str(params.get("data_dir", ""))
    if ctx.data_dir:
        crypto.init_crypto(ctx.data_dir)
    return {
        "plugin_id": params.get("plugin_id", ""),
        "db_path": ctx.db_path,
        "data_dir": ctx.data_dir,
        # Capability negotiation: this plugin does not use reverse-RPC
        # (no call_host).  Declared explicitly for contract uniformity.
        "capabilities": [],
    }


def _handle_migrate_db(params: dict[str, Any]) -> dict[str, Any]:
    """Create SQLite tables (raw_sql migration, from_version→to_version)."""
    if ctx.db_path:
        storage.migrate(ctx.db_path)
    return {
        "from_version": params.get("from_version", 0),
        "to_version": params.get("to_version", 1),
    }


def _handle_list_keys(params: dict[str, Any]) -> list[dict[str, Any]]:
    if not ctx.db_path:
        return []
    return storage.list_keys(ctx.db_path, _uid(params))


def _handle_add_key(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.add_key(ctx.db_path, params, _uid(params))


def _handle_update_key(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.update_key(ctx.db_path, params, _uid(params))


def _handle_remove_key(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.remove_key(ctx.db_path, params, _uid(params))


def _handle_link_key(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.link_key(ctx.db_path, params, _uid(params))


def _handle_claim_key(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.claim_key(ctx.db_path, params, _uid(params))


def _handle_share_group(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.share_group(ctx.db_path, params, _uid(params))


def _handle_unshare_group(params: dict[str, Any]) -> dict[str, Any]:
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    return storage.unshare_group(ctx.db_path, params, _uid(params))


def _handle_import_secrets(params: dict[str, Any]) -> dict[str, Any]:
    """Upsert core totp_keys rows (migration; idempotent by key id)."""
    if not ctx.db_path:
        raise ValueError("plugin storage not initialised")
    rows = params.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError("rows must be a list")
    return storage.import_secrets(ctx.db_path, rows)


def _handle_generate_secret(params: dict[str, Any]) -> dict[str, Any]:
    return {"secret": totp.generate_secret()}


def _handle_generate_code(params: dict[str, Any]) -> dict[str, Any]:
    secret = str(params.get("secret", ""))
    if not secret:
        raise ValueError("secret is required")
    timestamp = params.get("timestamp")
    code = totp.generate_code(
        secret,
        digits=int(params.get("digits", 6)),
        period=int(params.get("period", 30)),
        algorithm=str(params.get("algorithm") or "SHA1"),
        timestamp=int(timestamp) if timestamp is not None else None,
    )
    return {"code": code}


def _handle_verify_code(params: dict[str, Any]) -> dict[str, Any]:
    secret = str(params.get("secret", ""))
    code = str(params.get("code", ""))
    if not secret:
        raise ValueError("secret is required")
    ok = totp.verify_code(
        secret,
        code,
        digits=int(params.get("digits", 6)),
        period=int(params.get("period", 30)),
        algorithm=str(params.get("algorithm") or "SHA1"),
    )
    return {"valid": ok}


def _handle_count_owned_keys(params: dict[str, Any]) -> int:
    """Count TOTP keys owned by *owner_id* (mirrors _BuiltinTotp).

    owner_id=None counts keys with NULL owner (instance-shared).
    """
    if not ctx.db_path:
        return 0
    owner_id = params.get("owner_id")
    if owner_id is not None:
        owner_id = int(owner_id)
    return storage.count_owned_keys(ctx.db_path, owner_id)


# ── Server entry point ────────────────────────────────────────────────────


def main() -> None:
    """Register handlers and serve the JSON-RPC loop."""
    server = RpcPluginServer()
    server.set_init_handler(_handle_init)
    server.register("_migrate_db", _handle_migrate_db)
    server.register("list_keys", _handle_list_keys)
    server.register("add_key", _handle_add_key)
    server.register("update_key", _handle_update_key)
    server.register("remove_key", _handle_remove_key)
    server.register("link_key", _handle_link_key)
    server.register("claim_key", _handle_claim_key)
    server.register("share_group", _handle_share_group)
    server.register("unshare_group", _handle_unshare_group)
    server.register("import_secrets", _handle_import_secrets)
    server.register("generate_secret", _handle_generate_secret)
    server.register("generate_code", _handle_generate_code)
    server.register("verify_code", _handle_verify_code)
    server.register("count_owned_keys", _handle_count_owned_keys)
    server.serve()


if __name__ == "__main__":
    main()
