"""
vault_db.py — SQLite 数据库操作模块

建表、CRUD、标签管理、备份导入导出
"""

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vault_core import (
    VAULT_DB,
    encrypt_value,
    decrypt_value,
    encrypt_blob,
    decrypt_blob,
    ensure_vault_dir,
    require_session_key,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS secrets (
    key         TEXT PRIMARY KEY NOT NULL,
    encrypted   BLOB NOT NULL,
    tag         TEXT DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_tag ON secrets(tag);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_conn() -> sqlite3.Connection:
    ensure_vault_dir()
    conn = sqlite3.connect(str(VAULT_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """初始化数据库表"""
    conn = _get_conn()
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def db_exists() -> bool:
    return VAULT_DB.exists()


# ─── CRUD ───────────────────────────────────────────────────

def add_secret(key_name: str, value: str, tag: str = "") -> None:
    """添加或更新密钥"""
    key = require_session_key()
    encrypted = encrypt_value(key, value)
    now = _now_iso()

    conn = _get_conn()
    existing = conn.execute(
        "SELECT created_at FROM secrets WHERE key = ?", (key_name,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE secrets SET encrypted = ?, tag = ?, updated_at = ? WHERE key = ?",
            (encrypted, tag, now, key_name),
        )
    else:
        conn.execute(
            "INSERT INTO secrets (key, encrypted, tag, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (key_name, encrypted, tag, now, now),
        )

    conn.commit()
    conn.close()


def get_secret(key_name: str) -> Optional[str]:
    """获取密钥的明文值"""
    key = require_session_key()
    conn = _get_conn()
    row = conn.execute(
        "SELECT encrypted FROM secrets WHERE key = ?", (key_name,)
    ).fetchone()
    conn.close()

    if row is None:
        return None
    return decrypt_value(key, row[0])


def list_secrets(tag: Optional[str] = None) -> list[dict]:
    """列出所有密钥（不包含明文值）"""
    require_session_key()  # 仅验证会话有效性
    conn = _get_conn()

    if tag:
        rows = conn.execute(
            "SELECT key, tag, created_at, updated_at FROM secrets WHERE tag = ? ORDER BY key",
            (tag,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT key, tag, created_at, updated_at FROM secrets ORDER BY key"
        ).fetchall()

    conn.close()
    return [
        {"key": r[0], "tag": r[1], "created_at": r[2], "updated_at": r[3]}
        for r in rows
    ]


def search_secrets(keyword: str) -> list[dict]:
    """模糊搜索键名"""
    require_session_key()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT key, tag, created_at, updated_at FROM secrets WHERE key LIKE ? ORDER BY key",
        (f"%{keyword}%",),
    ).fetchall()
    conn.close()
    return [
        {"key": r[0], "tag": r[1], "created_at": r[2], "updated_at": r[3]}
        for r in rows
    ]


def delete_secret(key_name: str) -> bool:
    """删除密钥，返回是否成功"""
    require_session_key()
    conn = _get_conn()
    cur = conn.execute("DELETE FROM secrets WHERE key = ?", (key_name,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def count_secrets() -> int:
    """返回密钥总数"""
    require_session_key()
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()
    conn.close()
    return row[0]


def get_all_tags() -> list[str]:
    """获取所有标签"""
    require_session_key()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT tag FROM secrets WHERE tag != '' ORDER BY tag"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


# ─── 配对密钥 (Access Key ID + Secret Access Key) ──────────

def add_pair(key_name: str, pair_id: str, pair_secret: str, tag: str = "") -> None:
    """存储配对密钥：内部以 JSON {id, secret} 格式加密"""
    payload = json.dumps({"id": pair_id, "secret": pair_secret})
    add_secret(key_name, payload, tag)


def get_pair_id(key_name: str) -> Optional[str]:
    """获取配对密钥的 ID 字段"""
    raw = get_secret(key_name)
    if raw is None:
        return None
    try:
        return json.loads(raw)["id"]
    except (json.JSONDecodeError, KeyError):
        return None


def get_pair_secret(key_name: str) -> Optional[str]:
    """获取配对密钥的 secret 字段"""
    raw = get_secret(key_name)
    if raw is None:
        return None
    try:
        return json.loads(raw)["secret"]
    except (json.JSONDecodeError, KeyError):
        return None


# ─── 备份导出/导入 ──────────────────────────────────────────

def export_backup(output_path: str) -> int:
    """导出加密备份到指定路径，返回导出的条目数"""
    key = require_session_key()

    conn = _get_conn()
    rows = conn.execute(
        "SELECT key, encrypted, tag, created_at, updated_at FROM secrets ORDER BY key"
    ).fetchall()
    conn.close()

    export_data = {
        "version": 1,
        "exported_at": _now_iso(),
        "entries": [
            {
                "key": r[0],
                "encrypted_hex": r[1].hex(),
                "tag": r[2],
                "created_at": r[3],
                "updated_at": r[4],
            }
            for r in rows
        ],
    }

    # 用主密钥加密整个备份
    plaintext = json.dumps(export_data, ensure_ascii=False).encode("utf-8")
    encrypted = encrypt_blob(key, plaintext)

    Path(output_path).write_bytes(encrypted)
    return len(rows)


def import_backup(input_path: str, overwrite: bool = False) -> dict:
    """
    从加密备份导入，返回导入统计
    返回 {"imported": int, "skipped": int, "errors": int}
    """
    key = require_session_key()

    encrypted = Path(input_path).read_bytes()
    try:
        plaintext = decrypt_blob(key, encrypted)
        data = json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise ValueError("无法解密备份文件，请确认主密码一致")

    if data.get("version") != 1:
        raise ValueError(f"不支持的备份版本: {data.get('version')}")

    entries = data.get("entries", [])
    stats = {"imported": 0, "skipped": 0, "errors": 0}

    conn = _get_conn()

    for entry in entries:
        try:
            key_name = entry["key"]
            encrypted_bytes = bytes.fromhex(entry["encrypted_hex"])
            tag = entry.get("tag", "")
            created_at = entry.get("created_at", _now_iso())
            updated_at = entry.get("updated_at", _now_iso())

            existing = conn.execute(
                "SELECT key FROM secrets WHERE key = ?", (key_name,)
            ).fetchone()

            if existing:
                if overwrite:
                    conn.execute(
                        "UPDATE secrets SET encrypted = ?, tag = ?, updated_at = ? WHERE key = ?",
                        (encrypted_bytes, tag, _now_iso(), key_name),
                    )
                    stats["imported"] += 1
                else:
                    stats["skipped"] += 1
            else:
                conn.execute(
                    "INSERT INTO secrets (key, encrypted, tag, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (key_name, encrypted_bytes, tag, created_at, updated_at),
                )
                stats["imported"] += 1
        except Exception:
            stats["errors"] += 1

    conn.commit()
    conn.close()
    return stats
