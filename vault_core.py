# Copyright (c) 2026 rush
# SPDX-License-Identifier: MIT
"""
vault_core.py — 核心加密、会话、配置模块

安全设计:
- PBKDF2-SHA256 (600K iterations) 派生 AES-256-GCM 密钥
- 每个条目独立加密（独立 IV/nonce）
- 会话密钥缓存在 ~/.vault/.session（600 权限，超时自动失效）
"""

import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ─── 路径常量 ───────────────────────────────────────────────
_VAULT_HOME = os.environ.get("VAULT_HOME", str(Path.home() / ".vault"))
VAULT_DIR = Path(_VAULT_HOME)
SALT_PATH = VAULT_DIR / "salt"
CONFIG_PATH = VAULT_DIR / "config.json"
SESSION_PATH = VAULT_DIR / ".session"
VAULT_DB = VAULT_DIR / "vault.db"

PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32  # AES-256
SESSION_TIMEOUT_DEFAULT = 15 * 60  # 15 分钟


def ensure_vault_dir() -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    # 这个目录存储敏感信息元数据，权限应限制为仅所有者
    VAULT_DIR.chmod(0o700)


# ─── 配置管理 ───────────────────────────────────────────────

def load_config() -> dict:
    ensure_vault_dir()
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict) -> None:
    ensure_vault_dir()
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ─── 盐值管理 ───────────────────────────────────────────────

def get_or_create_salt() -> bytes:
    ensure_vault_dir()
    if SALT_PATH.exists():
        return SALT_PATH.read_bytes()
    salt = os.urandom(32)
    SALT_PATH.write_bytes(salt)
    SALT_PATH.chmod(0o600)
    return salt


# ─── 密钥派生 ───────────────────────────────────────────────

def derive_key(master_password: str, salt: Optional[bytes] = None) -> bytes:
    """从主密码派生 AES-256 密钥"""
    if salt is None:
        salt = get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode("utf-8"))


def verify_master_password(password: str) -> bool:
    """通过尝试解密验证盐值来检测密码是否正确"""
    salt = get_or_create_salt()
    try:
        key = derive_key(password, salt)
        # 用派生密钥加密一段已知明文，存储标记
        config = load_config()
        if "verify_token" not in config:
            # 首次初始化：创建验证令牌
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            token = aesgcm.encrypt(nonce, b"VAULT_OK", None)
            config["verify_token"] = (nonce + token).hex()
            save_config(config)
            return True
        # 验证已有令牌
        data = bytes.fromhex(config["verify_token"])
        nonce, token = data[:12], data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, token, None)
        return plaintext == b"VAULT_OK"
    except Exception:
        return False


# ─── AES-256-GCM 加解密 ─────────────────────────────────────

def encrypt_value(key: bytes, plaintext: str) -> bytes:
    """加密单个值，返回 nonce(12) + ciphertext"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_value(key: bytes, encrypted: bytes) -> str:
    """解密单个值，输入 nonce(12) + ciphertext"""
    nonce, ciphertext = encrypted[:12], encrypted[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt_blob(key: bytes, data: bytes) -> bytes:
    """加密二进制数据块，返回 nonce(12) + ciphertext"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_blob(key: bytes, encrypted: bytes) -> bytes:
    """解密二进制数据块"""
    nonce, ciphertext = encrypted[:12], encrypted[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─── 会话管理 ───────────────────────────────────────────────

def session_get_key() -> Optional[bytes]:
    """从会话文件读取派生密钥，检查是否有效且未超时"""
    if not SESSION_PATH.exists():
        return None

    try:
        data = json.loads(SESSION_PATH.read_text())
        timestamp = data.get("timestamp", 0)
        key_hex = data.get("key", "")

        # 检查超时（只依赖时间，不做 PID 检查——vault unlock 是一次性命令，进程已退出）
        config = load_config()
        timeout = config.get("session_timeout", SESSION_TIMEOUT_DEFAULT)
        if time.time() - timestamp > timeout:
            session_clear()
            return None

        return bytes.fromhex(key_hex)
    except Exception:
        session_clear()
        return None


def session_set_key(key: bytes) -> None:
    """保存派生密钥到会话文件"""
    ensure_vault_dir()
    data = {
        "pid": os.getpid(),
        "timestamp": int(time.time()),
        "key": key.hex(),
    }
    SESSION_PATH.write_text(json.dumps(data))
    SESSION_PATH.chmod(0o600)


def session_clear() -> None:
    """清除会话文件"""
    if SESSION_PATH.exists():
        SESSION_PATH.unlink()


def session_refresh() -> None:
    """刷新会话时间戳"""
    key = session_get_key()
    if key:
        session_set_key(key)


def session_remaining() -> int:
    """返回剩余有效秒数"""
    if not SESSION_PATH.exists():
        return 0
    try:
        data = json.loads(SESSION_PATH.read_text())
        config = load_config()
        timeout = config.get("session_timeout", SESSION_TIMEOUT_DEFAULT)
        elapsed = time.time() - data.get("timestamp", 0)
        remaining = int(timeout - elapsed)
        return max(0, remaining)
    except Exception:
        return 0


def require_session_key() -> bytes:
    """获取会话密钥，若未解锁则报错退出"""
    key = session_get_key()
    if key is None:
        print("错误: 保险库未解锁，请先执行 vault unlock", file=sys.stderr)
        sys.exit(1)
    return key


def _process_exists(pid: int) -> bool:
    """检查指定 PID 的进程是否存在"""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


# ─── 恢复密钥 ───────────────────────────────────────────────

def generate_recovery_key() -> str:
    """生成 32 字节随机恢复密钥，返回 hex 字符串（64 字符）"""
    return os.urandom(32).hex()


def store_recovery_key(aes_key: bytes, recovery_key_hex: str) -> None:
    """用恢复密钥加密 AES 密钥并存入 config.json"""
    recovery_key_bytes = bytes.fromhex(recovery_key_hex)
    encrypted = encrypt_blob(recovery_key_bytes, aes_key)
    config = load_config()
    config["recovery_payload"] = encrypted.hex()
    save_config(config)


def recover_session_key(recovery_key_hex: str) -> bytes:
    """用恢复密钥解密 AES 密钥，返回可用于会话的 key"""
    recovery_key_bytes = bytes.fromhex(recovery_key_hex)
    config = load_config()
    payload = config.get("recovery_payload")
    if not payload:
        raise ValueError("未设置恢复密钥，请先 vault init")
    encrypted = bytes.fromhex(payload)
    aes_key = decrypt_blob(recovery_key_bytes, encrypted)
    return aes_key


def has_recovery_key() -> bool:
    """检查是否已设置恢复密钥"""
    config = load_config()
    return "recovery_payload" in config
