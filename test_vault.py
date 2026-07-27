#!/usr/bin/env python3
# Copyright (c) 2026 rush
# SPDX-License-Identifier: MIT
"""vault 端到端功能测试"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

# 确保可以导入 vault 模块
sys.path.insert(0, str(Path(__file__).parent))

from vault_core import (
    VAULT_DIR,
    SALT_PATH,
    CONFIG_PATH,
    SESSION_PATH,
    VAULT_DB,
    derive_key,
    verify_master_password,
    session_set_key,
    session_get_key,
    session_clear,
    session_refresh,
    session_remaining,
    encrypt_value,
    decrypt_value,
    encrypt_blob,
    decrypt_blob,
    load_config,
    save_config,
)
from vault_db import (
    init_db,
    add_secret,
    get_secret,
    list_secrets,
    search_secrets,
    delete_secret,
    count_secrets,
    get_all_tags,
    export_backup,
    import_backup,
    add_pair,
    get_pair_id,
    get_pair_secret,
)

TEST_PASSWORD = "test-master-pw-123"
TEST_VAULT_DIR = Path.home() / ".vault_test_backup"


def setup():
    """保存现有 vault 并创建干净的测试环境"""
    if VAULT_DIR.exists():
        if TEST_VAULT_DIR.exists():
            shutil.rmtree(TEST_VAULT_DIR)
        shutil.copytree(VAULT_DIR, TEST_VAULT_DIR)
        shutil.rmtree(VAULT_DIR)


def teardown():
    """恢复原有 vault"""
    if VAULT_DIR.exists():
        shutil.rmtree(VAULT_DIR)
    if TEST_VAULT_DIR.exists():
        shutil.copytree(TEST_VAULT_DIR, VAULT_DIR)
        shutil.rmtree(TEST_VAULT_DIR)


def run_tests():
    passed = 0
    failed = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✓ {name}")
        else:
            failed += 1
            print(f"  ✗ {name}  {detail}")

    print("=== Vault 功能测试 ===\n")

    # 1. Init
    print("1. 初始化")
    init_db()
    key = derive_key(TEST_PASSWORD)
    check("verify_master_password", verify_master_password(TEST_PASSWORD))
    check("wrong password rejected", not verify_master_password("wrong"))
    session_set_key(key)
    check("session_key 可获取", session_get_key() is not None)
    check("盐值文件存在", SALT_PATH.exists())

    # 2. Add
    print("\n2. 添加密钥")
    add_secret("github_token", "ghp_abc123def456", tag="api")
    add_secret("db_password", "P@ssw0rd!2024", tag="database")
    add_secret("ssh_key_work", "ssh-ed25519 AAAAC3...work", tag="ssh")
    check("添加 3 条", count_secrets() == 3)

    # 3. Get
    print("\n3. 获取密钥")
    val = get_secret("github_token")
    check("获取 github_token", val == "ghp_abc123def456", f"got={val}")
    val2 = get_secret("db_password")
    check("获取 db_password", val2 == "P@ssw0rd!2024", f"got={val2}")
    not_found = get_secret("nonexistent")
    check("不存在的 key 返回 None", not_found is None)

    # 4. Update
    print("\n4. 更新密钥")
    add_secret("github_token", "ghp_updated789", tag="api")
    val = get_secret("github_token")
    check("更新成功", val == "ghp_updated789", f"got={val}")
    check("总数仍为 3", count_secrets() == 3)

    # 5. List
    print("\n5. 列出密钥")
    items = list_secrets()
    check("列出 3 条", len(items) == 3)
    keys = [i["key"] for i in items]
    check("包含 github_token", "github_token" in keys)
    check("包含 db_password", "db_password" in keys)
    check("包含 ssh_key_work", "ssh_key_work" in keys)

    items_api = list_secrets(tag="api")
    check("按标签 api 筛选", len(items_api) == 1)

    items_db = list_secrets(tag="database")
    check("按标签 database 筛选", len(items_db) == 1)

    # 6. Search
    print("\n6. 搜索密钥")
    results = search_secrets("github")
    check("搜索 'github' 找到 1 条", len(results) == 1)
    results2 = search_secrets("token")
    check("搜索 'token' 找到 1 条", len(results2) == 1)

    # 7. Tags
    print("\n7. 标签管理")
    tags = get_all_tags()
    check("3 个标签", len(tags) == 3)
    check("包含 api", "api" in tags)
    check("包含 database", "database" in tags)
    check("包含 ssh", "ssh" in tags)

    # 8. Delete
    print("\n8. 删除密钥")
    check("删除 ssh_key_work 成功", delete_secret("ssh_key_work"))
    check("再次删除返回 False", not delete_secret("ssh_key_work"))
    check("剩余 2 条", count_secrets() == 2)

    # Lock 并重新 unlock
    print("\n9. 锁定/解锁")
    session_clear()
    check("锁定后无会话", session_get_key() is None)
    session_set_key(key)
    check("解锁后恢复会话", session_get_key() is not None)

    # 10. Export backup
    print("\n10. 导出备份")
    backup_path = "/tmp/vault_test_backup.vaultbak"
    count = export_backup(backup_path)
    check("导出成功", count == 2)
    check("备份文件存在", os.path.exists(backup_path))
    check("备份文件非空", os.path.getsize(backup_path) > 0)

    # 验证备份已加密（不能直接读取为 JSON）
    try:
        with open(backup_path) as f:
            data = f.read()
            json.loads(data)
        check("备份文件已加密", False, "竟然能直接解析为 JSON")
    except Exception:
        check("备份文件已加密", True)

    # 11. Delete all and import
    print("\n11. 导入恢复")
    delete_secret("github_token")
    delete_secret("db_password")
    check("删除后为空", count_secrets() == 0)

    import_backup(backup_path, overwrite=True)
    check("导入后恢复 2 条", count_secrets() == 2)
    val = get_secret("github_token")
    check("恢复后值正确", val == "ghp_updated789", f"got={val}")

    # Cleanup backup
    os.remove(backup_path)

    # 12. 加密正确性验证
    print("\n12. 加密正确性")
    original = "Hello, 世界! 🔐 Secret"
    enc = encrypt_value(key, original)
    dec = decrypt_value(key, enc)
    check("加密往返正确", dec == original)

    # Blob 加密
    blob = b"binary data \x00\x01\x02 test"
    enc_b = encrypt_blob(key, blob)
    dec_b = decrypt_blob(key, enc_b)
    check("Blob 加密往返正确", dec_b == blob)

    # 不同密钥不能解密
    wrong_key = derive_key("wrong-password")
    try:
        decrypt_value(wrong_key, enc)
        check("错误密钥应解密失败", False)
    except Exception:
        check("错误密钥解密失败", True)

    # 13. 会话
    print("\n13. 会话管理")
    session_set_key(key)
    check("session_remaining > 0", session_remaining() > 0)

    # 14. exec — 密钥注入子进程
    print("\n14. exec 子进程注入")
    import subprocess as sp
    add_secret("test_exec_key", "my-super-secret-token", tag="test")

    # 用 vault exec 运行一个打印环境变量的命令
    vault_py = str(Path(__file__).parent / "vault.py")
    python = "/Users/rush/.workbuddy/binaries/python/envs/vault/bin/python3"
    result = sp.run(
        [python, vault_py, "exec", "test_exec_key", "--", "sh", "-c", "echo $VAULT_VALUE"],
        capture_output=True, text=True,
    )
    check("exec: 子进程收到 VAULT_VALUE", result.stdout.strip() == "my-super-secret-token",
          f"got={result.stdout.strip()}")
    check("exec: stderr 无错误", result.stderr.strip() == "",
          f"stderr={result.stderr.strip()}")
    check("exec: exit code=0", result.returncode == 0,
          f"exit={result.returncode}")

    # 自定义 env var name
    result2 = sp.run(
        [python, vault_py, "exec", "test_exec_key", "--env", "MY_TOKEN", "--", "sh", "-c", "echo $MY_TOKEN"],
        capture_output=True, text=True,
    )
    check("exec: 自定义 env 名", result2.stdout.strip() == "my-super-secret-token")

    # vault exec 自身的 stdout 不应该包含密钥明文
    result3 = sp.run(
        [python, vault_py, "exec", "test_exec_key", "--", "echo", "hello"],
        capture_output=True, text=True,
    )
    check("exec: vault 自身 stdout 不含密钥", "my-super-secret-token" not in result3.stdout)
    check("exec: 子命令 stdout 正常", result3.stdout.strip() == "hello")

    delete_secret("test_exec_key")

    # 15. touch — 会话续期
    print("\n15. touch 会话续期")
    session_set_key(key)
    old_remaining = session_remaining()
    import time as _time
    _time.sleep(1)
    session_refresh()
    new_remaining = session_remaining()
    check("touch: 续期后剩余时间 ≥ 旧值", new_remaining >= old_remaining - 1)

    # 测试 vault touch CLI
    result4 = sp.run(
        [python, vault_py, "touch"],
        capture_output=True, text=True,
    )
    check("touch CLI: exit 0", result4.returncode == 0)
    check("touch CLI: 输出含'续期'", "续期" in result4.stdout)

    # 锁定后 touch 应失败
    session_clear()
    result5 = sp.run(
        [python, vault_py, "touch"],
        capture_output=True, text=True,
    )
    check("touch CLI: 锁定后失败", result5.returncode != 0)
    session_set_key(key)

    # 16. config — 配置管理
    print("\n16. config 配置管理")
    # set
    result6 = sp.run(
        [python, vault_py, "config", "set", "session_timeout", "3600"],
        capture_output=True, text=True,
    )
    check("config set: exit 0", result6.returncode == 0)
    config = load_config()
    check("config set: session_timeout=3600", config.get("session_timeout") == 3600)

    # get specific
    result7 = sp.run(
        [python, vault_py, "config", "get", "session_timeout"],
        capture_output=True, text=True,
    )
    check("config get: 输出 3600", result7.stdout.strip() == "3600")

    # get all
    result8 = sp.run(
        [python, vault_py, "config", "get"],
        capture_output=True, text=True,
    )
    check("config get all: 包含 session_timeout", "session_timeout" in result8.stdout)

    # unset
    result9 = sp.run(
        [python, vault_py, "config", "unset", "session_timeout"],
        capture_output=True, text=True,
    )
    check("config unset: exit 0", result9.returncode == 0)
    config = load_config()
    check("config unset: 已删除", "session_timeout" not in config)

    # 17. Pair — 配对密钥 (Access Key ID + Secret Access Key)
    print("\n17. 配对密钥")
    add_pair("aws_test", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", tag="aws")
    check("pair: add 成功", count_secrets() == 3)  # 2 from before + 1 pair

    id_val = get_pair_id("aws_test")
    secret_val = get_pair_secret("aws_test")
    check("pair: get_id", id_val == "AKIAIOSFODNN7EXAMPLE")
    check("pair: get_secret", secret_val == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    # get --id / --secret via CLI
    r_id = sp.run([python, vault_py, "get", "aws_test", "--id"], capture_output=True, text=True)
    check("pair CLI: get --id", r_id.stdout.strip() == "AKIAIOSFODNN7EXAMPLE")
    r_sec = sp.run([python, vault_py, "get", "aws_test", "--secret"], capture_output=True, text=True)
    check("pair CLI: get --secret", r_sec.stdout.strip() == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    # exec with pair
    r_exec = sp.run(
        [python, vault_py, "exec", "aws_test",
         "--id-env", "AWS_ACCESS_KEY_ID",
         "--secret-env", "AWS_SECRET_ACCESS_KEY",
         "--", "sh", "-c", "echo ID=$AWS_ACCESS_KEY_ID SECRET=$AWS_SECRET_ACCESS_KEY"],
        capture_output=True, text=True,
    )
    check("pair exec: ID set", "ID=AKIAIOSFODNN7EXAMPLE" in r_exec.stdout)
    check("pair exec: Secret set", "SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in r_exec.stdout)
    check("pair exec: exit 0", r_exec.returncode == 0)

    # --pair-id/--pair-secret via CLI add
    r_add = sp.run(
        [python, vault_py, "add", "gcp_key", "--pair-id", "GCP-ID-123", "--pair-secret", "gcp-secret-456", "-t", "gcp"],
        capture_output=True, text=True,
    )
    check("pair CLI: add via --pair-id/--pair-secret", r_add.returncode == 0)
    check("pair CLI: stored correctly", get_pair_id("gcp_key") == "GCP-ID-123")

    # get without --id on pair returns JSON
    raw = get_secret("aws_test")
    check("pair: raw value is JSON", raw and "AKIAIOSFODNN7EXAMPLE" in raw)

    delete_secret("aws_test")
    delete_secret("gcp_key")

    # 18. chpass — 更换主密码
    print("\n18. 更换主密码")
    from vault_db import re_encrypt_all
    add_secret("chpass_test", "secret-before-chpass", tag="test")
    val_before = get_secret("chpass_test")
    check("chpass: 改密码前可读", val_before == "secret-before-chpass")

    old_key = derive_key(TEST_PASSWORD)
    NEW_PASSWORD = "new-master-password-456"
    new_key = derive_key(NEW_PASSWORD)
    count = re_encrypt_all(old_key, new_key)
    check("chpass: re_encrypt 3 条", count == 3)

    config = load_config()
    config["verify_token"] = encrypt_value(new_key, "VAULT_OK").hex()
    save_config(config)

    # 旧密钥应无法解密
    try:
        get_secret("chpass_test")
        check("chpass: 旧密钥解密失败", False)
    except Exception:
        check("chpass: 旧密钥解密失败", True)

    # 用新密钥重新会话，验证可读
    session_set_key(new_key)
    val_after = get_secret("chpass_test")
    check("chpass: 新密钥可读", val_after == "secret-before-chpass")
    check("chpass: 新密码验证通过", verify_master_password(NEW_PASSWORD))

    delete_secret("chpass_test")
    # 恢复原始密钥用于后续测试清理
    re_encrypt_all(new_key, old_key)
    config = load_config()
    config["verify_token"] = encrypt_value(old_key, "VAULT_OK").hex()
    save_config(config)
    session_set_key(old_key)

    # 19. recovery key — 恢复密钥
    print("\n19. 恢复密钥")
    from vault_core import generate_recovery_key, store_recovery_key, recover_session_key, has_recovery_key

    recovery_key = generate_recovery_key()
    check("recovery: 生成 64 字符 hex", len(recovery_key) == 64)

    store_recovery_key(old_key, recovery_key)
    check("recovery: has_recovery_key", has_recovery_key())

    recovered = recover_session_key(recovery_key)
    check("recovery: 恢复的 key 等于原 key", recovered == old_key)

    # 错误恢复密钥应失败
    wrong_recovery = "00" * 32
    try:
        recover_session_key(wrong_recovery)
        check("recovery: 错误密钥应失败", False)
    except Exception:
        check("recovery: 错误密钥失败", True)

    # 用恢复密钥解锁后可以正常用
    session_set_key(recovered)
    val = get_secret("github_token")
    check("recovery: 恢复后可读密钥", val == "ghp_updated789")

    # 清理 recovery_payload
    config = load_config()
    del config["recovery_payload"]
    save_config(config)
    session_set_key(old_key)

    print(f"\n{'='*40}")
    print(f"结果: {passed} 通过, {failed} 失败")
    return failed == 0


if __name__ == "__main__":
    setup()
    try:
        success = run_tests()
    finally:
        teardown()
    sys.exit(0 if success else 1)
