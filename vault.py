#!/usr/bin/env python3
# Copyright (c) 2026 rush
# SPDX-License-Identifier: MIT
"""
vault — 本地密钥保管箱

安全存储账号密码/密钥，LLM 友好命令行接口。
数据 AES-256-GCM 加密，会话免密模式，支持加密备份异地恢复。
支持配对密钥 (Access Key ID + Secret Access Key)。

用法:
  vault init                    初始化保险库
  vault unlock                  解锁保险库
  vault lock                    锁定保险库
  vault add <key> <value> [-t tag]  添加/更新密钥
  vault add <key> --pair-id <ID> --pair-secret <Secret>  添加配对密钥
  vault get <key> [--id|--secret]   获取密钥明文
  vault list [-t tag]           列出所有密钥
  vault search <kw>             模糊搜索
  vault delete <key>            删除密钥
  vault exec <key> [--id-env N] [--secret-env N] -- <cmd>  密钥注入
  vault export <path>           导出加密备份
  vault import <path> [--overwrite|--skip]  导入备份
  vault touch                   刷新会话
  vault config set/get/unset    管理配置
  vault status                  查看状态
"""

import argparse
import getpass
import os
import shlex
import subprocess
import sys
from pathlib import Path

from vault_core import (
    VAULT_DIR,
    derive_key,
    verify_master_password,
    session_set_key,
    session_get_key,
    session_clear,
    session_refresh,
    session_remaining,
    load_config,
    save_config,
    ensure_vault_dir,
)
from vault_db import (
    init_db,
    db_exists,
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


def cmd_init() -> None:
    if db_exists():
        print("保险库已初始化，如需重置请删除 ~/.vault/ 目录")
        sys.exit(1)

    print("=== 初始化密钥保管箱 ===")
    password = getpass.getpass("设置主密码: ")
    if len(password) < 8:
        print("错误: 主密码长度至少 8 位", file=sys.stderr)
        sys.exit(1)
    confirm = getpass.getpass("确认主密码: ")
    if password != confirm:
        print("错误: 两次输入的密码不一致", file=sys.stderr)
        sys.exit(1)

    ensure_vault_dir()
    init_db()
    key = derive_key(password)
    verify_master_password(password)
    session_set_key(key)
    print("✓ 保险库初始化成功")
    print(f"  数据目录: {VAULT_DIR}")


def cmd_unlock() -> None:
    if not db_exists():
        print("错误: 保险库未初始化，请先执行 vault init", file=sys.stderr)
        sys.exit(1)

    if session_get_key():
        remaining = session_remaining()
        print(f"保险库已解锁 (剩余 {remaining // 60} 分 {remaining % 60} 秒)")
        return

    password = getpass.getpass("主密码: ")
    if not verify_master_password(password):
        print("错误: 主密码不正确", file=sys.stderr)
        sys.exit(1)

    key = derive_key(password)
    session_set_key(key)
    print("✓ 保险库已解锁 (15 分钟超时)")


def cmd_lock() -> None:
    session_clear()
    print("✓ 保险库已锁定")


def cmd_add(args) -> None:
    # 配对模式
    if args.pair_id and args.pair_secret:
        add_pair(args.key, args.pair_id, args.pair_secret, args.tag or "")
        print(f"✓ 已保存配对密钥: {args.key}")
        return

    if args.value is None and not sys.stdin.isatty():
        args.value = sys.stdin.read().strip()

    if not args.value:
        print("错误: 请提供密钥值，或通过管道传入", file=sys.stderr)
        print("用法: vault add <key> <value> 或 echo 'secret' | vault add <key>", file=sys.stderr)
        print("配对: vault add <key> --pair-id <ID> --pair-secret <Secret>", file=sys.stderr)
        sys.exit(1)

    add_secret(args.key, args.value, args.tag or "")
    print(f"✓ 已保存: {args.key}")


def cmd_get(args) -> None:
    if args.id:
        value = get_pair_id(args.key)
    elif args.secret:
        value = get_pair_secret(args.key)
    else:
        value = get_secret(args.key)

    if value is None:
        print(f"错误: 未找到密钥 '{args.key}'", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(value)
    sys.stdout.flush()


def cmd_list(args) -> None:
    items = list_secrets(args.tag)
    if not items:
        tag_info = f" (标签: {args.tag})" if args.tag else ""
        print(f"保险库为空{tag_info}")
        return

    print(f"{'KEY':<30} {'TAG':<15} {'UPDATED':<20}")
    print("-" * 65)
    for item in items:
        print(f"{item['key']:<30} {item['tag']:<15} {item['updated_at'][:19]:<20}")
    print(f"\n共 {len(items)} 条")


def cmd_search(args) -> None:
    items = search_secrets(args.keyword)
    if not items:
        print(f"未找到匹配 '{args.keyword}' 的密钥")
        return

    print(f"{'KEY':<30} {'TAG':<15} {'UPDATED':<20}")
    print("-" * 65)
    for item in items:
        print(f"{item['key']:<30} {item['tag']:<15} {item['updated_at'][:19]:<20}")
    print(f"\n共 {len(items)} 条")


def cmd_delete(args) -> None:
    if delete_secret(args.key):
        print(f"✓ 已删除: {args.key}")
    else:
        print(f"未找到密钥: {args.key}", file=sys.stderr)
        sys.exit(1)


def cmd_export(args) -> None:
    count = export_backup(args.path)
    print(f"✓ 已导出 {count} 条密钥到: {args.path}")
    print("  该文件已加密，可用 vault import 恢复")


def cmd_import(args) -> None:
    overwrite = args.overwrite
    try:
        stats = import_backup(args.path, overwrite=overwrite)
        print(f"✓ 导入完成: 新增 {stats['imported']} 条, 跳过 {stats['skipped']} 条, 错误 {stats['errors']} 条")
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


def _parse_exec_cmd(args) -> tuple:
    """Parse cmd_parts from REMAINDER, extracting --env, --id-env, --secret-env.
    Returns (cmd_parts, env_name, id_env_name, secret_env_name)."""
    if not args.cmd:
        print("错误: 请提供要执行的命令 (-- 之后)", file=sys.stderr)
        sys.exit(1)

    cmd_parts = list(args.cmd)
    env_name = args.env or "VAULT_VALUE"
    id_env_name = args.id_env
    secret_env_name = args.secret_env

    # Extract env flags that were not parsed by argparse (consumed by REMAINDER)
    while cmd_parts and cmd_parts[0] in ("--env", "--id-env", "--secret-env"):
        flag = cmd_parts.pop(0)
        if cmd_parts:
            if flag == "--env":
                env_name = cmd_parts.pop(0)
            elif flag == "--id-env":
                id_env_name = cmd_parts.pop(0)
            elif flag == "--secret-env":
                secret_env_name = cmd_parts.pop(0)

    if cmd_parts and cmd_parts[0] == "--":
        cmd_parts.pop(0)

    if not cmd_parts:
        print("错误: 请提供要执行的命令 (-- 之后)", file=sys.stderr)
        sys.exit(1)

    return cmd_parts, env_name, id_env_name, secret_env_name


def cmd_exec(args) -> None:
    # Parse cmd parts (extracts --env, --id-env, --secret-env from REMAINDER)
    cmd_parts, env_name, id_env_name, secret_env_name = _parse_exec_cmd(args)

    # Pair mode: inject both id and secret as env vars
    if id_env_name or secret_env_name:
        id_val = get_pair_id(args.key)
        secret_val = get_pair_secret(args.key)
        if id_val is None and secret_val is None:
            print(f"错误: 未找到配对密钥 '{args.key}'", file=sys.stderr)
            sys.exit(1)

        env = os.environ.copy()
        if id_env_name and id_val:
            env[id_env_name] = id_val
        if secret_env_name and secret_val:
            env[secret_env_name] = secret_val

        cmd_str = shlex.join(cmd_parts)
        proc = subprocess.run(cmd_str, shell=True, env=env)
        sys.exit(proc.returncode)

    # Single value mode
    value = get_secret(args.key)
    if value is None:
        print(f"错误: 未找到密钥 '{args.key}'", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env[env_name] = value

    cmd_str = shlex.join(cmd_parts)
    proc = subprocess.run(cmd_str, shell=True, env=env)
    sys.exit(proc.returncode)


def cmd_status() -> None:
    if not db_exists():
        print("保险库: 未初始化")
        return

    key = session_get_key()
    if key:
        remaining = session_remaining()
        status = f"已解锁 (剩余 {remaining // 60} 分 {remaining % 60} 秒)"
    else:
        status = "已锁定"

    count = count_secrets()
    tags = get_all_tags()
    config = load_config()
    timeout = config.get("session_timeout", 900)

    print(f"保险库: {status}")
    print(f"数据目录: {VAULT_DIR}")
    print(f"密钥总数: {count}")
    print(f"超时设置: {timeout} 秒 ({timeout // 60} 分钟)")
    if tags:
        print(f"标签: {', '.join(tags)}")


def cmd_touch() -> None:
    if not session_get_key():
        print("错误: 保险库未解锁，请先执行 vault unlock", file=sys.stderr)
        sys.exit(1)
    session_refresh()
    remaining = session_remaining()
    print(f"✓ 会话已续期 (剩余 {remaining // 60} 分 {remaining % 60} 秒)")


def cmd_config(args) -> None:
    if args.config_cmd == "get":
        config = load_config()
        if args.key:
            print(config.get(args.key, ""))
        else:
            for k, v in config.items():
                if k != "verify_token":
                    print(f"{k} = {v}")
    elif args.config_cmd == "set":
        if not args.key or args.value is None:
            print("用法: vault config set <key> <value>", file=sys.stderr)
            sys.exit(1)
        config = load_config()
        try:
            config[args.key] = int(args.value)
        except ValueError:
            config[args.key] = args.value
        save_config(config)
        print(f"✓ {args.key} = {config[args.key]}")
    elif args.config_cmd == "unset":
        if not args.key:
            print("用法: vault config unset <key>", file=sys.stderr)
            sys.exit(1)
        config = load_config()
        if args.key in config:
            del config[args.key]
            save_config(config)
            print(f"✓ 已删除: {args.key}")
        else:
            print(f"配置项不存在: {args.key}")


def main():
    parser = argparse.ArgumentParser(
        description="本地密钥保管箱 — 安全存储账号密码/密钥",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  vault init                      初始化
  vault unlock                    解锁
  vault add my_api sk-xxxxx -t api   添加密钥
  vault add aws --pair-id AKIA... --pair-secret wJalr... -t aws  添加配对
  vault get my_api                获取密钥
  vault get aws --id              获取 Access Key ID
  vault list -t api               按标签列出
  vault search token              模糊搜索
  vault exec my_api -- curl ...   密钥注入，明文不出现
  vault exec aws --id-env AWS_ACCESS_KEY_ID --secret-env AWS_SECRET_ACCESS_KEY -- aws s3 ls
  vault export backup.vaultbak    导出加密备份
  vault import backup.vaultbak    导入恢复
  vault touch                     刷新会话
  vault lock                      锁定
""",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="初始化保险库")
    sub.add_parser("unlock", help="解锁保险库")
    sub.add_parser("lock", help="锁定保险库")

    p_add = sub.add_parser("add", help="添加/更新密钥")
    p_add.add_argument("key", help="密钥名称")
    p_add.add_argument("value", nargs="?", default=None, help="密钥值（也可通过管道 stdin 传入）")
    p_add.add_argument("-t", "--tag", default="", help="标签")
    p_add.add_argument("--pair-id", default=None, help="配对密钥 ID（与 --pair-secret 一起使用）")
    p_add.add_argument("--pair-secret", default=None, help="配对密钥 Secret（与 --pair-id 一起使用）")

    p_get = sub.add_parser("get", help="获取密钥明文（仅输出值）")
    p_get.add_argument("key", help="密钥名称")
    p_get.add_argument("--id", action="store_true", help="获取配对密钥的 ID 字段")
    p_get.add_argument("--secret", action="store_true", help="获取配对密钥的 secret 字段")

    p_list = sub.add_parser("list", help="列出所有密钥")
    p_list.add_argument("-t", "--tag", default=None, help="按标签筛选")

    p_search = sub.add_parser("search", help="模糊搜索密钥名")
    p_search.add_argument("keyword", help="搜索关键词")

    p_del = sub.add_parser("delete", help="删除密钥")
    p_del.add_argument("key", help="密钥名称")

    p_exp = sub.add_parser("export", help="导出加密备份")
    p_exp.add_argument("path", help="备份文件路径")

    p_imp = sub.add_parser("import", help="导入加密备份")
    p_imp.add_argument("path", help="备份文件路径")
    p_imp.add_argument("--overwrite", action="store_true", help="冲突时覆盖已有密钥")
    p_imp.add_argument("--skip", action="store_true", default=True, help="冲突时跳过（默认）")

    p_exec = sub.add_parser("exec", help="以环境变量注入密钥执行命令")
    p_exec.add_argument("key", help="密钥名称")
    p_exec.add_argument("--env", default="VAULT_VALUE", help="单值模式的环境变量名")
    p_exec.add_argument("--id-env", default=None, help="配对模式: ID 的环境变量名")
    p_exec.add_argument("--secret-env", default=None, help="配对模式: Secret 的环境变量名")
    p_exec.add_argument("cmd", nargs=argparse.REMAINDER, help="要执行的命令 (-- 之后)")

    sub.add_parser("touch", help="刷新会话时间戳（无需密码）")

    p_config = sub.add_parser("config", help="管理配置")
    p_config_sub = p_config.add_subparsers(dest="config_cmd")
    p_config_sub.add_parser("get", help="查看配置").add_argument("key", nargs="?", default=None, help="配置项名")
    p_config_set = p_config_sub.add_parser("set", help="设置配置")
    p_config_set.add_argument("key", help="配置项名")
    p_config_set.add_argument("value", help="配置值")
    p_config_sub.add_parser("unset", help="删除配置").add_argument("key", help="配置项名")

    sub.add_parser("status", help="查看保险库状态")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "init": cmd_init,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "add": lambda: cmd_add(args),
        "get": lambda: cmd_get(args),
        "list": lambda: cmd_list(args),
        "search": lambda: cmd_search(args),
        "delete": lambda: cmd_delete(args),
        "export": lambda: cmd_export(args),
        "import": lambda: cmd_import(args),
        "exec": lambda: cmd_exec(args),
        "touch": cmd_touch,
        "config": lambda: cmd_config(args),
        "status": cmd_status,
    }

    fn = commands.get(args.command)
    if fn:
        fn()
    else:
        print(f"未知命令: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
