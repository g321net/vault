# 🔐 Vault — 本地密钥保管箱

安全存储账号密码、API 密钥、SSH Key，支持 AI 助手免密调用，密钥不泄漏。

[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-65%20passed-brightgreen)](test_vault.py)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 为什么需要它？

在 AI 助手中使用 API Token 时，密钥会出现在对话上下文里。一旦会话日志泄漏，密钥也随之暴露。

Vault 通过 `vault exec` 将密钥注入子进程的**环境变量**，明文不经过 stdout，AI 永远看不到密钥值。

```
vault exec github_token -- gh api /user/repos
         │                         │
         ▼                         ▼
   密钥解密为 env var        只有 gh 的输出进入上下文
   $VAULT_VALUE=ghp_xxx     AI 看不到 ghp_xxx
```

## 快速开始

```bash
# 安装
git clone git@github.com:g321net/vault.git
cd vault
pip install -r requirements.txt
alias vault="$(pwd)/vault"

# 初始化
vault init                        # 设置主密码（≥8 位）

# 解锁（会话免密 15 分钟）
vault unlock

# 存储密钥
vault add github_token ghp_xxx -t api
vault add aws_prod --pair-id AKIA... --pair-secret wJalr... -t aws

# 安全使用 — 密钥不进 stdout
vault exec github_token -- gh pr list
vault exec aws_prod --id-env AWS_ACCESS_KEY_ID --secret-env AWS_SECRET_ACCESS_KEY -- aws s3 ls

# 获取密钥（谨慎使用）
vault get github_token            # 仅输出值，无前缀
vault get aws_prod --id           # 配对密钥提取单个字段

# 备份
vault export backup.vaultbak      # AES 加密，可放云盘
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `init` | 初始化保险库 |
| `unlock` / `lock` / `touch` | 解锁 / 锁定 / 续期会话 |
| `add <k> <v> [-t tag]` | 添加密钥 |
| `add <k> --pair-id <id> --pair-secret <s>` | 添加配对密钥 |
| `get <k> [--id\|--secret]` | 获取明文 |
| `list [-t tag]` / `search <kw>` | 列表 / 搜索 |
| `delete <k>` | 删除密钥 |
| `exec <k> [--id-env N] [--secret-env N] -- <cmd>` | 安全调用 |
| `export <path>` / `import <path>` | 加密备份 / 恢复 |
| `config set/get/unset` | 配置管理 |
| `status` | 查看状态 |

## 在 AI 助手中使用（WorkBuddy / Codex / Hermes）

```bash
# 1. 聊天开始前，终端解锁一次
vault unlock
vault config set session_timeout 28800   # 设为 8 小时

# 2. 聊天中直接让 AI 调用，密钥不会进入上下文
# AI 执行: vault exec github_token -- gh pr list
# AI 执行: vault exec openai_key --env OPENAI_API_KEY -- curl ...

# 3. 超时前 AI 可主动续期
# AI 执行: vault touch
```

## 安全设计

- **AES-256-GCM** 认证加密，每个条目独立 nonce
- **PBKDF2-SHA256** 60 万次迭代派生密钥，抗暴力破解
- **SQLite 仅存密文**，键名/标签明文（便于查找），值全加密
- **备份也加密**：`.vaultbak` 文件可直接上传云盘
- **会话超时**：默认 15 分钟自动锁定，可配置

## 文档

- [使用说明书](MANUAL.md) — 日常操作、AI 集成、备份恢复
- [实施计划文档](IMPLEMENTATION.md) — 架构设计、加密流程、安全分析

## 运行测试

```bash
cd vault && python3 test_vault.py
# 65 项测试全部通过
```
