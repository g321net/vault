# 本地密钥保管箱 (Vault) — 实施计划文档

> 版本 1.3 | 2026-07-27 | 70 项测试全部通过

---

## 1. 项目概述

### 1.1 目标

构建一个本地命令行工具，用于安全存储账号密码、API 密钥、SSH 密钥等敏感信息。核心诉求：

- **防泄漏**：AES-256-GCM 加密存储，磁盘上仅有密文
- **LLM 安全调用**：支持 `vault exec` 将密钥注入子进程环境变量，明文不进 AI 上下文
- **异地备份恢复**：导出加密备份文件，可在其他机器用同一主密码恢复
- **会话免密**：解锁一次后在超时窗口内免密使用

### 1.2 适用场景

| 场景 | 方式 |
|------|------|
| 日常命令行使用 | `vault get` / `vault exec` |
| AI 助手调用（WorkBuddy / Codex / Hermes） | 终端 `vault unlock` → 聊天中 `vault exec` |
| 密钥迁移 / 灾备 | `vault export` → 复制到异地 → `vault import` |

---

## 2. 技术架构

### 2.1 技术选型

| 层次 | 技术 | 理由 |
|------|------|------|
| 语言 | Python 3.13 | 跨平台，`cryptography` 库成熟 |
| 加密 | AES-256-GCM | 认证加密，防篡改 |
| 密钥派生 | PBKDF2-SHA256 (60 万迭代) | 抗暴力破解 |
| 存储 | SQLite | 内置、零依赖、适合单机本地存储 |
| CLI | argparse | 标准库，子命令模式 |

### 2.2 文件结构

```
vault/                          # 项目目录
├── vault.py                    # CLI 入口（13 个子命令 + 配对支持）
├── vault_core.py               # 加密核心 + 会话管理 + 配置
├── vault_db.py                 # SQLite CRUD + 备份导入导出 + 配对存储
├── vault                       # Shell 快捷入口脚本
├── test_vault.py               # 端到端测试（65 项）
├── IMPLEMENTATION.md           # 本文件
├── MANUAL.md                   # 用户手册
└── requirements.txt            # 依赖声明

~/.vault/                       # 运行时数据目录（权限 700）
├── vault.db                    # SQLite 数据库（仅存密文）
├── salt                        # PBKDF2 盐值（32 字节随机）
├── config.json                 # 运行时配置（超时等）
└── .session                    # 会话缓存文件（权限 600）
```

### 2.3 数据流

```
                      ┌─────────────────┐
  用户输入              │   主密码         │
     │                 │   (仅内存)       │
     ▼                 └───────┬─────────┘
  ┌──────────┐                 │ PBKDF2-SHA256
  │  vault   │                 │ 600K 迭代
  │  unlock  │                 ▼
  └────┬─────┘         ┌──────────────┐
       │               │  AES-256 密钥 │
       ▼               │  (32 bytes)  │
  ┌──────────┐         └──────┬───────┘
  │ .session │◄───────────────┘
  │ (600 权限)│  缓存 15 分钟
  └────┬─────┘
       │ 后续命令读取会话
       ▼
  ┌──────────┐   decrypt    ┌──────────────┐
  │ vault.db │◄────────────►│ 明文（仅内存） │
  │ (仅密文) │   encrypt    └──────┬───────┘
  └──────────┘                    │ vault exec
                                  ▼
                          ┌──────────────┐
                          │ 子进程 env    │
                          │ $VAULT_VALUE │
                          └──────────────┘
```

---

## 3. 加密设计详解

### 3.1 密钥派生

```
主密码 (UTF-8 bytes)
    │
    ▼
PBKDF2-SHA256 (
    password = 主密码,
    salt     = ~/.vault/salt (32 bytes 随机, 初始化时生成),
    iterations = 600,000,
    length   = 32 bytes   # AES-256
)
    │
    ▼
AES-256-GCM 密钥
```

- 盐值存储在 `~/.vault/salt`，权限 600
- 验证令牌 `verify_token` 存储在 config.json 中：用派生密钥加密 `b"VAULT_OK"` 的结果（hex 编码），用于密码校验而不泄露明文信息

### 3.2 条目加密

每个密钥条目独立加密，使用独立的 12 字节随机 nonce：

```
encrypt(key, plaintext):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), aad=None)
    return nonce + ciphertext    # 存储到 SQLite BLOB

decrypt(key, encrypted_blob):
    nonce, ciphertext = encrypted_blob[:12], encrypted_blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad=None).decode()
```

### 3.3 备份加密

导出时所有条目重新加密打包为单个 `.vaultbak` 文件：

```
备份结构 (自定义格式):
    nonce(12) + AESGCM(key).encrypt(json(payload))

payload:
    { "version": 1,
      "exported_at": "ISO8601",
      "entries": [
          { "key": "...", "encrypted_hex": "...", "tag": "...", ... }
      ]
    }
```

### 3.4 SQLite 表结构

```sql
CREATE TABLE secrets (
    key         TEXT PRIMARY KEY NOT NULL,   -- 键名（明文，用于查找）
    encrypted   BLOB NOT NULL,              -- 加密后的值
    tag         TEXT DEFAULT '',             -- 标签（明文，用于分类）
    created_at  TEXT NOT NULL,               -- ISO8601
    updated_at  TEXT NOT NULL                -- ISO8601
);
CREATE INDEX idx_secrets_tag ON secrets(tag);
```

**注意**：键名和标签是明文存储的——这是有意为之，用户需要通过键名查找条目。敏感信息仅存在于 `encrypted` 字段中。

### 3.5 配对密钥 (Access Key ID + Secret Access Key)

AWS/阿里云/腾讯云等服务的凭证通常由一对密钥组成。vault 以 JSON 格式将配对密钥作为一个条目加密存储：

```
存储格式:
    key   = "aws_prod"
    value = encrypt(key, '{"id": "AKIA...", "secret": "wJalr..."}')

CLI:
    vault add aws_prod --pair-id AKIA... --pair-secret wJalr... -t aws
    vault get aws_prod --id       → AKIA...
    vault get aws_prod --secret   → wJalr...

exec 双注入:
    vault exec aws_prod --id-env AWS_ACCESS_KEY_ID --secret-env AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

该设计无需修改数据库 schema，利用已有的 encrypted BLOB 字段。`vault_db.py` 中的 `add_pair` / `get_pair_id` / `get_pair_secret` 负责 JSON 序列化/反序列化。

---

## 4. 会话管理

### 4.1 设计原则

- **不存储明文密钥**：会话文件存储的是派生后的 AES 密钥（32 bytes hex），而非主密码本身
- **仅基于超时**：不做 PID 检查（因为 `vault unlock` 是一次性命令，进程立即退出），纯粹依赖时间窗口
- **权限隔离**：`.session` 文件权限 600，`.vault/` 目录权限 700

### 4.2 会话生命周期

```
vault unlock
    │
    ▼
derive_key(password) → key
    │
    ▼
session_set_key(key) → 写 ~/.vault/.session { timestamp, key_hex }
    │
    ▼
  [后续命令]
    │
    ├── session_get_key() → 读 .session → 检查超时
    │       │
    │       ├── 未超时 → 返回 key → 正常执行
    │       └── 已超时 → 删除 .session → 报错 "未解锁"
    │
    ├── vault touch → 刷新 timestamp（无需密码）
    │
    ├── vault lock  → 删除 .session
    │
    └── vault config set session_timeout N → 调整超时秒数
```

### 4.3 超时配置

| 命令 | 效果 |
|------|------|
| `vault config set session_timeout 900` | 15 分钟（默认） |
| `vault config set session_timeout 28800` | 8 小时（工作会话） |
| `vault config set session_timeout 0` | 永不过期（不推荐） |
| `vault config get session_timeout` | 查看当前值 |
| `vault config unset session_timeout` | 恢复默认 |

---

## 5. CLI 命令完整清单

| 命令 | 参数 | 功能 | 需要解锁 |
|------|------|------|:--:|
| `vault init` | — | 初始化保险库，设置主密码 | — |
| `vault unlock` | — | 输入主密码解锁会话 | — |
| `vault lock` | — | 立即锁定，清除会话 | — |
| `vault touch` | — | 刷新会话时间戳 | ✓ |
| `vault chpass` | — | 更换主密码（重新加密所有条目） | ✓ |
| `vault add` | `<key> [value] [-t tag]` | 添加/更新密钥（value 可管道传入） | ✓ |
| `vault add` | `<key> --pair-id <ID> --pair-secret <S>` | 存储配对密钥 (Access Key + Secret) | ✓ |
| `vault get` | `<key> [--id\|--secret]` | 获取密钥明文（--id/--secret 提取配对字段） | ✓ |
| `vault list` | `[-t tag]` | 列出键名（无明文值） | ✓ |
| `vault search` | `<keyword>` | 模糊搜索键名 | ✓ |
| `vault delete` | `<key>` | 删除密钥 | ✓ |
| `vault exec` | `<key> [--env N] -- <cmd>` | 单密钥注入子进程 env | ✓ |
| `vault exec` | `<key> --id-env N --secret-env N -- <cmd>` | 配对密钥双注入 | ✓ |
| `vault export` | `<path>` | 导出加密备份 | ✓ |
| `vault import` | `<path> [--overwrite]` | 从备份导入 | ✓ |
| `vault config` | `get/set/unset [key] [value]` | 管理配置 | — |
| `vault status` | — | 查看状态 | — |

---

## 6. 防泄漏策略

### 6.1 分层防护

| 层级 | 措施 |
|------|------|
| 存储层 | SQLite 中 `encrypted` 字段仅存密文 |
| 传输层 | 备份文件 `.vaultbak` 全程加密 |
| 内存层 | 会话密钥仅在内存中，15 分钟过期 |
| 输出层 | `vault get` 仅输出纯值；`vault exec` 零输出密钥 |
| 日志层 | 不写入任何明文操作记录 |

### 6.2 LLM 调用场景

```bash
# ❌ 危险：密钥进入 AI 上下文
vault get github_token
# stdout: ghp_xxxxxxxxxxxx   ← AI 的上下文窗口会捕获这一行

# ✅ 安全：密钥仅存在于子进程环境变量
vault exec github_token -- gh api /user/repos
# stdout: [... 仅 gh 命令的 API 返回 ...]   ← AI 看不到 token
```

### 6.3 威胁模型

| 威胁 | 防护 |
|------|------|
| 磁盘被盗 / 文件泄露 | AES-256-GCM 加密，主密码未知则无法解密 |
| 备份文件泄露 | `.vaultbak` 同样加密 |
| LLM 会话日志泄露 | `vault exec` 确保密钥不在 stdout 中 |
| 内存 dump 攻击 | Python 进程结束后密钥随内存释放 |
| 暴力破解主密码 | PBKDF2 60 万次迭代大幅增加破解成本 |

---

## 7. 备份与灾备

### 7.1 备份流程

```
源机器                                  目标机器
  │                                       │
  ├─ vault export backup.vaultbak ──►     │  (手动传输：U盘/云盘/scp)
  │   (AES 加密，需主密码)                  │
  │                                       ├─ vault import backup.vaultbak
  │                                       │   (输入同一主密码)
  │                                       └─ ✓ 恢复完成
```

### 7.2 备份文件存储建议

- 本地：`~/backups/vault-2026-07-27.vaultbak`
- U 盘：定期手动复制
- 云盘：上传加密文件（已经是密文，云服务商无法读取）
- 多机：scp 到其他 Mac/Linux 机器

### 7.3 导入冲突策略

| 参数 | 行为 |
|------|------|
| 默认（`--skip`） | 目标已存在的 key 跳过不覆盖 |
| `--overwrite` | 目标已存在的 key 用备份覆盖 |

---

## 8. 测试覆盖

测试文件 `test_vault.py` 包含 70 项自动化测试：

| 测试组 | 项数 | 覆盖内容 |
|--------|:--:|------|
| 初始化 | 4 | init、密码验证、盐值、会话 |
| CRUD | 3 | add / get / update |
| 列表/搜索 | 6 | list、tag 筛选 |
| 标签管理 | 4 | 标签 CRUD |
| 删除 | 3 | delete、幂等性 |
| 锁定/解锁 | 2 | lock/unlock |
| 备份导出 | 4 | export、加密验证 |
| 备份导入 | 3 | import、恢复正确性 |
| 加密算法 | 3 | 往返验证、错误密钥 |
| 会话管理 | 1 | remaining |
| exec 注入（单值） | 6 | env 注入、自定义变量名、防泄漏 |
| touch 续期 | 4 | 续期、锁定后拒绝 |
| config 配置 | 6 | set/get/unset |
| 配对密钥 | 11 | add/get/exec 配对、双注入、JSON 格式 |
| 更换主密码 | 5 | re_encrypt、旧密钥失效、新密钥验证 |
| **合计** | **70** | |

运行测试：

```bash
cd vault && python3 test_vault.py
```

---

## 9. 部署方式

### 9.1 安装依赖

```bash
# 项目已安装在隔离环境
python3 -m venv /path/to/venv
pip install cryptography
```

### 9.2 配置 alias

```bash
# 添加到 ~/.zshrc 或 ~/.bashrc
alias vault='/Users/rush/WorkBuddy/本地机要室/vault/vault'
```

### 9.3 初始化

```bash
vault init
# 设置主密码（≥8 位）→ 完成
```

### 9.4 首次使用建议

```bash
vault config set session_timeout 28800  # 8 小时工作会话
```

---

## 10. 安全建议

1. **主密码**：使用 ≥ 12 位的强密码，包含大小写字母、数字、符号
2. **备份密码**：用同一主密码导出/导入，不要使用不同密码（会导致无法恢复）
3. **会话超时**：根据使用场景调整，离开电脑时手动 `vault lock`
4. **磁盘清理**：删除 `~/.vault/` 前确认备份已安全存储
5. **共享机器**：不要在共享账户下使用，每个用户应有独立的 vault 目录
6. **日志安全**：注意 shell history 中不会记录 `vault add` 的参数值（建议用管道 `echo 'secret' | vault add key` 而非命令行直接传值）
