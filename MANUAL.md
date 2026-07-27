# Vault — 密钥保管箱使用说明书

> 安全存储你的 API 密钥、数据库密码、SSH Key，支持 AI 助手免密调用，密钥不泄漏。

---

## 快速开始

### 1. 安装（配置 alias）

在终端执行一次，之后就能用 `vault` 命令了：

```bash
echo "alias vault='/Users/rush/WorkBuddy/本地机要室/vault/vault'" >> ~/.zshrc
source ~/.zshrc
```

### 2. 初始化

```bash
vault init
```

按提示设置**主密码**（≥8 位，这是加密所有密钥的唯一钥匙，**请务必记住**）。

### 3. 解锁

```bash
vault unlock
# 输入主密�� → 解锁 15 分钟
```

### 4. 保存第一个密钥

```bash
vault add github_token ghp_abc123def456 -t api
# ✓ 已保存: github_token
```

### 5. 使用密钥

```bash
# 方式 1：输出到终端
vault get github_token
# ghp_abc123def456

# 方式 2：注入子进程（推荐，安全）
vault exec github_token -- gh api /user
```

---

## 日常使用

### 存储密钥

```bash
# 基本用法
vault add openai_key sk-proj-xxxxx -t api

# 管道传入（避免 shell history 记录明文）
echo 'P@ssw0rd!2024' | vault add db_password -t database

# SSH 密钥也可以存（包括换行）
cat ~/.ssh/id_ed25519 | vault add ssh_key_work -t ssh

# 更新已有密钥
vault add openai_key sk-new-key-xxxxx -t api

# 配对密钥（Access Key ID + Secret Access Key）
vault add aws_prod --pair-id AKIAIOSFODNN7EXAMPLE --pair-secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY -t aws
```

### 列出和搜索

```bash
# 列出所有
vault list
# KEY                            TAG             UPDATED
# db_password                    database        2026-07-27T10:00:00
# github_token                   api             2026-07-27T10:00:00
# openai_key                     api             2026-07-27T10:00:00

# 按标签筛选
vault list -t api

# 模糊搜索
vault search token

# 配对密钥：分别获取 ID 和 Secret
vault get aws_prod --id       # 仅输出 Access Key ID
vault get aws_prod --secret   # 仅输出 Secret Access Key
```

### 安全使用（密钥不进 stdout）

```bash
# GitHub API
vault exec github_token -- gh pr list

# OpenAI API（自定义环境变量名）
vault exec openai_key --env OPENAI_API_KEY -- curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

# 数据库连接
vault exec db_password --env PGPASSWORD -- psql -h localhost -U admin -d mydb

# 任何需要 key 的命令
vault exec sendgrid_key -- curl -H "Authorization: Bearer $VAULT_VALUE" https://api.sendgrid.com/v3/stats

# 配对密钥（双注入，AWS/阿里云/腾讯云等）
vault exec aws_prod --id-env AWS_ACCESS_KEY_ID --secret-env AWS_SECRET_ACCESS_KEY -- aws s3 ls
vault exec aliyun_key --id-env ALIBABA_CLOUD_ACCESS_KEY_ID --secret-env ALIBABA_CLOUD_ACCESS_KEY_SECRET -- aliyun ecs DescribeInstances
```

---

## 在 AI 助手中使用

### WorkBuddy / Codex / Hermes 中调用密钥

你不需要在聊天里粘贴密钥。流程很简单：

```
┌─────────────────────────────────────┐
│ 1. 开始聊天前，在终端执行一次         │
│    vault unlock                     │
│    (输入主密码，解锁 15 分钟)          │
│                                     │
│ 2. 在聊天中直接让 AI 用密钥           │
│    你："帮我用 github token 创建 PR"  │
│    AI 执行：vault exec github_token  │
│            -- gh pr create ...      │
│    → AI 看不到 token 值              │
│                                     │
│ 3. 如果会话过长，AI 可主动续期        │
│    vault touch                      │
│    (无需密码，刷新倒计时)             │
└─────────────────────────────────────┘
```

**超时优化**：开始工作前把超时调长，一整天不用重新解锁：

```bash
vault config set session_timeout 28800   # 8 小时
```

---

## 备份与恢复

### 导出备份

```bash
vault export ~/backups/vault-2026-07-27.vaultbak
# ✓ 已导出 12 条密钥到: ~/backups/vault-2026-07-27.vaultbak
#   该文件已加密，可用 vault import 恢复
```

备份文件已经 AES 加密，可以放心复制到任何地方：

```bash
# 复制到 U 盘
cp ~/backups/vault-2026-07-27.vaultbak /Volumes/USB/

# 上传云盘（已经是密文，云服务商无法读取）
# 直接把 .vaultbak 文件拖到 iCloud / Dropbox / 百度网盘

# scp 到另一台机器
scp ~/backups/vault-2026-07-27.vaultbak user@other-machine:~
```

### 恢复备份

在新机器上同样安装 vault → init 时使用**同一主密码** → 导入：

```bash
vault init              # 设置与源机器相同的主密码
vault unlock            # 输入主密码
vault import ~/vault-2026-07-27.vaultbak
# ✓ 导入完成: 新增 12 条, 跳过 0 条, 错误 0 条
```

如果目标机器已有同名 key：

```bash
vault import backup.vaultbak --overwrite   # 覆盖已有
vault import backup.vaultbak               # 跳过已有（默认）
```

---

## 管理会话

```bash
# 查看状态
vault status
# 保险库: 已解锁 (剩余 12 分 34 秒)
# 密钥总数: 12
# 标签: api, database, ssh

# 立即锁定（离开电脑时）
vault lock

# 刷新超时（无需密码）
vault touch

# 调整超时
vault config set session_timeout 3600    # 1 小时
vault config set session_timeout 28800   # 8 小时
vault config get session_timeout         # 查看当前值
```

---

## 命令速查表

| 命令 | 说明 | 示例 |
|------|------|------|
| `vault init` | 初始化 | — |
| `vault unlock` | 解锁 | — |
| `vault lock` | 锁定 | — |
| `vault touch` | 续期 | — |
| `vault add <k> <v> -t <tag>` | 保存单密钥 | `vault add gh_token xyz -t api` |
| `vault add <k> --pair-id <id> --pair-secret <s>` | 保存配对密钥 | `vault add aws --pair-id AKIA... --pair-secret wJalr...` |
| `vault get <k> [--id\|--secret]` | 获取明文 | `vault get gh_token` / `vault get aws --id` |
| `vault list [-t <tag>]` | 列表 | `vault list -t api` |
| `vault search <kw>` | 搜索 | `vault search token` |
| `vault delete <k>` | 删除 | `vault delete old_key` |
| `vault exec <k> -- <cmd>` | 安全调用（单密钥） | `vault exec gh_token -- gh pr list` |
| `vault exec <k> --id-env N --secret-env N -- <cmd>` | 安全调用（配对） | `vault exec aws --id-env ID --secret-env SECRET -- aws s3 ls` |
| `vault export <path>` | 备份 | `vault export backup.vaultbak` |
| `vault import <path>` | 恢复 | `vault import backup.vaultbak` |
| `vault config set/get/unset` | 配置 | `vault config set session_timeout 28800` |
| `vault status` | 状态 | — |

---

## 安全小贴士

1. **主密码要记牢**，这是恢复密钥的唯一钥匙，忘了就找不回来了
2. **定期备份**：建议每周 `vault export` 一次，存到 U 盘或云盘
3. **离开时锁定**：`vault lock` 或设置短超时
4. **AI 中用 exec 不用 get**：`vault exec` 比 `vault get` 更安全，密钥不会出现在聊天记录里
5. **管道传值**：`echo 'secret' | vault add key` 比 `vault add key secret` 更好，避免 shell history 泄漏
6. **备份也是加密的**：.vaultbak 文件本身就是密文，不需要额外加密就能上传云盘
