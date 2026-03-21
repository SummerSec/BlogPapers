# 仓库维护脚本

## `fetch_cloudflare_subdomains.py`

从 Cloudflare DNS API 拉取 `sumsec.me` 下全部记录，生成 Markdown 表格，写入 `resources/subdomain.md` 中 `<!--CLOUDFLARE_DNS_SYNC_BEGIN-->` … `END` 之间。

### 准备令牌

1. Cloudflare 控制台 → **My Profile** → **API Tokens** → **Create Token**。
2. 使用模板 **Read all resources** 或自定义权限至少包含：
   - **Zone** → **Zone** → **Read**
   - **Zone** → **DNS** → **Read**
3. 限定该令牌仅作用于 `sumsec.me` 所在 Zone（推荐）。

### 运行（仓库根目录）

```bash
export CLOUDFLARE_API_TOKEN="你的令牌"
python _scripts/fetch_cloudflare_subdomains.py --write
```

Windows PowerShell：

```powershell
$env:CLOUDFLARE_API_TOKEN = "你的令牌"
python _scripts/fetch_cloudflare_subdomains.py --write
```

- 不写 `--write`：只把生成的 Markdown 打印到 stdout，不改文件。
- `CLOUDFLARE_ZONE_NAME`：默认 `sumsec.me`。
- `CLOUDFLARE_ZONE_ID`：可选；若设置则跳过按域名查 Zone。

**切勿**把 API 令牌提交进 Git。

### GitHub Actions（自动同步）

工作流：`.github/workflows/sync-cloudflare-dns.yml`

1. 打开仓库 **Settings** → **Secrets and variables** → **Actions**。
2. **New repository secret**：名称 **`CLOUDFLARE_API_TOKEN`**，值为 Cloudflare API 令牌。
3. （可选）**Variables** 中新增：
   - **`CLOUDFLARE_ZONE_NAME`** — 默认可不建（工作流内默认 `sumsec.me`）；若域名不同再填。
   - **`CLOUDFLARE_ZONE_ID`** — 可选，填写后脚本不再按名称查 Zone。
4. **Actions** 页选择 **Sync Cloudflare DNS (subdomain.md)** → **Run workflow** 手动运行；工作流也会按 cron **每天 UTC 0:00** 尝试同步（无变更则不会提交）。若要 **北京时间 0:00**，将 workflow 中 cron 改为 `0 16 * * *`。

推送提交使用默认 `GITHUB_TOKEN`；若 `master` 有分支保护禁止 workflow 推送，需在保护规则中为「GitHub Actions」放行或改用 PAT（`PERSONAL_ACCESS_TOKEN` 等）——此处未内置 PAT，按仓库策略自行调整。
