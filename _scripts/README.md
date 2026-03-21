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
