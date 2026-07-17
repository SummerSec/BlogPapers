# 仓库维护脚本

## `generate_categories_page.py`

根据 `resources/Archives.md` 中登记的归档根目录收集博文，并优先读取各目录 `README.md` 时间轴中的日期与 Tags，生成 `categories/README.md` 分类目录，以及 `categories/<slug>.md` 独立分类页。

分类名称、页面 slug、匹配标签和关键词集中维护在 `_data/article_categories.json`。新增 `AI Coding`、`Web Coding` 一类配置后，脚本会创建对应的独立页面。文章文件继续保留在年份目录，不需要为了分类移动路径；已被 Git 跟踪或暂存、但尚未写入时间轴的 Markdown 也会被收录。未跟踪草稿不会提前出现在生成页中。

配置字段说明：

- `tags` / `keywords` / `roots`：按时间轴标签、标题关键词、归档根目录自动归类
- `articles`：显式指定某篇文章的归属（仓库相对路径），优先级最高；列出的文章即使尚未被 Git 跟踪也会收录，适合即将发布的新文
- `group`：可选分组名（如 `AI 方向`），相同分组在分类目录卡片与顶部导航下拉中显示组标题
- `fallback`：兜底分类，全配置有且只能有一个

```bash
python _scripts/generate_categories_page.py
```

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
