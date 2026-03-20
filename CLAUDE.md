# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A Jekyll-based security research blog hosted at [sumsec.me](https://sumsec.me) via GitHub Pages. Posts are Markdown files organized by year (`2021/`, `2022/`, `2023/`, `2026/`, `PL/`). The site uses a custom dark/sci-fi theme with matrix rain effects.

## Jekyll Commands

```bash
# Build the site
jekyll build

# Serve locally with live reload
jekyll serve --livereload

# Build and serve (production-like)
BUNDLE_WITHOUT="" bundle exec jekyll serve
```

Requires Jekyll 4.x and Dart Sass (not LibSass).

## Site Structure

- `_config.yml` — Jekyll config: markdown engine (kramdown), highlighter (rouge), Sass settings
- `_layouts/default.html` — main layout: sci-fi terminal header + matrix canvas + `scifi.js`
- `assets/css/style.scss` — all theme styles using CSS custom properties (`--bg-primary`, `--accent-blue`, etc.)
- `assets/js/scifi.js` — matrix rain canvas animation；浏览量：若 `_config.yml` 填写 `stats_endpoint`（Cloudflare Worker 根 URL），则优先请求 Worker（见 `workers/page-stats/`），失败再回退 [CountAPI](https://countapi.xyz）。键名仍为 `meta stats-namespace` + `site-total` / `pv-*`（与 CountAPI 一致）。
- 评论 — [utterances](https://utteranc.es/)（GitHub Issues）：在仓库安装 [utterances GitHub App](https://github.com/apps/utterances)，并在 Issues 中创建标签 `blog-comments`（与 `_config.yml` 中 `utterances.label` 一致）。**Utterances 只读布局里的脚本配置，不要求各篇 Markdown 带 `tags`。** 若仍希望 Jekyll 里有 `page.tags`，可在 **GitHub Actions 构建时** 用 `_scripts/add_blog_comments_tag.py` 在 runner 上注入（见 **jekyll-pages** workflow），无需提交进仓库。某页关闭评论：front matter 设 `comments: false`（`resources/Archives.md`、`resources/AboutMe.md` 已在 `defaults` 中关闭）。
- `README.md` — serves as the site homepage (`/`); contains the post timeline table
- `resources/` — static assets, AboutMe, Archives, sitemap, RSS feeds

## Adding a New Post

1. Create `YYYY/post-title.md`（可无 front matter，站点 `defaults` 会补 `layout`；`tags: blog-comments` 可由 CI 在构建时注入，不必手写；若用本地 pre-commit 也可在提交前自动写入）。如需手写：
   ```yaml
   ---
   layout: default
   title: Post Title
   ---
   ```
2. Add a row to `README.md` timeline table under the correct year section. In the **last column**, list tags as `标签甲/标签乙` (slash-separated); any new tag names are picked up automatically by `scifi.js` and colored by hash—no JS changes needed.
3. Update `resources/Archives.md` if needed
4. **Do not** update hard-coded article counts manually — they are static strings in the HTML

## GitHub Actions

Several workflows run on `master` (and/or schedule):

- **jekyll-pages**（`.github/workflows/jekyll-pages.yml`）— `jekyll build` + 部署 **GitHub Pages**；在构建前于 runner 上执行 `python _scripts/add_blog_comments_tag.py`，**只影响当次构建产物，不回写仓库**。启用前必须在 **Settings → Pages** 将 **Source** 设为 **GitHub Actions**，并停止使用「从分支/build 部署」，否则部署行为与官方预期不一致（详见该 workflow 文件头注释）。
- **AboutMe** (every 6h + push) — syncs `AboutMe.md`, `rss.xml`, `atom.xml`, and `dist/` SVG assets from other SummerSec repos via `wget`
- **SitemapGenerator** — regenerates `resources/sitemap.xml` and `resources/rss.xml` from repo content
- **Update images** — rewrites old image URLs (`raw.githubusercontent.com/SummerSec/Images/main/`) to CDN (`img.sumsec.me/`) across all Markdown files

Do not manually edit `resources/AboutMe.md`, `resources/rss.xml`, `resources/atom.xml`, or `resources/dist/` — they are overwritten by CI.

## Local Git hooks（可选）

若**不**希望在本地改 Markdown、且已用 **jekyll-pages** 在 CI 注入 `tags`，可跳过本节。

提交前为**暂存区**内的 `.md` 自动写入或合并 `tags: blog-comments`（跳过 `resources/AboutMe.md`、`CLAUDE.md`）。

**本仓库首次启用（每台机器一次）：**

```bash
git config core.hooksPath .githooks
```

（Linux/macOS 若提示无执行权限：`chmod +x .githooks/pre-commit`。）

依赖：本机可用 `py` / `python3` / `python`，且已安装 PyYAML（例如 `py -m pip install pyyaml`）。

**手动全量扫描**（不经过 commit）：`py _scripts/add_blog_comments_tag.py`  
**仅处理暂存文件**（与 hook 相同）：`py _scripts/add_blog_comments_tag.py --git-staged`

## Conventions

- Image CDN base: `https://img.sumsec.me/`
- CNAME: `sumsec.me`
- Commit messages historically use emoji prefix (e.g. `🍭Update Sitemap`) — optional
- The `_site/` directory is gitignored (Jekyll build output)
- `resources/` contains some non-blog files (swagger, vless config, etc.) — leave them as-is
