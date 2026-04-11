# CLAUDE.md

本文件用于说明 Claude Code 在本仓库中的默认工作方式、仓库约定与高频任务规则。

## 默认语言

- 面向用户的回复默认使用简体中文
- 仓库内新增的说明文字、文章配套 HTML、网页版 PPT、演讲稿页面默认优先使用中文
- 代码符号、命令、路径、配置键名等技术标识保持原语言，不要为了“中文化”改动 identifier

## 仓库定位

这是一个基于 Jekyll 的安全研究博客仓库，部署在 [sumsec.me](https://sumsec.me)。

- 文章按年份组织在 `2021/`、`2022/`、`2023/`、`2026/`、`PL/` 等目录
- 站点整体是深色、克制科幻感的博客主题
- 首页由根目录 `README.md` 生成
- 文章正文以 Markdown 为主，部分文章会有同目录 companion HTML 或独立演示页

## 站点关键结构

- `_config.yml`：Jekyll 配置，包含 markdown engine、highlighter、Sass 等设置
- `_layouts/default.html`：默认布局，包含终端风格头部、矩阵雨 canvas 和 `scifi.js`
- `assets/css/style.scss`：全站主题样式与颜色 token
- `assets/js/scifi.js`：矩阵雨动画与部分前端交互逻辑
- `README.md`：站点首页来源
- `resources/`：归档、RSS、站点资源与一些非博客静态文件

## Jekyll 常用命令

```bash
# 构建站点
jekyll build

# 本地开发
jekyll serve --livereload

# 更接近生产环境的本地预览
BUNDLE_WITHOUT="" bundle exec jekyll serve
```

要求：Jekyll 4.x + Dart Sass，不使用 LibSass。

## 新增文章约定

1. 新建文章：`YYYY/post-title.md`
2. 如无 front matter，可依赖站点 `defaults` 自动补 `layout`
3. 如需手写 front matter，可使用：

```yaml
---
layout: default
title: Post Title
---
```

4. 在 `README.md` 对应年份表格中补一行
5. 需要时更新 `resources/Archives.md`
6. 不要手动更新页面中的硬编码文章计数文案

标签约定：

- `README.md` 最后一列使用 `标签甲/标签乙` 这种斜杠分隔格式
- 若需给 Markdown 自动补 `tags: blog-comments`，可使用 `_scripts/add_blog_comments_tag.py` 或本地 pre-commit

## 文章转网页版 PPT

当用户要求把仓库中的文章做成网页版 PPT、HTML 演讲稿、slide deck 或独立演示页时，优先使用本仓库 skill：

- `.claude/skills/creating-blog-web-ppt/SKILL.md`

默认规则：

- 输入通常是 `YYYY/post-name.md`
- 输出默认是同目录、同 basename 的 `YYYY/post-name.html`
- 产物应为独立单文件 HTML，不依赖 Jekyll layout
- 保持文章目录内原有相对图片路径可用，例如 `./pic/...`

执行这类任务时，通常需要读取：

- `assets/css/style.scss`
- `_layouts/default.html`
- `.claude/skills/creating-blog-web-ppt/references/repo-conventions.md`
- `.claude/skills/creating-blog-web-ppt/references/visual-system.md`
- `.claude/skills/creating-blog-web-ppt/references/html-template.md`
- `.claude/skills/creating-blog-web-ppt/references/verification-checklist.md`

除非用户明确要求，否则不要顺手改：

- `README.md`
- `resources/Archives.md`
- 首页入口、站点导航、归档入口

这类任务完成前必须做浏览器级验证，不能只做静态阅读或代码检查。

## 评论与页面统计

- 评论系统使用 [utterances](https://utteranc.es/) 对接 GitHub Issues
- `_config.yml` 中的 `utterances.label` 应与仓库内 Issues 标签保持一致
- 若 `_config.yml` 配置了 `stats_endpoint`，则优先通过 Cloudflare Worker 获取页面统计，失败后回退 CountAPI

某页如需关闭评论，可在 front matter 中设置 `comments: false`。

## GitHub Pages 发布约定

本站依赖 `jekyll-readme-index` 等插件将根目录 `README.md` 生成为首页 `/`。

GitHub Pages 应使用：

- Branch：`master`
- Folder：`/ (root)`

如果误改为仅依赖 GitHub Actions 构建且 workflow 失败，可能导致整站或首页 404。此时应改回“Deploy from a branch”并等待一次成功构建。

## GitHub Actions 与 CI 生成文件

当前仓库有多条工作流会自动更新内容，包括：

- `AboutMe`：同步 `AboutMe.md`、`rss.xml`、`atom.xml` 与 `dist/` SVG 资源
- `SitemapGenerator`：重新生成 `resources/sitemap.xml` 与 `resources/rss.xml`
- `Update images`：批量把旧图片地址改写到 CDN

这些文件不要手工长期维护，因为会被 CI 覆盖：

- `resources/AboutMe.md`
- `resources/rss.xml`
- `resources/atom.xml`
- `resources/dist/`

## 本地工作区与 Git 约定

本项目默认把本地 worktree 放在：

- `.worktrees/`

原则：

- `.worktrees/` 仅用于本地开发隔离，不属于仓库正式内容
- `.worktrees/` 不应提交到 Git 仓库
- `.claude/` 目录下的本地 skill、agent 辅助文件也默认视为本地资产，不应直接作为常规站点内容维护

如果确实需要把被忽略目录中的某个文件纳入版本控制，必须明确确认该文件是“仓库资产”而不是“本地工具资产”，不要顺手批量提交整个目录。

## 本地 Git hooks（可选）

若不希望在本地改 Markdown，且不需要 `tags: blog-comments`，可跳过本节。

提交前，hook 可为暂存区中的 `.md` 自动写入或合并 `tags: blog-comments`，跳过 `resources/AboutMe.md` 与 `CLAUDE.md`。

首次启用：

```bash
git config core.hooksPath .githooks
```

若在 Linux/macOS 下提示无执行权限：

```bash
chmod +x .githooks/pre-commit
```

依赖：

- 本机可用 `py` / `python3` / `python`
- 已安装 `PyYAML`

手动执行：

- 全量扫描：`py _scripts/add_blog_comments_tag.py`
- 仅处理暂存文件：`py _scripts/add_blog_comments_tag.py --git-staged`

## 其他约定

- 图片 CDN 前缀：`https://img.sumsec.me/`
- CNAME：`sumsec.me`
- 历史提交信息常见 emoji 前缀，例如 `🍭Update Sitemap`
- `_site/` 是 Jekyll 构建产物，默认不提交
- `resources/` 下存在一些非博客文件，例如 swagger、vless 配置等，除非明确相关任务，不要随意整理或重构
