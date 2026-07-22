# CLAUDE.md / AGENTS.md

本文件用于说明 Claude Code 与 Codex 在本仓库中的默认工作方式、仓库约定与高频任务规则。

`CLAUDE.md` 是代理/助手规则的规范源；`AGENTS.md` 作为普通文件镜像本文件内容维护，避免 GitHub Pages/Jekyll 3 扫描根目录软链接时触发构建错误。

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

## 主题分类

除按年份浏览外，站点还有一套主题分类，入口在顶部导航「分类」下拉与 `/categories/`：

- 分类定义集中在 `_data/article_categories.json`（slug、名称、配色、`tags`/`keywords`/`roots` 自动匹配规则、`articles` 显式归属、`group` 分组、`fallback` 兜底）
- 新增/改名/删除分类只改这一个 JSON 再重跑脚本即可，导航下拉、目录页、独立分类页全部自动生成；配色 `accent` 复用 `assets/css/style.scss` 里已有的 `[data-topic='...']` 值，未定义的 accent 会回退默认蓝色
- `categories/` 下所有页面由 `_scripts/generate_categories_page.py` 生成，**不要手工编辑**；AboutMe 工作流会自动重跑并提交
- 新增文章只需正常登记到年份 README 时间轴（带上 Tags），脚本下次运行即自动归类；标签匹配不准时，把文章相对路径加进对应分类的 `articles` 列表
- 新增并准备提交文章时，先检查其主题、标签与现有分类是否一致，能纳入现有分类时优先复用；只有现有分类都无法准确覆盖文章主题时，才在 `_data/article_categories.json` 新建分类，并补齐名称、slug、分组、匹配规则和配色
- 调整分类后本地运行 `py _scripts/generate_categories_page.py` 验证

## 新增文章约定

**年份归档基准：** 后续新建文章或博客时，必须以创建文件时的当前年份作为归档依据，并放入同名年份目录。例如，当前时间为 2026 年，则放入 `2026/`；当前时间为 2025 年，则放入 `2025/`。如果对应年份目录不存在，应先创建该目录。不要根据文章内容涉及的年份决定存放目录。

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

## Remotion 博文配图与短视频

当用户要求用 Remotion 为文章生成与站点风格一致的静帧、MP4 或（可选）GIF 时，优先阅读：

- `.claude/skills/remotion-blog-motion-assets/SKILL.md`
- `.codex/skills/remotion-blog-motion-assets/SKILL.md`（Codex 环境；若本地目录为 `.Codex/`，按实际路径读取）

编写或调试 Remotion 代码时，还应协同使用本机 **remotion-best-practices** skill（通常在用户目录 `.claude/skills/remotion-best-practices/SKILL.md` 或 `.codex/skills/remotion-best-practices/SKILL.md`，按需打开其 `rules/*.md`），与上一条仓库 skill 分工见该 `SKILL.md` 内「依赖」小节。

实现与批量导出命令以 `_scripts/remotion-blog-ppt-article/README.md` 为准。

## 微信公众号发文

当用户要把仓库中的 Markdown **发布到微信公众号**、排版成可发表文章/贴图、或提到「公众号 / 微信图文 / 贴图 / 文章」等需求时，优先使用本仓库 skill：

- `.claude/skills/baoyu-post-to-wechat/SKILL.md`
- `.codex/skills/baoyu-post-to-wechat/SKILL.md`（Codex 环境；若本地目录为 `.Codex/`，按实际路径读取）

上游集合：[JimLiu/baoyu-skills](https://github.com/JimLiu/baoyu-skills)（skill 名 **`baoyu-post-to-wechat`**）。该 skill 通过脚本支持 **API** 或 **Chrome CDP** 等路径，具体前置条件、权限检查与命令以 `SKILL.md` 正文为准；执行脚本需要本机可用 **`bun`** 或按 skill 说明用 **`npx -y bun`**。

**不要**把公众号 AppSecret、Cookie、Token 等敏感信息写入仓库或提交进 Git；仅放在本机环境变量或私有配置中。

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

- `AboutMe`：同步 `AboutMe.md`、`dist/` SVG 资源，并用 `_scripts/generate_feed_and_sitemap.py` 根据仓库内 Markdown 生成 `resources/rss.xml`、`resources/atom.xml`、`resources/sitemap.xml`（仅此工作流负责 feed / sitemap，可 `workflow_dispatch` 手动重跑）。脚本从 `resources/Archives.md` 里所有 `(../某目录/README.md)` 链接自动收集「归档根目录」，新增年份时维护 Archives 即可，无需改脚本常量。
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
- `.claude/`、`.codex/`、`.Codex/` 目录下的本地 skill、agent 辅助文件也默认视为本地资产，不应直接作为常规站点内容维护

如果确实需要把被忽略目录中的某个文件纳入版本控制，必须明确确认该文件是“仓库资产”而不是“本地工具资产”，不要顺手批量提交整个目录。

## 本地 Git hooks（可选）

若不希望在本地改 Markdown，且不需要 `tags: blog-comments`，可跳过本节。

提交前，hook 可为暂存区中的 `.md` 自动写入或合并 `tags: blog-comments`，跳过 `resources/AboutMe.md`、`CLAUDE.md` 与 `AGENTS.md`。

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
- 本项目的常规文章、资源与站点维护只允许提交到 `master` 分支；除非用户明确要求，不要创建或提交到其他分支
- 本项目提交前必须先同步远端；默认先执行 `git fetch origin`，再执行 `git pull --rebase origin master`，确认吸收最新自动更新后再 `commit` / `push`
- `_site/` 是 Jekyll 构建产物，默认不提交
- `resources/` 下存在一些非博客文件，例如 swagger、vless 配置等，除非明确相关任务，不要随意整理或重构
