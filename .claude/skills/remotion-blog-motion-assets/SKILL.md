---
name: remotion-blog-motion-assets
description: 当用户给出单篇博文路径时，自动从正文中识别适合用 Remotion 静帧或短循环视频说明的段落/小节，并在渲染资源后把引用写回同一篇 Markdown。也适用于手动指定「用 Remotion 做动图/示意图」、批量 MP4/GIF、以及固化 `_scripts/remotion-blog-ppt-article` 到文章 `pic/` 目录。实现 Remotion 代码时应协同读取本机 remotion-best-practices skill。
---

# Remotion 博文配图与短视频

## 这个 skill 做什么

绑定 `BlogPapers` 仓库，说明如何用 **Remotion 子工程** 产出可嵌入 Markdown 的 **静帧图** 与 **短视频**，并在配色与气质上对齐本站深色科幻风。

**推荐主路径（用户给一篇文章文件时）**：以 `YYYY/某文章.md` 为唯一输入，按下文「从文章到槽位 → 实现/选用 composition → 导出 → 写回正文」走完；不要只做 Remotion 而忘记把资源嵌回原文。

与 [creating-blog-web-ppt](../creating-blog-web-ppt/SKILL.md) 的分工：

| 产物 | 工具 |
|------|------|
| 独立单文件 HTML 幻灯 / 演讲稿 | `creating-blog-web-ppt` |
| 栅格图、H264 循环短片、（可选）GIF | 本 skill + `_scripts/remotion-blog-ppt-article` |

**目录说明**：本仓库 skills 根路径为 `.claude/skills/`（与根目录 `CLAUDE.md` 一致）。若本地习惯写成 `.CLAUDE/SKILLS/`，请指向同一套路径。

## 输入与输出

| 输入 | 输出 |
|------|------|
| 用户提供的 **单篇 Markdown 路径**（如 `2026/从Markdown到网页版PPT_同源deck与博客对照阅读.md`） | ① 槽位清单（见下）；② `YYYY/pic/<slug>/` 下的 PNG/MP4/（可选）GIF；③ **已插入引用后的同一 `.md` 文件** |

- **`<slug>`**：与文章主题一致的小写英文短目录名（可与现有 `pic/` 子目录对齐，例如 `blog-ppt-remotion`）；若文章已存在 `![](./pic/xxx/...)`，优先沿用 `xxx`。
- ** basename**：文章文件名去掉 `.md`，用于命名导出文件时保持可读、可追溯。

## 从正文自动提取「需要配图说明」的部分

目标不是改写全文，而是找出 **用一张图或一段短循环比纯文字更清楚** 的位置，并为每个位置预留 **一个槽位（slot）**，便于对应一个 composition 或一张 still。

### 高优先级（几乎总是槽位）

1. **小节标题**含：`图`、`示意`、`架构`、`流程`、`分层`、`对照`、`路径`、`数据流`、`链路`、`状态机`、`时序` 等，且正文在解释结构/步骤/多选一方案。
2. **显式占位**：HTML 注释如 `<!-- motion: composition-id -->` 或 `<!-- 配图: 简述 -->`（实现后改为真实 `<video>` / `![...]()` 或删除注释并在紧邻位置插入媒体）。
3. **列表 + 抽象名词**：多条并列（如三种方案、三层结构、五个步骤）且后文没有现成配图。
4. **表格**：多列对比、矩阵选型；若表后是总结段，槽位可放在表后。

### 中优先级（结合后文判断）

5. **密集技术段**：连续出现「输入 → 输出」「A 层 / B 层」「解析 / 渲染 / 发布」等空间或管线隐喻，且段落长度超过约 8 行或 400 字仍无图。
6. **代码块前后**：若在讲「目录结构」「构建命令与产物路径」，可在代码块 **后** 设槽位做目录树或数据流示意（仍用 Remotion 画布，而非截图代码字体）。
7. **已有弱配图**：仅有文字说明「见下图」但无 `![]` / `<video>`，视为待补槽位。

### 低优先级 / 通常不设槽位

- 纯观点、随笔、书单；单句定义；已有满意静态截图且无需动效。
- 与站点无关的外链大图（不要随意替换成本地 Remotion 产物，除非用户要求）。

### 槽位清单（必须先产出再给 Remotion）

在动任何 `src/*.tsx` 之前，在回复或笔记中写出 **槽位表**，便于用户确认与批量渲染：

```text
| slot | 锚点（原文小节标题或首句摘录） | 建议媒体类型 | 建议 composition / 动作 | 相对路径草案 |
|------|----------------------------------|----------------|-------------------------|----------------|
| S1   | …                                | MP4 循环       | 已有 `data-flow` 或新建 | ./pic/<slug>/data-flow.mp4 |
```

- **锚点**：便于在编辑器里 `Ctrl+F` 定位；插入媒体时放在 **该锚点所在小节最后一个完整语义段之后**（一般是该 `##`/`###` 小节末，或列表/表格之后），避免打断列表项中间。
- **每个槽位最多一个主媒体**（MP4 或 PNG）；GIF 仅在 README 约定或用户明确要求时使用。

### 写回原文的规则

1. **动效优先 `<video>`**（相对路径、与文章同目录解析）：

```html
<video autoplay loop muted playsinline src="./pic/<slug>/example.mp4"></video>
```

（若站点对 HTML 有限制，以 Jekyll 实际渲染为准；可退化为 `![alt](./pic/...gif)`。）

2. **静帧**：`![简短说明](./pic/<slug>/frame.png)`，说明文字用中文、不夸张。
3. **不要破坏** front matter、现有锚点链接、脚注；新增块与上下各留一空行。
4. **已存在** 指向同一文件的引用则 **更新属性/说明** 而非重复插入。
5. 若用户只要「提取清单」而不要改文件：只输出槽位表与建议路径，**不**写回 `md`。

## 依赖：remotion-best-practices（必协同）

本 skill 只覆盖 **BlogPapers 仓库内的落盘路径、站点视觉对齐、导出到博文与 GIF 约定**。凡是 **编写、重构或调试** `_scripts/remotion-blog-ppt-article` 里的 Remotion 代码，都应把 **`remotion-best-practices`** 当作 **通用领域知识** 一并加载，二者互补、不互相替代。

| 来源 | 负责什么 |
|------|----------|
| **本 skill**（`remotion-blog-motion-assets`） | 文章槽位提取与写回、`pic/` 目录约定、`Root.tsx` 画布与批量导出流程、博客色板与验证清单 |
| **remotion-best-practices** | Studio 预览、`remotion still` / `render` 习惯、composition 与动画、字体与资源、`rules/*.md` 专题（如 `animations.md`、`timing.md`、`fonts.md`、`assets.md`） |

**本机路径**（随 Claude Code 安装位置可能略有不同，以你机器上实际为准）：

- macOS / Linux：常见为 `~/.claude/skills/remotion-best-practices/SKILL.md`
- Windows：常见为 `%USERPROFILE%\.claude\skills\remotion-best-practices\SKILL.md`

执行时：先读 `remotion-best-practices/SKILL.md` 的索引，再按任务打开其 `rules/` 下对应条目；同时按本 skill 的「必读路径」处理仓库专属部分。

## 何时使用

- 用户给出 **一篇** `YYYY/*.md`，要求「用 Remotion 配图 / 动图 / 自动找需要图的地方并插入」
- 「用 Remotion 给这篇文章做动图 / 视频」
- 「导出和博客风格一致的示意图」
- 「批量 render MP4、再转 GIF」
- 「改画布分辨率后怎么重渲」

**不要用本 skill**：纯 CSS/HTML 幻灯、不涉及 Remotion 的静态配图、站点导航与 Jekyll 配置。

## 用户要求优先

若用户指定了输出目录、文件名、分辨率、只用 `<video>` 不用 GIF、或 **禁止自动改 md 只出清单**，以用户为准；本 skill 只补齐仓库内默认约定。

## 必读路径（按顺序）

1. **Remotion 通用实践**：本机 `remotion-best-practices/SKILL.md`，按需深入其 `rules/*.md`（与下述步骤穿插进行即可）。
2. 视觉对齐（颜色、字体、反 AI 味）：[references/visual-alignment.md](references/visual-alignment.md)（可与 `creating-blog-web-ppt/references/visual-system.md` 对照）
3. 子工程权威命令与参数：[`_scripts/remotion-blog-ppt-article/README.md`](../../../_scripts/remotion-blog-ppt-article/README.md)
4. Composition 注册与画布：`src/Root.tsx`（`W` / `H` / `fps`、各 `id` 与 `durationInFrames`）

## 执行清单

```text
文章驱动（给定 YYYY/article.md 时）：
- [ ] 通读全文，按「提取规则」产出槽位表（含锚点与 ./pic/<slug>/ 草案）
- [ ] 与用户确认槽位数量与类型（可省略：用户已说「按 skill 全自动」）
- [ ] 确认文章对应的资源子目录（例如 YYYY/pic/<slug>/）

Remotion 与资源：
- [ ] 已对照 remotion-best-practices（及按需打开的 rules）实现或调整 composition
- [ ] 配色与版式对齐 visual-alignment
- [ ] npm install / npm run dev 预览
- [ ] 导出 MP4（--codec=h264，CRF 按 README，常用 --crf=16）
- [ ] 若需要 GIF：两阶段 palette；GIFW 必须与 Root.tsx 的 W 一致

写回与验证：
- [ ] 在 Markdown 中按槽位插入 <video> 或 ![ ]；不重复、不拆列表
- [ ] 浏览器打开文章页核对动效与暗色背景下的对比度
```

## 工作流摘要

1. **读文章** → 槽位表 →（可选确认）→ **实现/注册 composition** → 导出到 `YYYY/pic/<slug>/`。
2. **进入子工程**：`cd _scripts/remotion-blog-ppt-article`，`npm install`，`npm run dev`。
3. **画布**：在 `src/Root.tsx` 修改 `W`、`H`（建议 16∶9）；所有 composition 共用。
4. **静帧**：`npx remotion still src/index.ts <composition-id> --frame=<n> --output=<相对文章 pic 的路径>`。
5. **视频**：按 README 中的 PowerShell / Bash 批量 `npx remotion render ... --codec=h264 --crf=16`；输出目录一般为文章旁的 `YYYY/pic/<slug>/`。
6. **GIF**：仅 256 色；高清循环更推荐博文中使用 `<video autoplay loop muted playsinline>`。若仍要 GIF，严格按 README 两阶段 `ffmpeg`，且 **`GIFW` = `W`**。
7. **写回**：按槽位锚点插入引用；保存 `YYYY/article.md`。
8. **CDN**：全站图片前缀见根目录 `CLAUDE.md`；新文件若走既有发布流程，保持与文章相对路径一致即可。

## Composition id 维护

当前注册的 `id` 与用途以 README 中的表格为准；新增 composition 时必须在 `Root.tsx` 增加 `<Composition ... />`，并在 README 表格中补一行，便于他人批量 render。

## 完成前验证

- 本地至少：文章页在浏览器中加载，检查 `<video>` / `![...](...gif)` 是否正常、暗色背景下是否可读。
- 若动效用于与「网页版 PPT」对照的同一篇文章，可顺带打开同目录 `*-ppt.html` 看视觉是否同一套 token。
