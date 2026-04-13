---
name: creating-blog-web-ppt
description: 当用户要求把本仓库中的 Markdown 文章转成网页版 PPT、HTML slides、演讲稿页面或独立演示页，尤其希望输出与原文同目录、同 basename 时使用。已合并 FeeiCN/slide-writer：结构化工作流 + 全量企业主题文件（vendor/slide-writer/themes）；另增博客站主题 blog-sumsec，仅在博文缺省场景作为默认色板。
---

# 创建文章网页版 PPT（合并 Slide-Writer）

## 这个 skill 做什么

这是一个绑定 `BlogPapers` 仓库的专用 skill，用来把文章型 Markdown 转成独立的网页版 PPT。

合并来源：[FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer)（MIT，快照于 `vendor/slide-writer/`，见 `vendor/slide-writer/UPSTREAM.md`）。上游的**全部企业主题 CSS**（`vendor/slide-writer/themes/*.md`）、**主题识别索引**（`vendor/slide-writer/themes/_index.md`）、**组件与 `_base.html` 引擎**均在仓库内保留可用。另增 **`blog-sumsec`** 博客站补充主题（[`themes/blog-sumsec.md`](themes/blog-sumsec.md)）：仅在「博文转 PPT、且未指定/未命中企业主题」时作为**缺省**色板，取代上游「未识别品牌 → 蚂蚁蓝」；**不得**在用户已选企业主题时强行改用博客色。本 skill 同时保留博客仓库的落盘路径、品牌回链、视口与图片约束。

主 `SKILL.md` 只负责：

- 判断是否该触发
- 规定不可跳过的执行顺序
- 指向 `references/` 与 `themes/` 中的细节文件

细节不要堆回主文件；需要时再读对应 reference。

## 何时使用

出现下面这类请求时使用：

- “把这篇文章做成网页版 PPT”
- “把这个 Markdown 转成 HTML slides / 演讲稿”
- “给这篇博文做一个独立演示页”

下面这些情况不要用本 skill：

- 普通博客排版修改
- 首页、归档、导航维护
- 通用 landing page 或产品展示页

## 用户要求优先

本 skill 提供默认规则，不覆盖用户的明确要求。

如果用户明确指定了输出路径、文件名、页数策略、视觉方向或是否补入口链接，则以用户要求为最高优先级，仅用本 skill 补齐未指定部分。

如果用户明确要求品牌位跳原文、画布不超视口或指定某种响应式策略，则这些要求优先于默认实现细节。

## 默认产物

如果用户没有额外指定，默认按以下规则执行：

- 产出一个独立的单文件 HTML
- HTML 与源 Markdown 放在同一目录
- HTML 与源 Markdown 同 basename，仅扩展名从 `.md` 改为 `.html`
- 不依赖 Jekyll layout
- 保持文章目录内的相对图片路径
- 若页面出现 `SUMSEC` 品牌位，则该品牌位必须可点击跳转到原文公开地址
- 页面右下角必须提供可见的全屏切换按钮
- deck 主画布不得超过当前视口，必须具备自适应缩放或响应式重排能力
- 小屏下优先保证可读性与不裁切，必要时允许退化为纵向滚动阅读
- 不改首页、归档、站点导航
- **主题选择**：先读 [`themes/_index.md`](themes/_index.md)。**并行保留**博客主题与 slide-writer 全量企业主题：命中企业分支或用户指定时读 `vendor/slide-writer/themes/[id].md`；否则在博文缺省场景使用 **`blog-sumsec`**，并读 [`themes/blog-sumsec.md`](themes/blog-sumsec.md)

## 读取策略

默认按下面方式读取参考文件：

- 与 Slide-Writer 的分工、双轨道说明：**必读** [references/slide-writer-merge.md](references/slide-writer-merge.md)
- 路径、落盘位置、禁止改动项：读 [references/repo-conventions.md](references/repo-conventions.md)
- 视觉方向、版式原则、反 AI 味规则：读 [references/visual-system.md](references/visual-system.md)
- HTML 最小结构和交互基线：读 [references/html-template.md](references/html-template.md)
- 完成前的验证动作：必读 [references/verification-checklist.md](references/verification-checklist.md)
- 需要类比案例时：读 [references/examples.md](references/examples.md)
- 主题解析：读 [`themes/_index.md`](themes/_index.md)；博客缺省色板：[`themes/blog-sumsec.md`](themes/blog-sumsec.md)；企业主题：按需读 `vendor/slide-writer/themes/_index.md` 与匹配到的 `vendor/slide-writer/themes/[id].md`
- 采用 Slide-Writer 引擎轨道或借鉴其组件 HTML 时：按需读 `vendor/slide-writer/components.md`、`vendor/slide-writer/SKILL.md`（仅 Phase 2–3 相关小节）

## 执行清单

复制这段清单并在执行时逐项完成，不要跳步：

```text
生成进度：
- [ ] 步骤 1：读取原文、主题索引与仓库视觉参考
- [ ] 步骤 2：写出三句前置主张，并做演示结构规划（吸收 slide-writer Phase 2）
- [ ] 步骤 3：选择生成轨道（博客默认 / Slide-Writer 引擎）并生成单文件 HTML
- [ ] 步骤 4：核对路径与仓库约定
- [ ] 步骤 5：完成浏览器级验证
```

## 工作流

### 步骤 1：读取原文、主题与参考

先读 Markdown，提取叙事主线、章节层级、可复用图片和适合拆页的观点组。

读取主题与色板：

- [`themes/_index.md`](themes/_index.md)：判定本次用 **blog-sumsec** 还是 **slide-writer 某一 `themes/[id].md`**
- [`themes/blog-sumsec.md`](themes/blog-sumsec.md)：仅在选用博客缺省主题时读取
- `vendor/slide-writer/themes/_index.md` 与对应 `vendor/slide-writer/themes/[id].md`：在选用或命中企业主题时读取

同时读取：

- `assets/css/style.scss`
- `_layouts/default.html`
- [references/repo-conventions.md](references/repo-conventions.md)
- [references/visual-system.md](references/visual-system.md)
- [references/slide-writer-merge.md](references/slide-writer-merge.md)

只借用视觉 token、字体和氛围，不复用整站壳子。

### 步骤 2：先写三句话 + 结构规划

在开始生成 HTML 前，先在自己的推理里写出：

- `visual thesis`
- `content plan`
- `interaction thesis`

默认基调：

- 正式技术演讲稿优先
- **色板**：若本次为博文缺省且未走企业分支，用 **`blog-sumsec` 深色科幻站色**；若用户指定或命中 slide-writer 企业主题，则**完整使用**对应 `vendor/slide-writer/themes/[id].md`（含蚂蚁蓝等上游设计），不得混用两套主色
- 长文允许做成长版 deck，不强压页数

结构规划阶段吸收 slide-writer 的「长文 → 演示结构」原则：一页一判断、先骨架后填字、控制信息密度与布局多样性。细则见 [references/slide-writer-merge.md](references/slide-writer-merge.md) 与按需查阅的 `vendor/slide-writer/SKILL.md`。

这一步不能省略。先有三句主张与清晰页级结构，再开始写 HTML。

### 步骤 3：生成独立 HTML

**轨道选择**（见 [references/slide-writer-merge.md](references/slide-writer-merge.md)）：

- **默认**：自研单文件 deck，内联 CSS/JS，结构与交互以 [references/html-template.md](references/html-template.md) 为准；主题色按 `themes/_index.md`：缺省为 `blog-sumsec.md`，否则为选定的 `vendor/slide-writer/themes/[id].md`。
- **可选**：用户明确要求采用 slide-writer `_base.html` 引擎时，从 `vendor/slide-writer/_base.html` 复制到输出路径并按上游占位符填充；`<!-- %%THEME_STYLE%% -->` 填入**本次选定**主题的 CSS（`blog-sumsec.md` **或** 任一企业 `themes/[id].md`）。无论哪条轨道，都必须满足本仓库关于 SUMSEC、全屏、视口与图片的硬约束。

生成时额外强制满足：

- 若使用 `SUMSEC` / `sumsec` 品牌位，必须用可点击链接而不是纯文本，并指向原文公开地址
- 页面右下角必须存在全屏切换按钮，优先接入 `Fullscreen API`
- 全屏按钮需具备清晰可点击样式、`aria-label`，并在不支持全屏的环境下优雅降级
- 优先用 `clamp()`、`min()`、`max()`、`aspect-ratio` 等 CSS 约束画布大小
- 原文图片必须放进受限的 figure 容器，默认优先 `object-fit: contain`，不能让图片反向撑大 slide 边框
- 首屏 slide 在常见桌面视口下不得超出可视区域
- 页面不得出现由主画布导致的横向溢出
- 当视口过小或内容过长时，应切换为更易读的响应式布局，而不是硬撑固定大画布

### 步骤 4：核对路径与仓库约定

生成后立即核对：

- 输出路径是否为同目录、同 basename
- favicon 和图片相对路径是否正确
- `SUMSEC` 品牌位是否存在且跳转到原文公开地址
- 右下角是否存在可用的全屏切换按钮
- 主画布是否被 `max-width` / `max-height` 或等效策略限制在视口内
- 原文图片是否被限制在 figure 容器内，而不是把主画布或列布局撑大
- 缩小窗口后是否仍无横向滚动、无关键内容被裁切
- 是否误用了整站导航、footer 或 Liquid

详细规则见 [references/repo-conventions.md](references/repo-conventions.md)。

### 步骤 5：浏览器级验证

完成后必须做浏览器级验证，不能只做静态检查。

验证步骤、最低证据格式和收尾要求见 [references/verification-checklist.md](references/verification-checklist.md)。

这一步也不能省略。没有验证证据，就不能声称完成。

## 禁止事项

- 不要把输出文件默认写到 `resources/`
- 不要随手起临时文件名，必须优先考虑与原文同 basename
- 不要把博客整站 header / footer / nav 直接搬进 deck
- 不要无故改坏文章目录里的相对图片路径
- 不要把长文硬压成过少页面，导致单页信息过载
- 不要把 `SUMSEC` 品牌位做成不可点击文本
- 不要省略右下角全屏按钮，也不要把它放到不易发现的位置
- 不要让 slide 主画布宽度或高度超出视口后再依赖用户缩放页面查看
- 不要直接把原文大图按原尺寸塞进 slide，导致图片把页面边框撑开
- 不要对内容图默认使用会裁切关键信息的铺满策略；原文配图默认优先完整可见
- 不要为了保住固定比例而让小屏内容溢出、裁切或出现横向滚动
- 不要没开浏览器就声称完成
- **不要在应使用 slide-writer 企业主题时强行改成 `blog-sumsec`**（用户指定、关键词命中或要求上游企业默认时，须用对应 `vendor/slide-writer/themes/[id].md`）
- **不要在博文缺省场景默认套用上游蚂蚁蓝或其他企业色**：未命中企业分支时应使用 `blog-sumsec`（见 `themes/_index.md`）

## 参考文件

- [references/slide-writer-merge.md](references/slide-writer-merge.md)
- [references/repo-conventions.md](references/repo-conventions.md)
- [references/visual-system.md](references/visual-system.md)
- [references/html-template.md](references/html-template.md)
- [references/verification-checklist.md](references/verification-checklist.md)
- [references/examples.md](references/examples.md)
- [`themes/_index.md`](themes/_index.md)
- [`themes/blog-sumsec.md`](themes/blog-sumsec.md)
- `vendor/slide-writer/`（上游快照：`SKILL.md`、`components.md`、`_base.html`、**完整** `themes/*.md` 企业主题族）

## 最终规则

在这个仓库里，文章转网页版 PPT 的默认标准是：

`同目录 + 同 basename + 单文件 HTML + 主题按 themes/_index 在 blog-sumsec 与 slide-writer 企业主题间二选一（缺省博文用前者）+ SUMSEC 可跳原文 + 画布不超视口且可自适应 + 原文图片不撑破固定舞台 + slide-writer 风格文件在 vendor 内完整保留可选用 + 浏览器验证通过`

slide-writer 的结构化演示、组件与**全部企业主题**均为一等能力；仅「博文且未指定企业」时缺省到博客色板。
