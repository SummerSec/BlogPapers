---
name: creating-blog-web-ppt
description: 当用户要求把本仓库中的 Markdown 文章转成网页版 PPT、HTML slides、演讲稿页面或独立演示页，尤其希望输出与原文同目录、同 basename 时使用。主题与工作流对齐 FeeiCN/slide-writer；博客站主题见 vendor/slide-writer/themes/blog-sumsec.md（与上游主题同目录）。
---

# 创建文章网页版 PPT（slide-writer 对齐 + 博客主题增补）

## 这个 skill 做什么

这是一个绑定 `BlogPapers` 仓库的专用 skill，用来把文章型 Markdown 转成独立的网页版 PPT。

**与 [FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer) 的关系**：Phase 0～4、`_base.html` 占位符、`components.md`、企业主题识别与**未识别时默认 `ant-group`**，均以 `vendor/slide-writer/` 快照为准（见 `vendor/slide-writer/UPSTREAM.md`）。本 skill **不改写**上游默认主题逻辑。

**唯一增补**：在 `vendor/slide-writer/themes/` 增加主题文件 **`blog-sumsec.md`**（与 `ant-group.md` 等并列），并在同目录 [`vendor/slide-writer/themes/_index.md`](vendor/slide-writer/themes/_index.md) 文首规定 Phase 0 增补顺序：仅当未匹配到任何企业主题、且命中「博客站 / sumsec」等关键词时选用 **`blog-sumsec`**；否则与上游一样落 **`ant-group`**。

本 skill 另保留 BlogPapers 的落盘路径、SUMSEC 回原文、全屏、视口与图片等仓库硬约束（见 `references/`）。

主 `SKILL.md` 只负责：

- 判断是否该触发
- 规定不可跳过的执行顺序
- 指向 `references/` 与 `vendor/slide-writer/themes/` 中的细节文件

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
- **主题**：按 [`vendor/slide-writer/themes/_index.md`](vendor/slide-writer/themes/_index.md)（含 BlogPapers 增补与企业识别全文）选择 `blog-sumsec` 或企业 `<id>`，读取同目录对应 `*.md`（未命中企业与博客关键词时为 **`ant-group`**，与上游一致）

## 读取策略

默认按下面方式读取参考文件：

- 与 slide-writer 的分工、轨道说明：**必读** [references/slide-writer-merge.md](references/slide-writer-merge.md)
- 路径、落盘位置、禁止改动项：读 [references/repo-conventions.md](references/repo-conventions.md)
- 视觉方向、版式原则、反 AI 味规则：读 [references/visual-system.md](references/visual-system.md)
- HTML 最小结构和交互基线：读 [references/html-template.md](references/html-template.md)
- 完成前的验证动作：必读 [references/verification-checklist.md](references/verification-checklist.md)
- 需要类比案例时：读 [references/examples.md](references/examples.md)
- **主题**：读 [`vendor/slide-writer/themes/_index.md`](vendor/slide-writer/themes/_index.md)；再按需读同目录 `blog-sumsec.md` 或 `<id>.md`
- 结构/组件与 `_base.html` 填充：按需读 `vendor/slide-writer/SKILL.md`、`vendor/slide-writer/components.md`

## 执行清单

复制这段清单并在执行时逐项完成，不要跳步：

```text
生成进度：
- [ ] 步骤 1：读取原文；按 `vendor/slide-writer/themes/_index.md`（含增补顺序）确定主题 ID
- [ ] 步骤 2：写出三句前置主张，并做演示结构规划（slide-writer Phase 2）
- [ ] 步骤 3：选择生成轨道（自研 HUD / slide-writer _base.html）并生成单文件 HTML
- [ ] 步骤 4：核对路径与仓库约定
- [ ] 步骤 5：完成浏览器级验证
```

## 工作流

### 步骤 1：读取原文、主题与参考

先读 Markdown，提取叙事主线、章节层级、可复用图片和适合拆页的观点组。

**主题（与 slide-writer 一致，仅多 `blog-sumsec.md`）**：

1. 完整阅读 [`vendor/slide-writer/themes/_index.md`](vendor/slide-writer/themes/_index.md)：先按文首 **「BlogPapers Phase 0 增补顺序」**（企业识别 → blog-sumsec 关键词 → `ant-group`），再按需查阅下文各企业表。
2. 对照 `vendor/slide-writer/SKILL.md` Phase 0 的进度与输出习惯（可选）。

按需读取色板文件（均在 `vendor/slide-writer/themes/`）：

- 主题 ID `blog-sumsec` → [`vendor/slide-writer/themes/blog-sumsec.md`](vendor/slide-writer/themes/blog-sumsec.md)
- 企业或其它 ID → 同目录 `<id>.md`（如 `ant-group.md`）

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
- **色板**：严格跟随步骤 1 得到的主题 ID（`blog-sumsec`、`ant-group`、或其它企业 `[id]`），**不得**在未判定时写死某一企业色，也不得忽略用户显式指定的主题
- 长文允许做成长版 deck，不强压页数

结构规划阶段遵循 slide-writer Phase 2（长文 → 演示结构、布局多样性等）。细则见 [references/slide-writer-merge.md](references/slide-writer-merge.md) 与 `vendor/slide-writer/SKILL.md`。

这一步不能省略。先有三句主张与清晰页级结构，再开始写 HTML。

### 步骤 3：生成独立 HTML

**轨道选择**（见 [references/slide-writer-merge.md](references/slide-writer-merge.md)）：

- **自研 HUD 轨道**：结构与交互以 [references/html-template.md](references/html-template.md) 为准；**主题色**来自步骤 1 选定的 `vendor/slide-writer/themes/<id>.md`（含 `blog-sumsec.md`）。
- **Slide-Writer `_base.html` 轨道**：从 `vendor/slide-writer/_base.html` 复制到输出路径（用户要求或你判断需要该引擎时），按上游 Phase 3 替换占位符；`<!-- %%THEME_STYLE%% -->` 使用**当前主题 ID** 对应文件的 CSS。

无论哪条轨道，都必须满足本仓库关于 SUMSEC、全屏、视口与图片的硬约束。

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
- **不要改写 slide-writer 的默认回退**：未命中企业与博客增补关键词时，主题必须是 **`ant-group`**，而不是自行改成其它默认
- **不要在用户已选定某企业 `[id]` 或上游已命中品牌时改用 `blog-sumsec`**

## 参考文件

- [references/slide-writer-merge.md](references/slide-writer-merge.md)
- [references/repo-conventions.md](references/repo-conventions.md)
- [references/visual-system.md](references/visual-system.md)
- [references/html-template.md](references/html-template.md)
- [references/verification-checklist.md](references/verification-checklist.md)
- [references/examples.md](references/examples.md)
- [`vendor/slide-writer/themes/_index.md`](vendor/slide-writer/themes/_index.md)（唯一主题索引；含 BlogPapers 增补）
- [`vendor/slide-writer/themes/blog-sumsec.md`](vendor/slide-writer/themes/blog-sumsec.md)（选用 `blog-sumsec` 时）
- `vendor/slide-writer/`（`SKILL.md`、`components.md`、`_base.html`、`themes/*.md`）

## 最终规则

在这个仓库里，文章转网页版 PPT 的默认标准是：

`同目录 + 同 basename + 单文件 HTML + 主题流程对齐 slide-writer（未识别企业时默认 ant-group）+ 仅增补 blog-sumsec 关键词分支 + SUMSEC 可跳原文 + 画布不超视口且可自适应 + 原文图片不撑破固定舞台 + 浏览器验证通过`
