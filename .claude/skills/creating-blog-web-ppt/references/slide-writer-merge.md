# 与 Slide-Writer 的合并约定

本 skill 在保留 BlogPapers 仓库硬约束的前提下，合并了 [FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer)（MIT）中适用于「长文 / 大纲 → 演示结构」的工作流与组件化表达。

上游快照路径：`vendor/slide-writer/`（见 `vendor/slide-writer/UPSTREAM.md`）。

## 仍由本仓库说了算的硬约束

以下规则**优先于** slide-writer 原文表述：

- 输出默认：`YYYY/post-name.html`，与源 `YYYY/post-name.md` **同目录、同 basename**。
- 单文件、内联 CSS/JS、不依赖 Jekyll layout。
- 文章配图相对路径保持以文章目录为基准（如 `./pic/...`）。
- `SUMSEC` / `sumsec` 品牌位若为 HUD 一部分，必须**可点击**指向**原文公开 URL**（推导规则见 `references/html-template.md`），不得指向仓库或当前 PPT 文件。
- 右下角**全屏**按钮、主画布**不超视口**、原文图片**不撑破舞台**、完成后**浏览器级验证**：一律照 `references/html-template.md` 与 `references/verification-checklist.md`。

## slide-writer 中刻意不照搬的部分

- **Phase 0「在 skill 目录 git pull」**：合并版以 `vendor/slide-writer` 快照为准；不在该路径假设可写 `.git` 或网络可用。
- **默认企业主题**：上游在未识别品牌时使用蚂蚁蓝；本 skill **默认**使用 [`themes/blog-sumsec.md`](../themes/blog-sumsec.md)，索引见 [`themes/_index.md`](../themes/_index.md)。
- **输出文件名**：上游倾向英文小写连字符；本仓库默认 **与中文/混合 basename 的 Markdown 同名**，除非用户明确改路径。
- **每张必须在 100vh 内且无滚动条**：对博客技术长文转 deck，允许在极窄视口下按 `html-template` 的**纵向兜底**阅读；桌面端仍以不超视口、不横向溢出为准。

## 建议吸收的上游能力（Phase 2 结构规划）

在「写 HTML 之前」对内容做一次结构化（可与原 skill「三句主张」合并思考）：

1. **文章 / 演讲稿 → 演示结构**：不要 1:1 把 Markdown 贴成幻灯片；一页一判断，先结论标题再 2–4 个支撑点。
2. **内容类型 → 布局**：优先页面骨架与大组件，再填文字；参见上游 `SKILL.md` 的「内容类型 → 页面骨架 / 组件选择规则」与「布局多样性约束」——实现时既可用手写 `slide-inner` 结构，也可在采用 `_base.html` 时复用其 `section` class 与 `components.md` 片段。
3. **润色**：去冗余、名词化、层级清晰、引用克制；避免满屏长段与通用 SaaS 卡片风（与 `references/visual-system.md` 一致）。

按需查阅（不必通读）：

- `vendor/slide-writer/components.md`：只读与本轮页面相关的组件章节。
- `vendor/slide-writer/index.html`：需要对照真实渲染结构时打开对应片段。

## 两条生成轨道（实现时二选一或混合）

### A. 博客默认轨道（推荐默认）

- 结构与交互以 `references/html-template.md` 为准。
- 视觉 token 与渐变以 `themes/blog-sumsec.md` 为准。
- 可借用 `components.md` 的**版式思想**（卡片、步骤、对比），类名不必与上游完全一致，但需保持可读与可维护。

### B. Slide-Writer 引擎轨道（可选）

当用户明确要求「用 slide-writer 那套企业幻灯片骨架 / `_base.html`」时：

1. 将 `vendor/slide-writer/_base.html` **复制**到目标输出路径（仍优先满足同目录、同 basename 规则），再按上游 `SKILL.md` Phase 3 替换 `%%TITLE%%`、`<!-- %%THEME_STYLE%% -->`、`%%LOGO_GROUP%%`、`%%FOOTNOTE%%`、`<!-- %%SLIDES%% -->`。
2. **主题样式**：默认粘贴 `themes/blog-sumsec.md` 的 CSS；仅在触发「可选企业主题」时改读 `vendor/slide-writer/themes/[id].md`。
3. **Logo**：博客默认主题按 `blog-sumsec.md` 隐藏或省略 Logo 块；企业主题遵守上游 Logo 规则且处理好缺失 PNG 时的降级。
4. **仓库硬约束的补全**：`_base.html` 未必自带「SUMSEC 回原文」「博客 favicon 相对路径」——必须通过额外内联 HUD、在封面外增加链接块、或生成后在同文件内追加最小补丁等方式满足 `html-template` / `repo-conventions` 中的硬要求，**不得**因为套了上游壳子而跳过。

## 进度通知（可选）

上游要求每个阶段向用户输出一行纯文本进度。本 skill **不强制**；若任务耗时长、页数多，可沿用上游格式简短汇报主题选择与页数规划，便于用户感知进度。
