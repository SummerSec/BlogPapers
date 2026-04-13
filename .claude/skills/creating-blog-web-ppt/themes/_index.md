# 主题说明：与 slide-writer 一致，仅增补 `blog-sumsec`

本 skill 的**主题流程以 slide-writer 为准**（见 `vendor/slide-writer/SKILL.md` Phase 0 与 [`../vendor/slide-writer/themes/_index.md`](../vendor/slide-writer/themes/_index.md)）：企业关键词、子品牌、多品牌冲突、Logo 组合、未识别时的**上游默认**（**蚂蚁集团 `ant-group`**）均**不修改**。

本目录**只做一件事**：在 BlogPapers 场景下，**多提供一个主题 ID** —— **`blog-sumsec`**（[`blog-sumsec.md`](blog-sumsec.md)），与 `ant-group`、`tencent` 等**并列**，供选用。

---

## Phase 0 执行顺序（合并版）

1. **先**按 slide-writer 原文：读取 [`../vendor/slide-writer/themes/_index.md`](../vendor/slide-writer/themes/_index.md)，做企业/子品牌识别；若得到主题 ID（如 `tencent`），则使用 `../vendor/slide-writer/themes/<id>.md`（将 `<id>` 替换为实际 ID，如 `tencent.md`）。
2. **用户显式指定**主题名或 `blog-sumsec` / 某公司名时，以用户为准（与上游「用户明确指定」优先级一致）。
3. **仅当**第 1 步**没有**匹配到任何企业主题 ID（在上游规则下会落入「未识别 → 使用 `ant-group`」之前），再检查下面 **「博客站主题」关键词**；若命中，则主题 ID 改为 **`blog-sumsec`**，读取 [`blog-sumsec.md`](blog-sumsec.md) 的 CSS / Logo 约定。
4. 若第 3 步也未命中博客关键词，则主题 ID 为 **`ant-group`**，读取 [`../vendor/slide-writer/themes/ant-group.md`](../vendor/slide-writer/themes/ant-group.md) —— **与 slide-writer 默认完全一致**。

> 说明：第 3 步是**唯一**相对上游新增的分支；其余与 [FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer) 行为对齐。

---

## 博客站主题 `blog-sumsec` 命中关键词（增补）

仅在**未**匹配到企业 `[id]` 时评估；命中**任一**即可选用 `blog-sumsec`（仍可由用户一句话改选企业主题）：

- `blog-sumsec`、`sumsec` 站色、`sumsec.me`、`SUMSEC` 站、与本站一致、博客站色、sumsec 博客风（及用户明确表达的同义说法）

**不要**用泛词「博客」单独作为唯一条件，以免与普通技术文章混淆；除非用户明确「要博客站视觉 / sumsec 风」。

---

## 企业主题表与 Logo

企业主题 ID 列表、子品牌表、双 Logo 规则仍以 **`../vendor/slide-writer/themes/_index.md`** 为权威；各主题 CSS 在 **`../vendor/slide-writer/themes/[id].md`**。

`logos/` PNG 本快照可能不全：需要显示 Logo 时，从上游仓库 `logos/` 复制到与输出 HTML 同目录，或按上游无 Logo 规则降级。

---

## 与两条生成轨道的关系（仅主题来源不同）

- **自研 HUD 轨道**（`references/html-template.md`）：结构与交互按本仓库约定；**色板**仍由上面 Phase 0 得到的主题 ID 决定（`blog-sumsec.md` 或某 `vendor/.../themes/[id].md`）。
- **Slide-Writer `_base.html` 轨道**：占位符填充与上游相同；`<!-- %%THEME_STYLE%% -->` 粘贴**当前主题 ID** 对应文件的 CSS 块（`blog-sumsec` 或企业 `[id]`）。
