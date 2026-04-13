# 博客站点主题 `blog-sumsec`（slide-writer 增补主题 ID）

与 `sumsec.me` 博客一致的深色、克制科幻感，配色与字体约定对齐 [`../../references/visual-system.md`](../../references/visual-system.md) 与 `assets/css/style.scss`（仓库根目录）。

本文件定义主题 ID **`blog-sumsec`**，与本目录下 `ant-group`、`tencent` 等主题文件**并列**；选用条件与 Phase 0 顺序见 [`_index.md`](_index.md) 文首「BlogPapers Phase 0 增补顺序」。

本主题用于：

- **自研 HUD 轨道**：当 Phase 0 选定主题为 **`blog-sumsec`** 时，将下列 CSS 变量与渐变写入单文件 HTML 的 `:root` / 关键页背景。
- **Slide-Writer `_base.html` 轨道**：当且仅当本次选定主题为 **`blog-sumsec`** 时，把 `<!-- %%THEME_STYLE%% -->` 替换为下方 **CSS** 块。若主题为某企业 `[id]`，则应粘贴**同目录** `[id].md`（如 `tencent.md`）内的 CSS 与 Logo 规则，而不是本文件。

## Logo（仅当选用本主题 `blog-sumsec` 时）

- **本主题不依赖** `../logos/*.png`（相对 `_base.html` 所在目录的 `logos/`，若快照未带 PNG 则隐藏 Logo 即可）。
- **Slide-Writer `_base.html` 轨道 + 选用 blog-sumsec**：
  - `%%LOGO_GROUP%%`：可用隐藏占位，避免引用不存在的 PNG：

```html
<div id="globalLogoGroup" class="logo-group-single" style="display:none" aria-hidden="true"></div>
```

  - 封面 / 章节 / 结尾等深色页：可**省略**整个 `.fixed-logo-dark`；品牌与回链交给外层 HUD 的 `SUMSEC` 可点击链接（见 [`../../references/html-template.md`](../../references/html-template.md)）。

- **若选用 slide-writer 某一企业主题**：Logo、双 Logo、深色/白底页写法**一律**以对应同目录 `[id].md` 与 [`_index.md`](_index.md) 为准，并处理好 `logos/` 资源是否已复制到输出 HTML 同目录。

- **自研 deck 轨道**：HUD 内 `SUMSEC` / `sumsec` 品牌位必须可点击跳转到**原文公开地址**，不得使用纯文本冒充链接。

## CSS

变量命名尽量与 Slide-Writer 主题文件对齐，便于覆盖 `_base.html` 内默认色板。

```css
:root {
  --primary:       #5cdbcf;
  --primary-dark:  #2fb8ae;
  --primary-light: #8df2ea;
  --primary-pale:  rgba(92, 219, 207, 0.12);
  --primary-dim:   rgba(92, 219, 207, 0.18);
  --cover-bg:      radial-gradient(1200px 800px at 70% 10%, rgba(148, 168, 232, 0.35), transparent 55%),
                   radial-gradient(900px 600px at 10% 90%, rgba(92, 219, 207, 0.22), transparent 50%),
                   linear-gradient(135deg, #05060c 0%, #0a1020 45%, #070b14 100%);
  --section-bg:    linear-gradient(135deg, #060814 0%, #0d1830 55%, #0a1628 100%);
  --red:           #e0a050;
  --green:         #7dd79a;
  --orange:        #94a8e8;
}

.slide-section {
  background: linear-gradient(135deg, #060814 0%, #0d1830 55%, #0a1628 100%) !important;
}

.slide-qa {
  background: radial-gradient(800px 500px at 80% 0%, rgba(92, 219, 207, 0.25), transparent 55%),
              linear-gradient(125deg, #05060c 0%, #0b1224 40%, #0a1020 100%) !important;
}
```

## 字体提示

- 标题倾向：`Exo 2`、`Noto Sans SC`
- 正文 / 代码：`JetBrains Mono`、`Noto Sans SC`

若 `_base.html` 已内联字体栈，可不再重复 `@import`；仅在需要与博客完全同族时，再按 `_layouts/default.html` 的 `link` 方案补齐 webfont（注意单文件体积与离线打开场景）。

## 与仓库硬约束的关系

使用本主题**不放宽**以下仓库级要求：

- 同目录、同 basename 单文件 HTML（除非用户明确覆盖）
- 右下角全屏按钮、`SUMSEC` 链到原文、主画布不超视口、原文图片不撑破舞台
- 生成后浏览器级验证（[`../../references/verification-checklist.md`](../../references/verification-checklist.md)）
