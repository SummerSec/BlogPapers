# 博客站点主题 `blog-sumsec`（与 slide-writer 企业主题并存）

与 `sumsec.me` 博客一致的深色、克制科幻感，配色与字体约定对齐 `references/visual-system.md` 与 `assets/css/style.scss`。

这是本仓库在合并 slide-writer 时**新增**的一条主题分支，用于「像本站一样」的演示；**不替代** `vendor/slide-writer/themes/` 下各企业主题文件。企业主题的全表与选用条件见 [`_index.md`](_index.md) 第二节。

本主题用于：

- **博客默认轨道**：自研单文件 deck（`references/html-template.md`）时，将下列 CSS 变量与渐变作为 `:root` / 关键页背景参考。
- **Slide-Writer 引擎轨道**：当且仅当本次选定主题为 **`blog-sumsec`** 时，从 `vendor/slide-writer/_base.html` 复制出 HTML 后，把 `<!-- %%THEME_STYLE%% -->` 替换为下方 **CSS** 块，使 `slide-cover` / `slide-section` / `slide-qa` 与博客站色一致。若本次选定的是 `vendor/slide-writer/themes/tencent.md` 等**企业主题**，则应粘贴**该文件**内的 CSS 与 Logo 规则，而不是本文件的色板。

## Logo（仅当选用本主题 `blog-sumsec` 时）

- **本主题不依赖** `vendor/slide-writer/logos/*.png`。
- **Slide-Writer `_base.html` 轨道 + 选用 blog-sumsec**：
  - `%%LOGO_GROUP%%`：可用隐藏占位，避免引用不存在的 PNG：

```html
<div id="globalLogoGroup" class="logo-group-single" style="display:none" aria-hidden="true"></div>
```

  - 封面 / 章节 / 结尾等深色页：可**省略**整个 `.fixed-logo-dark`；品牌与回链交给外层 HUD 的 `SUMSEC` 可点击链接（见 `references/html-template.md`）。

- **若选用 slide-writer 某一企业主题**：Logo、双 Logo、深色/白底页写法**一律**以对应 `vendor/slide-writer/themes/[id].md` 与 `vendor/slide-writer/themes/_index.md` 为准，并处理好 `logos/` 资源是否已复制到输出 HTML 同目录。

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
- 生成后浏览器级验证（`references/verification-checklist.md`）
