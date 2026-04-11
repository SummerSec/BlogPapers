# HTML 模板

默认生成一个内联 CSS 和 JS 的单文件 HTML deck。

## 最小结构

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <meta name="theme-color" content="#05060c">
  <title>文章标题 · 网页版 PPT</title>
  <link rel="icon" href="../assets/favicon.svg" type="image/svg+xml" sizes="any">
  <style>
    /* 仅内联 CSS */
  </style>
</head>
<body>
  <div class="deck-shell">
    <header class="deck-hud">
      <!-- 原文入口、当前标题、页码、控制区、进度条 -->
    </header>
    <main id="deck">
      <section class="slide" data-title="封面">
        <div class="slide-inner">...</div>
      </section>
    </main>
    <button class="deck-fullscreen-toggle" type="button" aria-label="切换全屏">
      全屏
    </button>
  </div>
  <script>
    /* 仅内联 JS */
  </script>
</body>
</html>
```

## 必备元素

- `.deck-shell`
- `.deck-hud`
- `.hud-brand`
- `#deck`
- 多个 `section.slide`
- 通过 `data-title` 提供页标题
- 页码计数
- 进度条
- 右下角全屏按钮，如 `.deck-fullscreen-toggle`

如果页面里使用 `SUMSEC` / `sumsec` 品牌位，默认写成：

```html
<a class="hud-brand" href="原文公开地址" aria-label="查看原文">
  <span>SUMSEC</span>
  <strong>WEB PPT</strong>
</a>
```

不要把它写成纯文本 `div` 或 `span`。

## 原文地址规则

默认把原文公开地址理解为“博客里这篇文章最终可访问的 HTML 页面地址”，不是仓库地址，也不是生成的 PPT 页面地址。

默认推导方式：

- 站点根地址取 `_config.yml` 中的 `url`
- 若 `baseurl` 非空，则拼接 `baseurl`
- 文章路径按仓库相对路径推导
- `YYYY/post-name.md` 默认对应 `https://sumsec.me/YYYY/post-name.html`

如果原文 front matter 显式设置了 `permalink`、`redirect_from` 或其他会改变公开访问路径的规则，则优先使用该公开路径。

## 画布与视口约束

deck 的“主画布”必须始终被限制在当前视口内，不能让用户依赖浏览器缩放来阅读。

默认要求：

- 优先给主内容容器设置 `max-width: calc(100vw - 安全边距)`
- 优先给主内容容器设置 `max-height: calc(100vh - HUD高度 - 上下边距)`
- 需要固定比例时，使用 `aspect-ratio`，并与 `width` / `max-width` / `max-height` 联合约束
- 优先使用 `clamp()`、`min()`、`max()` 控制字体、间距和模块尺寸
- 页面不应因主画布产生横向滚动
- 首屏 slide 在常见桌面视口下应完整落在可视区域内
- 当视口过窄、过矮或内容过多时，允许切换为纵向流式布局，而不是硬撑固定舞台

常见安全做法：

- 桌面端用一个受限宽高的舞台容器承载 `slide-inner`
- 移动端或矮屏下改为 `min-height: auto`、`height: auto`、纵向滚动阅读
- 对大标题、网格、多列布局设置断点，必要时降级为单列

## 必备交互

- `ArrowLeft` / `ArrowRight`
- `PageUp` / `PageDown`
- `Space`
- `Home` / `End`
- 桌面端滚轮翻页
- 右下角全屏按钮切换全屏
- 尊重 reduced motion

## JS 典型职责

- 收集所有 slide
- 维护当前 slide 索引
- 更新页码和进度
- 滚动到当前 slide
- 通过 IntersectionObserver 更新 HUD
- 使用 `Fullscreen API` 处理进入/退出全屏，并同步按钮文案或状态

## CSS 典型职责

- 深色全屏背景
- 居中的 slide 画布
- 响应式单列兜底
- 足够强的正文对比度
- 固定在顶部的 HUD
- 通过视口约束避免主画布超宽或超高
- 右下角提供固定定位、可点击且不遮挡主内容的全屏按钮

## 响应式底线

以下情况都不能算合格：

- 首屏主要内容超出视口，被浏览器直接裁掉
- 缩小窗口后出现横向滚动条
- 为了保固定比例，导致文字或图表被压到不可读
- 小屏下仍保持桌面多列布局，导致信息挤压

## 内容映射提醒

不要把 Markdown 原文 1:1 原样塞进去。

应把文章内容映射为这类页面：

- 封面
- 问题提出
- 证据 / 对比
- 机制解释
- 流程 / 方法
- 工具 / 框架
- 结论
