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
      <!-- 标题、页码、控制区、进度条 -->
    </header>
    <main id="deck">
      <section class="slide" data-title="封面">
        <div class="slide-inner">...</div>
      </section>
    </main>
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
- `#deck`
- 多个 `section.slide`
- 通过 `data-title` 提供页标题
- 页码计数
- 进度条

## 必备交互

- `ArrowLeft` / `ArrowRight`
- `PageUp` / `PageDown`
- `Space`
- `Home` / `End`
- 桌面端滚轮翻页
- 尊重 reduced motion

## JS 典型职责

- 收集所有 slide
- 维护当前 slide 索引
- 更新页码和进度
- 滚动到当前 slide
- 通过 IntersectionObserver 更新 HUD

## CSS 典型职责

- 深色全屏背景
- 居中的 slide 画布
- 响应式单列兜底
- 足够强的正文对比度
- 固定在顶部的 HUD

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
