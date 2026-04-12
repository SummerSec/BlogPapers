# Remotion 画面与博客视觉对齐

Remotion 画布内的色值与字体应让读者感到「和 sumsec.me 同一套语言」，而不是通用 SaaS 或高饱和 AI 模板。

## 颜色（与 `assets/css/style.scss` 一致）

在组件中优先使用下列 hex（变量名仅作说明，TSX 里直接写色值即可）：

| Token | Hex | 用途 |
|-------|-----|------|
| bg | `#05060c` | 主背景 |
| accent | `#5cdbcf` | 主强调、高亮边 |
| magenta | `#94a8e8` | 辅助结构、次要强调 |
| green | `#7dd79a` | 正向 / 成功语义 |
| danger | `#e0a050` | 警告、摩擦点 |
| text | `#e8ecf4` | 主文案 |
| text-muted | `#8b95ab` | 说明、标签 |

原则：一主强调 + 少量辅助色，避免彩虹渐变铺满。

## 字体

与 `_layouts/default.html` 对齐的意图即可（Remotion 侧可用系统栈或内联 `link` 引入）：

- 标题气质：`Exo 2`、无则 `Noto Sans SC`
- 正文与等宽感：`JetBrains Mono` + `Noto Sans SC`

## 版式与动效

- 一镜一个信息层次；大字短句优于长段落。
- 动效服务于「读一遍就懂」，避免无意义装饰循环。
- 导出前在 **暗色背景** 下检查细线与文字是否发灰不可读。

## 延伸阅读

- 更完整的版式与反 AI 味规则：`../creating-blog-web-ppt/references/visual-system.md`
