# 视觉系统

## 设计目标

页面要看起来属于这个仓库，但不能像把整站博客直接套进幻灯片。

优先级：

1. 正式技术演讲稿
2. 高可读性
3. 克制的仓库科幻质感

## 默认主题（合并 Slide-Writer 后）

生成网页版 PPT 时，**默认**使用本 skill 的 **`blog-sumsec`** 主题（见 [`themes/blog-sumsec.md`](../themes/blog-sumsec.md) 与 [`themes/_index.md`](../themes/_index.md)），而不是 slide-writer 上游的蚂蚁蓝默认。

仅在用户明确要求企业/品牌汇报风，或 `themes/_index.md` 判定进入企业分支时，才读取 `vendor/slide-writer/themes/[id].md` 作为色板与 Logo 规则来源。

## 颜色 token

默认从 `assets/css/style.scss` 借用这组配色（与 `blog-sumsec` 一致，可作为手写 deck 的 `:root`）：

- `--bg: #05060c`
- `--accent: #5cdbcf`
- `--magenta: #94a8e8`
- `--green: #7dd79a`
- `--danger: #e0a050`
- `--text: #e8ecf4`
- `--text-muted: #8b95ab`

建议一个主强调色加少量辅助色，不要引入彩虹配色。

## 字体

默认沿用 `_layouts/default.html` 的组合：

- 标题：`Exo 2`、`Noto Sans SC`
- 正文 / 代码：`JetBrains Mono`、`Noto Sans SC`

## 版式原则

- 一页一个核心观点
- 标题要大，辅助文案要短
- 优先靠结构表达，不靠装饰堆砌
- 原文已有图片时，优先复用这些图片
- 长文可以做成长版 deck，但单页仍要一眼可扫

## 常用页面类型

- 封面页
- 大数字对比页
- 左右对照卡片页
- 工作流步骤页
- 引言 / 金句页
- 矩阵 / 象限页
- checklist 页
- 配图解释页

## 反 AI 味规则

避免：

- 满屏通用 SaaS 卡片
- 紫色渐变白底的通用 AI 审美
- 一页堆很多长段落
- 与内容无关的假仪表盘
- 夸张入场动画
- 把博客导航和 footer 原样搬进 deck

## 交互基线

默认交互：

- 键盘翻页
- 滚轮翻页
- 固定 HUD 显示当前页标题
- 页码计数
- 进度条
- 移动端纵向滚动兜底

## 视觉前置模板

开始生成前，先在推理里写：

```text
visual thesis: 正式技术演讲稿，带克制的深色科幻纵深
content plan: 封面 -> 证据 -> 机制 -> 方法 -> 结论
interaction thesis: 键盘翻页 + 滚轮翻页 + HUD进度
```
