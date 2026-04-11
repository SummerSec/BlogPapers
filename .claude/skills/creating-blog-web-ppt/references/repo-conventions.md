# 仓库约定

## 输出路径

对于源文章：

```text
YYYY/post-name.md
```

默认创建：

```text
YYYY/post-name.html
```

规则：

- 与 Markdown 原文同目录
- 与原文同 basename
- 只把 `.md` 改成 `.html`

如果该文章已经存在同名 companion HTML，就更新原文件，不要再创造一个新名字。

## 资源路径

所有资源路径都以“文章所在目录”为基准处理。

常见情况：

- favicon：`../assets/favicon.svg`
- 文章局部图片：`./pic/...`

如果 Markdown 里已经用了：

```text
./pic/llm/foo.png
```

并且 HTML 也放在同目录，那么 HTML 中也应保持同样的相对路径。

## 允许借用什么

可以读取但不要直接依赖：

- `assets/css/style.scss`
- `_layouts/default.html`

可以借用：

- 配色 token
- 字体选择
- 深色科幻阅读氛围

不要直接复用：

- 站点导航
- footer
- 评论区
- 浏览量统计逻辑
- Liquid 模板
- 整页 Jekyll layout 包装

## 默认不要改什么

除非用户明确要求，否则不要改：

- `README.md`
- `resources/Archives.md`
- 站点导航
- 首页和归档里的链接入口

## 本仓库常见误区

- 习惯性把文件写到 `resources/`
- 输出临时名字，比如 `semantic-trap-skill-ppt.html`
- 没必要地把本地图片路径改成别的根路径
- 误以为独立演示页也必须写 Jekyll front matter
