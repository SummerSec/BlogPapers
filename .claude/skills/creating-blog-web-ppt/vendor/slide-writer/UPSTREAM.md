# slide-writer 上游快照

本目录为 [FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer) 的精简快照，供 `creating-blog-web-ppt` 读取 `_base.html`、`components.md` 与**完整** `themes/*.md`（含 `themes/_index.md` 与各企业 `[id].md`）。主题 Phase 0 以本目录内上游文件为准；BlogPapers 仅在 skill 的 `themes/_index.md` + `themes/blog-sumsec.md` **增补**一个主题 ID `blog-sumsec`，不改变上游默认 **`ant-group`** 逻辑。

- **快照提交**：`fed00af0904b7c879d584dc47df1fecb3c614070`（以当时 `origin/main` 为准）
- **许可证**：上游 README 声明为 **MIT**；使用与再分发请遵守上游条款并保留署名。
- **更新方式**：需要新版本时，在仓库维护者机器上对上游执行同步后替换本目录对应文件（或重新执行稀疏克隆），不要假设终端环境一定能访问 GitHub。

本快照**不包含** `logos/` 下的二进制资源。若选用企业主题且需要品牌 Logo，请自行从上游仓库获取 `logos/` 并放到**与输出 HTML 同目录**的 `logos/` 下，或按无 Logo 规则省略图片。
