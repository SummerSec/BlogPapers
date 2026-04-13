# 主题索引（creating-blog-web-ppt · 合并版）

本文件用于在本 skill 内解析「用哪套色板与 Logo 规则」，取代上游 slide-writer 在未识别品牌时默认落到的蚂蚁蓝。

## 默认（最高优先级）

以下任一情况，一律使用 **`blog-sumsec`**，读取 [`blog-sumsec.md`](blog-sumsec.md)：

- 从本仓库 `YYYY/*.md` 生成网页版 PPT（本 skill 主场景）
- 用户未明确要求「企业风 / 某公司产品汇报 / 某品牌主题」
- 用户要求「跟博客一致 / sumsec 站色 / 深色科幻阅读感」

## 可选企业主题

当用户**明确要求**使用某互联网公司品牌风、或演讲场景明显是「对外企业汇报」而非个人博客技术演讲时：

1. 读取 [`../vendor/slide-writer/themes/_index.md`](../vendor/slide-writer/themes/_index.md) 做关键词与多品牌冲突处理。
2. 读取匹配到的 `../vendor/slide-writer/themes/[id].md`，取得 CSS 变量与 Logo 路径说明。
3. **Logo 资源**：本仓库快照不含 `logos/` PNG。若主题文件要求 `./logos/...` 而文章目录下不存在对应文件，必须按上游「无 Logo」规则省略图片或隐藏 `globalLogoGroup`，**禁止**引用不存在的相对路径导致裂图。

## 与两条生成轨道的关系

- **博客默认轨道**（自研 HUD + `references/html-template.md`）：主题 = `blog-sumsec.md` 的 token + 渐变；结构规划可吸收 `references/slide-writer-merge.md` 中的 Phase 2 规则。
- **Slide-Writer 引擎轨道**（复制 `vendor/slide-writer/_base.html` 再填占位符）：主题 CSS 默认仍用 `blog-sumsec.md`；仅当用户或场景触发「可选企业主题」时，才改读 `vendor/slide-writer/themes/[id].md`。
