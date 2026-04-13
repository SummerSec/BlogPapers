# 主题索引（creating-blog-web-ppt · 双体系保留）

本 skill **同时保留**两套彼此独立的视觉体系，互不替代：

1. **博客站补充主题 `blog-sumsec`**：见 [`blog-sumsec.md`](blog-sumsec.md)，对齐 `sumsec.me` / `style.scss`，用于「像本站一样」的博文演示。
2. **[FeeiCN/slide-writer](https://github.com/FeeiCN/slide-writer) 内置企业主题族**：完整保留在 `vendor/slide-writer/themes/`，识别规则、多品牌冲突与 Logo 组合仍以 **[`../vendor/slide-writer/themes/_index.md`](../vendor/slide-writer/themes/_index.md)** 为权威说明；每个品牌对应一个 `../vendor/slide-writer/themes/[id].md`（CSS 变量 + `.slide-section` / `.slide-qa` + Logo 路径）。

生成前必须先决定本次落点在哪一套（或用户是否已指定），再只读**需要**的主题文件，避免把两套规则混在一起。

---

## A. 何时用 `blog-sumsec`（博客站）

在**未**指定 slide-writer 企业主题、且**未**从内容/用户话术中匹配到企业品牌关键词时，若属于下面任一情况，使用 **`blog-sumsec`**：

- 从本仓库 `YYYY/*.md` 做「博文转网页版 PPT」且用户只说「按博客风 / 站色 / sumsec」
- 用户明确说「跟博客一致」「深色科幻阅读感」「用 blog-sumsec」
- 用户明确说「不要企业品牌色」

这只是在**缺省场景**用博客色板取代上游「未识别品牌 → 蚂蚁蓝」的默认；**不代表**删除或禁用 slide-writer 各企业主题文件。

---

## B. 何时用 slide-writer 企业主题（全量保留）

以下任一情况，应走 **slide-writer 主题族**，读取 **`vendor/slide-writer/themes/[id].md`**（并配合上游 `themes/_index.md` 做识别与 Logo 规则）：

- 用户点名公司/品牌、主题名（如「腾讯蓝」「用 ant-group」「阿里巴巴橙」）
- 用户说「按 slide-writer 企业风」「用上游默认企业主题」→ 按上游惯例使用 **`ant-group`**（[`../vendor/slide-writer/themes/ant-group.md`](../vendor/slide-writer/themes/ant-group.md)）
- 正文/署名里出现可匹配关键词，按 [`../vendor/slide-writer/themes/_index.md`](../vendor/slide-writer/themes/_index.md) 命中对应 `[id]`
- 使用 **`vendor/slide-writer/_base.html`** 且用户要求「纯正企业模板色」而非博客站色

### 本仓库已快照的主题 ID 与文件（与上游一致，均需保留可用）

| 主题 ID | 主题文件 |
|--------|-----------|
| `ant-group` | [`../vendor/slide-writer/themes/ant-group.md`](../vendor/slide-writer/themes/ant-group.md) |
| `alibaba` | [`../vendor/slide-writer/themes/alibaba.md`](../vendor/slide-writer/themes/alibaba.md) |
| `tencent` | [`../vendor/slide-writer/themes/tencent.md`](../vendor/slide-writer/themes/tencent.md) |
| `bytedance` | [`../vendor/slide-writer/themes/bytedance.md`](../vendor/slide-writer/themes/bytedance.md) |
| `meituan` | [`../vendor/slide-writer/themes/meituan.md`](../vendor/slide-writer/themes/meituan.md) |
| `jd` | [`../vendor/slide-writer/themes/jd.md`](../vendor/slide-writer/themes/jd.md) |
| `baidu` | [`../vendor/slide-writer/themes/baidu.md`](../vendor/slide-writer/themes/baidu.md) |
| `huawei` | [`../vendor/slide-writer/themes/huawei.md`](../vendor/slide-writer/themes/huawei.md) |
| `xiaomi` | [`../vendor/slide-writer/themes/xiaomi.md`](../vendor/slide-writer/themes/xiaomi.md) |
| `netease` | [`../vendor/slide-writer/themes/netease.md`](../vendor/slide-writer/themes/netease.md) |
| `didi` | [`../vendor/slide-writer/themes/didi.md`](../vendor/slide-writer/themes/didi.md) |
| `microsoft` | [`../vendor/slide-writer/themes/microsoft.md`](../vendor/slide-writer/themes/microsoft.md) |
| `google` | [`../vendor/slide-writer/themes/google.md`](../vendor/slide-writer/themes/google.md) |
| `apple` | [`../vendor/slide-writer/themes/apple.md`](../vendor/slide-writer/themes/apple.md) |

子品牌、双 Logo、多品牌冲突等细则**一律**以 `vendor/slide-writer/themes/_index.md` 为准，本文件不重复维护一份「第二真相」。

### Logo 资源（企业主题）

上游 `themes/[id].md` 中的 `./logos/...` 指向品牌 PNG。本仓库 `vendor/slide-writer/` 快照**默认不含** `logos/` 目录；当选用企业主题且需要显示 Logo 时：

- 将所需 PNG 从 [上游仓库 `logos/`](https://github.com/FeeiCN/slide-writer/tree/main/logos) 复制到**与输出 HTML 同目录**的 `logos/` 下，保持 `./logos/...` 相对路径有效；或
- 按上游「无 Logo」规则隐藏 `%%LOGO_GROUP%%` / `.fixed-logo-dark`，**禁止**引用不存在的路径导致裂图。

---

## C. 与两条生成轨道的关系（主题层）

- **博客默认轨道**（自研 HUD + `references/html-template.md`）：主题通常用 **`blog-sumsec.md`** 的 token；若用户指定某企业风，也可把对应 `vendor/slide-writer/themes/[id].md` 的 CSS 变量**改写**进自研 deck 的 `:root`（实现成本自负），不得声称「本轨道不支持企业色」。
- **Slide-Writer 引擎轨道**（`vendor/slide-writer/_base.html`）：`<!-- %%THEME_STYLE%% -->` 填入 **本次选定**主题的 CSS：可以是 **`blog-sumsec.md`**，也可以是 **任意** `vendor/slide-writer/themes/[id].md` 中的块；由本节 A/B 判定，而不是固定死只能博客色。
