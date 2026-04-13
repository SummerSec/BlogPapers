---
name: slide-writer
display_name: Slide-Writer
description: 把想法、大纲、文档或草稿变成结构清晰、设计精良的企业级 HTML 演示文稿。
version: 0.2.0
author: Feei
homepage: https://github.com/FeeiCN/slide-writer
repository: https://github.com/FeeiCN/slide-writer
license: MIT
tags:
  - presentation
  - slides
  - ppt
  - keynote
  - html
  - storytelling
  - enterprise
entry: SKILL.md
language: zh-CN
compatible_with:
  - claude-code
  - codex
---

# Slide-Writer

把任意输入（想法、大纲、草稿文档、会议纪要）转化为企业级 HTML 演示文稿，自动匹配所在公司的品牌主题。

## 核心原则

1. **品牌一致** — 从请求中自动识别公司，应用对应品牌色主题；内置 14 家互联网公司主题。
2. **内容为王** — 自动润色每句话：去冗余、精简、让表达更有力。
3. **不溢出** — 每张幻灯片必须在 100vh 内完整呈现，内容多则分页，绝不出现滚动条。
4. **单文件交付** — 输出单个 `.html` 文件，CSS/JS 全部内联，零依赖，浏览器直接打开。

---

## 进度通知规范

在每个阶段开始前，必须向用户输出一行进度说明，让用户知道当前在做什么。格式统一为纯文本，不用 markdown 列表或标题，一句话即可。

| 时机 | 输出示例 |
|---|---|
| Phase 0 完成后（主题确定） | `已识别主题：腾讯，应用腾讯蓝主题。` |
| Phase 2 完成后（结构规划） | `规划完成，共 12 张幻灯片：封面 / 目录 / 背景 / …/ Q&A。` |
| Phase 3 开始前 | `开始生成 HTML 文件，共 12 张…` |
| Phase 4 保存完成后 | （见 Phase 4 输出规范） |

---

## Phase 0：自动更新 + 识别模式 + 主题检测

### 自动更新（第一步，必须执行）

在当前 skill 工作目录执行：

```bash
git pull --ff-only
```

- 成功 → 静默继续，无需告知用户
- 失败（无网络 / 有本地冲突）→ 静默忽略，继续使用当前版本，不打断流程

### 模式识别
- **Mode A：全新制作** — 从主题/大纲/草稿创建。进入 Phase 1。
- **Mode B：增强改稿** — 在现有 HTML 上修改或扩充内容。执行步骤：
  1. 完整读取现有 HTML 文件
  2. 识别原有主题（除非用户明确要求更换，否则保留）
  3. 按用户指示定位需要修改的幻灯片，精确替换对应 `<section>` 块
  4. 新增幻灯片插入到逻辑顺序最合适的位置，不打乱原有结构
  5. 未被点名的幻灯片保持原样，不做"顺手优化"
  6. 修改完成后，执行与 Mode A 相同的质量检查（不溢出、结构完整、logo 路径有效）

### 主题自动检测

**读取 [themes/_index.md](themes/_index.md)**，从用户请求中提取公司关键词，优先级从高到低：
1. 用户请求原文中明确提到的公司名、产品名
2. 署名中的部门/团队名称
3. 内容中出现的公司名

Phase 1 收集到「公司」字段后，如与初步判断不一致，以用户明确填写的为准并更新主题。

**匹配规则：**
- 识别到关键词 → 记录「主题 ID」和对应的 `themes/[id].md` 路径，生成时告知用户（如”已应用阿里巴巴橙色主题”）
- 未识别到 → 默认使用蚂蚁集团蓝色主题（`themes/ant-group.md`）
- 用户明确指定主题名 → 优先遵从用户指定
- 多品牌冲突、竞品对比场景 → 按 `themes/_index.md`「多品牌冲突处理」规则执行

---

## Phase 1：内容收集

**优先一次性收集以下信息：**

- **公司**（header: “公司”）：所在公司或品牌名称？（用于自动匹配主题色）
- **主题**（header: “主题”）：演讲/汇报的核心主题是什么？
- **受众**（header: “受众”）：管理层 / 团队内部 / 跨部门 / 外部客户？
- **页数**（header: “页数”）：5-8 页 / 10-15 页 / 20 页以上？
- **内容**（header: “内容”）：请直接粘贴大纲、草稿或关键要点。如果只有主题，说明即可。
- **署名**（header: “署名”）：演讲者姓名 + 角色/岗位/Title（用于封面）？
- **日期**（header: “日期”）：演讲日期？（默认今天）

如果运行环境支持 `AskUserQuestion`，一次性补问缺失项；如果不支持，就用一条普通消息补问，或在低风险场景下按默认值直接继续：

- 公司缺失 → 从内容、署名、部门名称中推断；仍无法识别则默认蚂蚁集团蓝
- 受众缺失 → 默认”管理层/跨部门汇报”
- 页数缺失 → 默认 5-8 页
- 日期缺失 → 默认今天
- 署名缺失 → 默认留空，但不要伪造职位

---

## Phase 2：结构规划

根据收集的内容，自动规划幻灯片结构：

### 演讲稿转 PPT 专项规则

如果输入是”演讲全文 / 发言稿 / 逐字稿 / 长文”，先做”演讲稿 → 演示结构”的转换，不要直接把原文分段贴到页面里。

1. **PPT 是演讲辅助，不是原文上墙** — 禁止逐段照搬；单页文字量必须明显少于讲稿密度；详细解释交给演讲者口头完成。
2. **一页一判断** — 先提炼一个结论句作为标题，再保留 2–4 个支撑点；多个论点拆成多页，允许重组顺序。
3. **留金句，删铺垫** — 保留原话中的数字、判断、类比；删除寒暄、重复、口语化过渡、背景铺垫；引用只取最有代表性的 1 句。
4. **3 秒可读** — 观众应在 3 秒内看懂这页在讲什么；副标题只做提示词，不写成第二段正文；bullet 和卡片描述优先短句，不写完整段落。
5. **第一视角** — 标题、副标题、过渡语优先”我 / 我们 / 今天想讲”；不写成”作者认为””整场发言围绕”等编辑转述口吻。

推荐转换顺序：

1. 先提炼演讲的 3-6 个核心判断
2. 再为每个判断找 2-4 个支撑点
3. 最后只挑少量最有代表性的原话做 quote

不适合保留到 PPT 的内容：

- 开场寒暄
- 重复表达同一观点的不同句子
- 口语化连接词和铺垫
- 大段故事细节
- 没有信息增量的抒情句
- 可以由演讲者口头补充的背景说明

### 视觉化原则

如果页面内容仍然“像一堆文字”，必须继续改写成更强的视觉结构，而不是直接交付。

默认遵守：

1. **先做结构，再放文字** — 优先用数字、卡片、对比、流程、章节页承载内容，不要先写满文字再找地方放。
2. **一页一种主视觉节奏** — 例如 3 个大数字、2 列对比、1 组 step-card；允许页面留白，不要为了信息完整把屏幕填满。
3. **把段落改成组件** — 长段优先改写成 `stat-block`、`step-card`、`quote-box`、`agenda-item` 等组件，而不是正文段落。
4. **关键词可扫读** — 数字、判断句必须一眼能扫到；长句只能作为补充。
5. **多横向，少纵向** — 优先并列卡片、对比、矩阵，少用连续多段纵向文字。
6. **每 3–4 页变换节奏** — 穿插章节页、金句页、超大字判断页或轻内容页，避免全稿信息密度完全一致。
7. **先判内容形态，再选版式** — 详见「内容类型 → 页面骨架 / 组件选择规则」。
8. **标题区固定** — 所有内容页默认复用统一的标题区位置；标题和副标题不应因正文密度不同而上下漂移。
9. **SVG 优先，减少文字密度** — 凡能用图形表达的关系（数量对比、趋势、占比、流程、层级、演进），必须用内联 SVG 替代文字描述；单页文字块超过 3 个时，主动考虑能否将其中 1 个改写为 SVG 图表或视觉元素；禁止用纯数字 + 文字句子描述可视化数据。

### 必须包含的页面
| 页面类型 | 用途 | Slide Class |
|---|---|---|
| 封面页 | 主题、副标题、演讲者 + 角色/岗位/Title、日期 | `slide-cover` |
| 目录页 | 用 agenda-item 列出所有章节 | `slide-white` |
| 章节过渡页 | 每个大章节开始前 | `slide-section` |
| 结尾页 | Q&A 或感谢 | `slide-qa` |

### 内容页密度规则

| 内容类型 | 普通场景上限 | 演讲稿场景上限 |
|---|---|---|
| 文字要点 | 4-6 条 bullet | **3 条**，每条 ≤ 12 字 |
| 信息卡片 | 3 列 info-card | **2 列**，卡片描述 ≤ 20 字 |
| 数据统计 | 3-4 个 stat-block | 3 个，配 1 句解读 |
| 对比/流程 | 2-4 个 step-card | **2 个**，描述 ≤ 15 字 |
| 表格 | 最多 5 行 × 4 列 | 最多 3 行 × 3 列 |
| 引用原话 | 1 段，30-50 字 | 1 句，**≤ 25 字** |
| 卡片描述正文 | 2-3 句话 | **1 句话**，禁止完整段落 |

超出限制 → 自动拆成多页，页间用连贯的过渡标题衔接。

### 内容类型 → 页面骨架 / 组件选择规则

在把每一部分内容写成 HTML 之前，必须先做一次“内容类型判断”，再决定使用哪种布局。优先级是：**页面级骨架 > 成组组件 > 普通 bullet / 段落**。

| 内容形态 | 优先页面骨架 / 组件 | 适用场景 | 避免用法 |
|---|---|---|---|
| 全文总览 / 章节预告 | 分组目录页、`agenda-item` | 目录页、章节总览、分阶段议程 | 直接用普通 bullet 平铺全篇目录 |
| 开场判断 / 问题定义 | 开场钩子页、2×2 信息面板、`highlight-box` + `info-card` | 开场第一页正文、问题陈述、背景变化 | 用整页长段正文解释背景 |
| 单一核心结论 | `highlight-box`、`stat-block`、大数字 + 简短支撑 | 这一页只讲一个明确判断 | 做成密集列表或多主题混页 |
| 并列要点 / 三原则 / 三抓手 | `three-col`、`info-card`、`stat-block` | 3 个并列观点、原则、分类 | 把 3 个平级观点写成纵向长段 |
| 双对象对比 / 两个重点方向 | `two-col`、左右图文混排 | A/B 对比、两类对象、两个重点模块 | 用单列顺序写法削弱对比感 |
| 分阶段推进 / 先后逻辑 | `step-card`、双阶段桥接流程、`step-flow-grid` | 路线图、推进步骤、阶段拆解 | 用普通 bullet 描述“第一、第二、第三” |
| 组织支撑 / 能力体系 | `support-board`、`support-card`、`role-card` | 横向能力、机制、专项保障 | 用多段正文描述体系结构 |
| 多角色流转 / 跨方协同 | `demand-flow-board` | 多角色参与、需求流转、协作看板 | 用静态列表描述角色流转 |
| 数据结构 / 占比 / 趋势 | `stat-block`、进度条、标签云、表格、SVG 柱状图 / 折线图 / 环形图 | 数据对比、趋势、构成、分布 | 没有图形支撑却只写数字句子 |
| 引用原话 / 观点摘录 | `quote-box`、`insight` | 保留一句金句或关键原话 | 堆多段长引用 |
| 结尾总结 / 行动主张 | 分组总结页、`agenda-item`、`highlight-box` | 结论页、行动建议、价值回收 | 结尾再次展开大量新信息 |

### 组件选择约束

- 先选页面骨架，再决定骨架内部放什么组件。
- 一页只保留一种主关系，不要同时把”对比 + 流程 + 目录 + 图表”塞进同一页。
- 如果内容天然属于 `support-board`、`demand-flow-board`、双阶段流程这类强结构页面，就不要退回普通卡片页。
- 如果只是 2-4 个短支撑点，优先用现有组件，不要新造大量自定义 HTML。
- 只有当 `components.md` 现有骨架都不适配时，才允许做轻量自定义布局。

### 布局多样性约束（强制）

规划完整体结构后，扫描一遍布局序列，同时满足以下局部和全局要求：

**局部约束（连续检查）：**
- 连续 3 页都是 `three-col` / `info-card` 三列 → 中间插入 `stat-block`、`highlight-box` 大字判断页、`step-card` 流程页或章节过渡页
- 连续 3 页都是普通 `styled-list` bullet → 至少 1 页改为卡片、数据或图文骨架
- 连续 2 页都是 `step-card` 流程 → 第 3 页必须换为其他骨架

**全局约束（整稿比例）：**
- 三列卡片页（`three-col` / `info-card`）占全稿内容页比例 ≤ 40%
- 整稿超过 8 页时，必须包含至少 1 页纯视觉页（大数字、金句、SVG 图表等）

**布局多样性检查清单**（生成前对照一遍）：

| 检查项 | 类型 | 要求 |
|---|---|---|
| 最长同类布局连续段 | 局部 | ≤ 2 页 |
| 三列卡片页占比 | 全局 | ≤ 40% |
| 纯视觉页（大数字/图表/金句）| 全局 | ≥ 1 页（超过 8 页时） |
| 章节过渡页间隔 | 局部 | 每 4–6 页内容页穿插 1 页 |

### 文字润色（自动执行，无需问用户）

结构规划完成后，在写 HTML 前对所有文字执行：

1. **去冗余** — 删除”我们认为””需要指出的是”等无信息量的前缀。
2. **名词化** — “进行分析”→”分析”，”做出决策”→”决策”。
3. **数字化** — 有数据的地方补充具体数字；没有数据时保持概括性但有力。
4. **动词有力** — 用”推进””落地””打通””提升””收敛”替代”做””进行””开展”。
5. **层级清晰** — 主标题是结论/判断，副标题是补充说明，内容是支撑。
6. **引用克制** — 原话引用只保留最有代表性的句子；同页不出现多段长引用。

---

## Phase 3：生成 HTML

### Step 3.1：准备输出文件 + 读取主题和组件

**① 复制 shell 模板**
```
cp _base.html [输出文件名].html
```
- `_base.html` 是预构建的引擎壳，含完整 CSS/JS，**禁止直接编辑 `_base.html` 本身**
- 输出文件名使用英文小写 + 连字符，例如 `antgroup-q1-review.html`

**② 并行读取以下两个文件**（同时发起，不要等一个读完再读另一个）

- **`themes/[id].md`**（Phase 0 已确定的公司主题文件，约 30 行）
  - 获取 CSS 变量块、`.slide-section` / `.slide-qa` 覆盖、logo 文件路径
  - 腾讯 / 字节跳动 / 苹果：文件内已包含补充规则，无需额外读取

- **`components.md`**（按需读取，不必全读）
  - Phase 2 结构规划时已确定每页用哪类组件，只需 Grep 提取对应章节
  - 例：只用到 `info-card` 和 `agenda-item` → 只读「信息卡片」和「目录/议程」两节

### Step 3.2：用 Edit 工具填充占位符

复制完 `_base.html` 后，**依次用 Edit 工具替换 5 个占位符**，不要重写整个文件：

**① 标题**
```
old: %%TITLE%%
new: [演讲主题] — [演讲者]
```

**② 主题样式覆盖**（内容直接从 `themes/[id].md` 的 CSS 块复制）
```
old: <!-- %%THEME_STYLE%% -->
new:
<style>
:root { ... }
.slide-section { background: ... !important; }
.slide-qa      { background: ... !important; }
</style>
```

**③ Logo 规范（白底页 + 深色页）**

文件选择（路径查 `themes/[id].md` 的「Logo」节，双 logo 规则查 `themes/_index.md`「双 Logo 展示规则」）：
- 白底页 → 彩色版（`-color.png` / `-blue.png`）
- 深色页 → 白色版（`-white.png`）；无则用彩色版 + `style=”filter:brightness(0) invert(1)”`

白底页：填充 `%%LOGO_GROUP%%` 占位符
```html
<!-- 单 logo -->
<div id=”globalLogoGroup” class=”logo-group-single”>
    <img src=”./logos/[brand]-color.png” alt=”[公司]”>
</div>

<!-- 双 logo -->
<div id=”globalLogoGroup” class=”logo-group-dual”>
    <img src=”./logos/[集团]-color.png” alt=”[集团]”>
    <span class=”logo-divider”></span>
    <img src=”./logos/[子品牌]-color.png” alt=”[子品牌]”>
</div>

<!-- 无 logo -->
<div id=”globalLogoGroup” class=”logo-group-single” style=”display:none;”></div>
```

深色页（封面 / 章节 / 结尾）：内联写入各 `<section>`，三种页面写法完全一致
```html
<!-- 单 logo（有白色版）-->
<div class=”fixed-logo-dark logo-group-single”>
    <img src=”./logos/[brand]-white.png” alt=”[公司]” class=”logo-img-cover”>
</div>

<!-- 单 logo（无白色版，用彩色版转白）-->
<div class=”fixed-logo-dark logo-group-single”>
    <img src=”./logos/[brand]-color.png” alt=”[公司]” class=”logo-img-cover”
         style=”filter:brightness(0) invert(1);”>
</div>

<!-- 双 logo -->
<div class=”fixed-logo-dark logo-group-dual”>
    <img src=”./logos/[集团]-white.png” alt=”[集团]” class=”logo-img-cover”>
    <span class=”logo-divider”></span>
    <img src=”./logos/[子品牌]-white.png” alt=”[子品牌]” class=”logo-img-cover”>
</div>

<!-- 无 logo：省略整个 .fixed-logo-dark，不写占位 -->
```

禁止事项：
- 不要在深色页 logo 上手写 `position:absolute`、`top:`、`right:`、`height:` 等定位和尺寸样式（CSS + JS 已统一处理）
- 不要用裸 `<img>` 放 logo，必须套在 `.fixed-logo-dark` 容器内
- 不要在不同页面用不同的 height clamp 值，尺寸由 CSS class 统一控制

**④ 页脚说明**
```
old: %%FOOTNOTE%%
new: * 仅限内部交流使用（或用户指定的文字）
```

**⑤ 幻灯片内容**
```
old: <!-- %%SLIDES%% -->
new: 所有 <section> 幻灯片 HTML
```

**主题应用说明：**
- `.slide-section` 和 `.slide-qa` 在基础 CSS 中使用硬编码渐变，必须用 `!important` 覆盖。
- `--primary-pale` 会自动影响 `info-card` 背景、`agenda-item` hover、`highlight-box` 等，无需逐一覆盖。
- logo 统一使用 `./logos/...` 相对路径。

### Step 3.3：幻灯片 HTML 结构

**封面页：**
```html
<section class="slide slide-cover" id="slide-1">
    <div class="cover-arcs" aria-hidden="true">
        <div class="arc arc-1"></div>
        <div class="arc arc-2"></div>
        <div class="arc arc-3"></div>
    </div>
    <!-- 深色页 logo：写法见 Step 3.2 ③；无 logo 时省略整个 .fixed-logo-dark -->
    <div class="fixed-logo-dark logo-group-single">
        <img src="./logos/[brand]-white.png" alt="[公司名] Logo" class="logo-img-cover">
    </div>
    <div class="cover-top reveal" style="display:flex;align-items:center;">
        <span style="color:rgba(255,255,255,0.65);font-size:clamp(0.65rem,1.1vw,0.85rem);">[部门名称]</span>
    </div>
    <div class="cover-main">
        <h1 class="cover-title reveal">[主标题]</h1>
        <p class="cover-subtitle reveal">[副标题/部门]</p>
        <p class="reveal" style="font-size:clamp(0.85rem,1.5vw,1.1rem);color:#fff;font-weight:700;">[演讲者姓名｜角色 / 岗位 / Title]</p>
    </div>
    <div class="cover-bottom">
        <div class="cover-date reveal">[日期]</div>
    </div>
</section>
```

**内容页（白色）：**
```html
<section class="slide slide-white" id="slide-N">
    <div class="slide-header center-stack">
        <span class="header-mark"></span>
        <h2 class="header-title">[页面标题（结论/判断句）]</h2>
        <p class="header-sub">[副标题（补充说明）]</p>
    </div>
    <div class="slide-body" style="justify-content:center;">
        <!-- 内容区，使用组件填充 -->
    </div>
</section>
```

**章节过渡页：**
```html
<section class="slide slide-section" id="slide-N">
    <!-- 深色页 logo：写法见 Step 3.2 ③；无 logo 时省略整个 .fixed-logo-dark -->
    <div class="fixed-logo-dark logo-group-single">
        <img src="./logos/[brand]-white.png" alt="[公司]" class="logo-img-cover">
    </div>
    <p class="section-num reveal">PART [章节号]</p>
    <h2 class="section-title reveal">[章节标题]</h2>
    <p class="section-desc reveal">[一句话说明这一章节要回答的问题]</p>
</section>
```

**结尾页：**
```html
<section class="slide slide-qa" id="slide-N">
    <!-- 深色页 logo：写法见 Step 3.2 ③；无 logo 时省略整个 .fixed-logo-dark -->
    <div class="fixed-logo-dark logo-group-single">
        <img src="./logos/[brand]-white.png" alt="[公司]" class="logo-img-cover">
    </div>
    <h2 class="qa-title reveal">Q&amp;A</h2>
    <p class="qa-sub reveal">[感谢语]</p>
</section>
```

**演讲稿专项密度检查**（输入为演讲稿时，每页生成后执行）：

对照以下标准自检，不达标则继续精简或拆页：

- 这一页，站在 3 米外能在 5 秒内看完吗？→ 不能则继续删
- 卡片 / bullet 描述里有完整段落吗？→ 有则压缩到 1 句话
- 同一页里出现了 2 个以上并列模块吗？→ 拆成 2 页
- 标题是结论句还是话题词？→ 必须是结论句（"我们做了 X" 而非 "X 的情况"）

---

## Phase 4：输出

1. **保存** — 将文件保存到当前工作目录。文件名使用英文小写 + 连字符，例如 `antgroup-q1-review.html`、`alibaba-ai-strategy.html`；主题关键词是中文时转为拼音或英译，避免中文文件名造成路径兼容问题。
2. **用浏览器打开** — 执行 `open [文件名].html` 自动在默认浏览器中打开。
3. **告知用户：**
   - 文件路径、幻灯片总数、应用的主题名称
   - 导航：方向键 / 空格翻页，点击右侧圆点导航，`F` 全屏
   - 如需修改：直接编辑 HTML 文件，或告知我继续修改

---

## 支持文件

| 文件 | 用途 | 何时读取 |
|---|---|---|
| [_base.html](_base.html) | 预构建引擎壳（含完整 CSS/JS），生成时 `cp` 为输出文件再用 Edit 填充 | Phase 3 Step 3.1（必须） |
| [themes/_index.md](themes/_index.md) | 主题识别规则 + 集团/子品牌关键词表 + logo 索引 + 双 logo 规则 | Phase 0 主题检测（只读此一个文件） |
| `themes/[id].md` | 单公司主题文件（~30 行）：CSS 变量 + logo 路径 + 补充规则 | Phase 3 Step 3.1（只读匹配到的那一个） |
| [components.md](components.md) | 所有可用组件的 HTML 片段参考 | Phase 3 按需 Grep 对应章节，不必全读 |
| `logos/[变体]-white.png` | 公司 Logo 白色版（深色幻灯片使用） | Phase 3 Step 3.1（有 logo 时） |
| `logos/[变体]-blue.png` / `logos/[变体]-color.png` | 公司 Logo 彩色版（白色幻灯片使用） | Phase 3 Step 3.1（有 logo 时） |
| [index.html](index.html) | 完整示例文档，含所有组件的真实渲染样例 | 需要查阅组件骨架细节时（只读参考） |

---


## 非目标 / 不处理的事情

- 不直接生成 .pptx 文件，只输出单个 HTML 文件
- 不负责从互联网自动抓取事实内容，除非用户明确提供素材
- 不伪造演讲者身份、职位、部门信息
- 不擅自修改未被点名的现有页面
- 不保证所有品牌主题都与官方品牌规范完全一致
