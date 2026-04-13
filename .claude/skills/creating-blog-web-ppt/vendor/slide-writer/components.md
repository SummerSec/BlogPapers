# Component Library — Slide-Writer

所有组件均已在 CSS 中定义，直接使用对应 class 即可。添加 `reveal` class 启用入场动画（向上淡入）、`reveal-left` 启用从左淡入动画。

---

## 布局容器

### 两列 / 三列 Grid
```html
<!-- 两列等宽 -->
<div class="two-col">
    <!-- 左列内容 -->
    <!-- 右列内容 -->
</div>

<!-- 三列等宽 -->
<div class="three-col">
    <!-- 列1 --><!-- 列2 --><!-- 列3 -->
</div>
```

---

## 数据展示

### 统计数字块 `stat-block`
大号数字配说明文字，适合展示关键指标。
```html
<div class="stat-block">
    <div class="stat-num">85%</div>          <!-- 蓝色大数字 -->
    <div class="stat-label">代码生成采纳率</div>
</div>

<!-- 红色变体 -->
<div class="stat-num red">-40%</div>
```

### 目标卡片 `goal-card`
超大数字 + 标题 + 描述，适合展示 OKR 或关键目标。
```html
<div style="display:flex;gap:1rem;">
    <div class="goal-card">
        <div class="goal-num-big">85<span class="unit">%</span></div>
        <div class="goal-label">AI 代码覆盖率目标</div>
        <div class="goal-sublabel">2025 年底前达成</div>
    </div>
</div>
```

---

## 信息卡片

### 信息卡 `info-card`（最常用）
左侧彩色竖线，灰色背景，适合要点/特性展示。
```html
<div class="info-card">                          <!-- 默认蓝色竖线 -->
    <div class="card-title">高可用</div>
    <div class="card-body">说明文字，两三句话即可。</div>
</div>

<!-- 颜色变体：在 class 后加 red / green / orange -->
<div class="info-card red">...</div>
<div class="info-card green">...</div>
<div class="info-card orange">...</div>
```

### 步骤卡 `step-card`
渐变背景，适合展示分步骤/阶段。
```html
<div style="display:flex;gap:1rem;">
    <div class="step-card step-card-1">   <!-- 浅蓝渐变 -->
        <div class="step-num">STEP 01</div>
        <div class="step-title">启动阶段</div>
        <div class="step-desc">描述文字</div>
    </div>
    <div class="step-card step-card-2">   <!-- 浅靛渐变 -->...</div>
    <div class="step-card step-card-3">   <!-- 浅紫渐变 -->...</div>
    <div class="step-card step-card-4">   <!-- 浅橙渐变 -->...</div>
</div>
```

### 支持卡 `support-card`
带图标的功能/服务卡，适合展示支撑体系。
```html
<div style="display:flex;gap:1rem;">
    <div class="support-card">
        <div class="support-icon">🛡️</div>
        <div class="support-title">安全合规</div>
        <ul class="support-items">
            <li>数据脱敏规范</li>
            <li>工具准入清单</li>
        </ul>
    </div>
</div>
```

### 角色卡 `role-card`
展示职能角色的演进/变化。
```html
<div style="display:flex;gap:1rem;">
    <div class="role-card">
        <div class="role-icon">👨‍💻</div>
        <div class="role-name">研发工程师</div>
        <div class="role-arrow">传统 → AI增强</div>
        <div class="role-evolution">AI 辅助代码审查、单测生成、文档撰写</div>
    </div>
</div>
```

---

## 目录 / 议程

### 议程条目 `agenda-item`
带编号、标签的议程列表，适合目录页。
```html
<div style="display:flex;flex-direction:column;gap:0.6rem;max-width:72%;margin:0 auto;">
    <div class="agenda-item reveal">
        <span class="agenda-num">01</span>
        <span class="agenda-text">为什么要做这件事</span>
        <span class="agenda-tag" style="background:#FFF1F0;color:#E8380D;">背景</span>
    </div>
    <div class="agenda-item reveal">
        <span class="agenda-num">02</span>
        <span class="agenda-text">现状与问题</span>
        <span class="agenda-tag" style="background:#E6F4FF;color:#1677FF;">分析</span>
    </div>
</div>
```

---

## 文字组件

### 高亮引用框 `highlight-box`
重要结论或引用，左蓝竖线背景。默认全宽拉伸，如需限制宽度必须同时加 `margin: 0 auto` 居中，否则会左对齐偏歪。
```html
<div class="highlight-box reveal">
    <strong>核心判断：</strong>这里写最重要的一句话结论。
</div>

<!-- 红色警示变体 -->
<div class="highlight-box red-box reveal">危险或紧急提示</div>

<!-- 限制宽度时必须同时加 margin: 0 auto，否则会左对齐偏歪 -->
<div class="highlight-box reveal" style="max-width:900px;">
    <strong>核心判断：</strong>限制宽度时居中显示。
</div>
```

### 标签 `tag`
行内标签，适合分类或标注。
```html
<span class="tag tag-blue">蓝色标签</span>
<span class="tag tag-red">红色标签</span>
<span class="tag tag-green">绿色标签</span>
<span class="tag tag-dark">深色标签</span>
```

### 要点列表 `styled-list`
带蓝色圆点的列表，替代默认 ul/li。
```html
<ul class="styled-list reveal">
    <li>第一个要点，简洁有力的一句话</li>
    <li>第二个要点，<strong>关键词加粗</strong>突出重点</li>
    <li>第三个要点</li>
</ul>
```

### 洞察/观点 `insight`
带圆点的单条观点，适合图表下方的解读。
```html
<div class="insight reveal">
    <span class="insight-dot"></span>
    <span>从数据可以看出，深度用户的效率提升远高于平均水平，关键变量是<strong>工具使用深度</strong>而非工具数量。</span>
</div>
```

---

## 层级 / 评分

### 级别行 `level-row`
展示能力等级或评分维度，支持高亮当前级别。
```html
<div style="display:flex;flex-direction:column;gap:0.4rem;">
    <div class="level-row">
        <span class="level-badge">L1</span>
        <div class="level-main">
            <div class="level-title">工具使用</div>
            <div class="level-desc">会用 Copilot / ChatGPT 完成简单任务</div>
        </div>
        <span class="level-dot"></span>
    </div>
    <div class="level-row active">   <!-- active 高亮 -->
        <span class="level-badge">L2</span>
        <div class="level-main">
            <div class="level-title">场景驱动</div>
            <div class="level-desc">能结合业务场景设计 Prompt，独立完成复杂任务</div>
        </div>
        <span class="level-dot"></span>
    </div>
</div>
```

---

## 流程图

### 步骤流箭头 `step-flow-grid`
横向流程，带箭头连接，适合4步以内的流程。
```html
<div class="step-flow-grid reveal">
    <div class="step-card step-card-1">
        <div class="step-num">STEP 01</div>
        <div class="step-title">需求分析</div>
    </div>
    <div class="step-flow-arrow">→</div>
    <div class="step-card step-card-2">
        <div class="step-num">STEP 02</div>
        <div class="step-title">方案设计</div>
    </div>
    <div class="step-flow-arrow">→</div>
    <div class="step-card step-card-3">...</div>
    <div class="step-flow-arrow">→</div>
    <div class="step-card step-card-4">...</div>
</div>
```

---

## 图文混排

### 左图右文
图片区域可替换为 `<img>` 标签或任意 SVG 图表；占位块仅作布局参考。
```html
<div style="display:grid;grid-template-columns:1fr 1fr;gap:2rem;align-items:center;" class="reveal">
    <!-- 图片区 -->
    <div style="border-radius:12px;overflow:hidden;aspect-ratio:4/3;background:var(--primary-pale);display:flex;align-items:center;justify-content:center;color:var(--primary);font-size:var(--small-size);font-weight:600;">
        图片 / 图表 / 截图
    </div>
    <!-- 文字区 -->
    <div style="display:flex;flex-direction:column;gap:0.6rem;">
        <h3 style="font-size:clamp(1rem,1.4vw,1.15rem);font-weight:800;color:var(--text-1);">标题</h3>
        <p style="font-size:var(--body-size);color:var(--text-2);line-height:1.65;">说明文字，2–3 句话，简洁描述图片要传达的关键信息。</p>
        <ul class="mini-list">
            <li>补充要点一</li>
            <li>补充要点二</li>
        </ul>
    </div>
</div>
```

### 右图左文
```html
<div style="display:grid;grid-template-columns:1fr 1fr;gap:2rem;align-items:center;" class="reveal">
    <!-- 文字区 -->
    <div style="display:flex;flex-direction:column;gap:0.6rem;">
        <h3 style="font-size:clamp(1rem,1.4vw,1.15rem);font-weight:800;color:var(--text-1);">标题</h3>
        <p style="font-size:var(--body-size);color:var(--text-2);line-height:1.65;">文字放左侧，图片放右侧，视觉重心靠右。</p>
        <ul class="mini-list">
            <li>补充要点一</li>
            <li>补充要点二</li>
        </ul>
    </div>
    <!-- 图片区 -->
    <div style="border-radius:12px;overflow:hidden;aspect-ratio:4/3;background:var(--primary-pale);display:flex;align-items:center;justify-content:center;color:var(--primary);font-size:var(--small-size);font-weight:600;">
        图片 / 图表 / 截图
    </div>
</div>
```

---

## 数据可视化（纯 CSS）

### 横向进度条（对比数据）
```html
<div style="display:flex;flex-direction:column;gap:0.5rem;" class="reveal">
    <div style="display:flex;align-items:center;gap:0.6rem;">
        <span style="font-size:var(--small-size);font-weight:900;color:var(--red);min-width:2.5em;">~200</span>
        <div style="flex:1;height:7px;border-radius:3px;background:linear-gradient(90deg,var(--red),#FFCDD2);"></div>
        <span style="font-size:var(--small-size);color:var(--text-2);white-space:nowrap;">标签文字</span>
    </div>
    <div style="display:flex;align-items:center;gap:0.6rem;">
        <span style="font-size:var(--small-size);font-weight:900;color:var(--primary);min-width:2.5em;">~80</span>
        <div style="flex:1;height:7px;border-radius:3px;background:linear-gradient(90deg,var(--primary),#BAE0FF);width:40%;"></div>
        <span style="font-size:var(--small-size);color:var(--text-2);white-space:nowrap;">另一个标签</span>
    </div>
</div>
```

### 标签云（密度代表规模）
```html
<div style="display:flex;flex-wrap:wrap;justify-content:center;gap:0.5rem 0.7rem;" class="reveal">
    <span class="tag tag-blue" style="font-size:clamp(1rem,2vw,1.4rem);font-weight:800;">核心业务</span>
    <span class="tag tag-blue" style="font-size:clamp(0.8rem,1.4vw,1rem);">子业务A</span>
    <span class="tag tag-blue" style="font-size:clamp(0.72rem,1.2vw,0.9rem);">子业务B</span>
</div>
```

---

---

## 表格

### 标准数据表 `slide-table`
带交替行背景，适合最多 5 行 × 4 列的结构化数据。
```html
<div style="overflow:hidden;border-radius:8px;border:1px solid var(--border);width:100%;" class="reveal">
    <table style="width:100%;border-collapse:collapse;font-size:var(--small-size);">
        <thead>
            <tr style="background:var(--primary);color:#fff;">
                <th style="padding:0.5rem 0.9rem;text-align:left;font-weight:600;">维度</th>
                <th style="padding:0.5rem 0.9rem;text-align:left;font-weight:600;">现状</th>
                <th style="padding:0.5rem 0.9rem;text-align:right;font-weight:600;">目标</th>
                <th style="padding:0.5rem 0.9rem;text-align:right;font-weight:600;">差距</th>
            </tr>
        </thead>
        <tbody>
            <tr style="background:#fff;border-bottom:1px solid var(--border);">
                <td style="padding:0.45rem 0.9rem;font-weight:600;color:var(--text-1);">指标 A</td>
                <td style="padding:0.45rem 0.9rem;color:var(--text-2);">数据1</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;color:var(--text-2);">数据2</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;font-weight:700;color:var(--red);">▲ 差距值</td>
            </tr>
            <tr style="background:var(--bg-page);border-bottom:1px solid var(--border);">
                <td style="padding:0.45rem 0.9rem;font-weight:600;color:var(--text-1);">指标 B</td>
                <td style="padding:0.45rem 0.9rem;color:var(--text-2);">数据3</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;color:var(--text-2);">数据4</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;font-weight:700;color:var(--green);">▲ 已达标</td>
            </tr>
            <tr style="background:#fff;">
                <td style="padding:0.45rem 0.9rem;font-weight:600;color:var(--text-1);">指标 C</td>
                <td style="padding:0.45rem 0.9rem;color:var(--text-2);">数据5</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;color:var(--text-2);">数据6</td>
                <td style="padding:0.45rem 0.9rem;text-align:right;font-weight:700;color:var(--text-3);">持平</td>
            </tr>
        </tbody>
    </table>
</div>
```

---

## 数据可视化（SVG）

SVG 图表无需外部库，`fill`/`stroke` 使用 CSS 变量自动跟随主题色。使用时按实际数据调整矩形高度和折线坐标。

### 竖向柱状图
```html
<svg viewBox="0 0 520 240" style="width:100%;max-width:520px;height:auto;display:block;margin:0 auto;" class="reveal">
    <!-- 网格线 -->
    <line x1="60" y1="20" x2="60" y2="190" stroke="var(--border,#E4E8EF)" stroke-width="1.5"/>
    <line x1="60" y1="190" x2="500" y2="190" stroke="var(--border,#E4E8EF)" stroke-width="1.5"/>
    <line x1="60" y1="130" x2="500" y2="130" stroke="var(--border,#E4E8EF)" stroke-width="1" stroke-dasharray="4,3"/>
    <line x1="60" y1="70"  x2="500" y2="70"  stroke="var(--border,#E4E8EF)" stroke-width="1" stroke-dasharray="4,3"/>
    <!-- Y轴刻度 -->
    <text x="52" y="194" text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">0</text>
    <text x="52" y="134" text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">50%</text>
    <text x="52" y="74"  text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">100%</text>
    <!-- 柱子：高度 = (值/最大值) × 120，y = 190 - 高度 -->
    <rect x="90"  y="70"  width="55" height="120" style="fill:var(--primary,#1677FF);" rx="3" opacity="0.9"/>
    <text x="117" y="65"  text-anchor="middle" style="fill:var(--text-1,#141414);font-size:12px;font-weight:700;">100%</text>
    <text x="117" y="208" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Q1</text>

    <rect x="200" y="100" width="55" height="90"  style="fill:var(--primary,#1677FF);" rx="3" opacity="0.75"/>
    <text x="227" y="95"  text-anchor="middle" style="fill:var(--text-1,#141414);font-size:12px;font-weight:700;">75%</text>
    <text x="227" y="208" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Q2</text>

    <rect x="310" y="88"  width="55" height="102" style="fill:var(--primary,#1677FF);" rx="3" opacity="0.85"/>
    <text x="337" y="83"  text-anchor="middle" style="fill:var(--text-1,#141414);font-size:12px;font-weight:700;">85%</text>
    <text x="337" y="208" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Q3</text>

    <rect x="420" y="50"  width="55" height="140" style="fill:var(--primary-dark,#0950D9);" rx="3" opacity="0.9"/>
    <text x="447" y="45"  text-anchor="middle" style="fill:var(--text-1,#141414);font-size:12px;font-weight:700;">116%</text>
    <text x="447" y="208" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Q4</text>
</svg>
```

### 折线图（带面积）
```html
<svg viewBox="0 0 520 220" style="width:100%;max-width:520px;height:auto;display:block;margin:0 auto;" class="reveal">
    <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#1677FF" stop-opacity="0.18"/>
            <stop offset="100%" stop-color="#1677FF" stop-opacity="0"/>
        </linearGradient>
    </defs>
    <!-- 网格线 -->
    <line x1="60" y1="20" x2="60" y2="170" stroke="var(--border,#E4E8EF)" stroke-width="1.5"/>
    <line x1="60" y1="170" x2="500" y2="170" stroke="var(--border,#E4E8EF)" stroke-width="1.5"/>
    <line x1="60" y1="110" x2="500" y2="110" stroke="var(--border,#E4E8EF)" stroke-width="1" stroke-dasharray="4,3"/>
    <line x1="60" y1="50"  x2="500" y2="50"  stroke="var(--border,#E4E8EF)" stroke-width="1" stroke-dasharray="4,3"/>
    <!-- Y轴刻度 -->
    <text x="52" y="174" text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">0</text>
    <text x="52" y="114" text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">50</text>
    <text x="52" y="54"  text-anchor="end" style="fill:var(--text-3,#8C8C8C);font-size:11px;">100</text>
    <!-- 面积 -->
    <path d="M100,140 L200,105 L300,75 L400,50 L480,62 L480,170 L100,170 Z" fill="url(#areaGrad)"/>
    <!-- 折线 -->
    <polyline points="100,140 200,105 300,75 400,50 480,62"
              fill="none" style="stroke:var(--primary,#1677FF);" stroke-width="2.5"
              stroke-linejoin="round" stroke-linecap="round"/>
    <!-- 数据点 -->
    <circle cx="100" cy="140" r="4" style="fill:var(--primary,#1677FF);" stroke="#fff" stroke-width="2"/>
    <circle cx="200" cy="105" r="4" style="fill:var(--primary,#1677FF);" stroke="#fff" stroke-width="2"/>
    <circle cx="300" cy="75"  r="4" style="fill:var(--primary,#1677FF);" stroke="#fff" stroke-width="2"/>
    <circle cx="400" cy="50"  r="4" style="fill:var(--primary-dark,#0950D9);" stroke="#fff" stroke-width="2"/>
    <circle cx="480" cy="62"  r="4" style="fill:var(--primary,#1677FF);" stroke="#fff" stroke-width="2"/>
    <!-- X轴标签 -->
    <text x="100" y="190" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Jan</text>
    <text x="200" y="190" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Feb</text>
    <text x="300" y="190" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Mar</text>
    <text x="400" y="190" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">Apr</text>
    <text x="480" y="190" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:11px;">May</text>
</svg>
```

### 环形图（带图例）
```html
<!-- 总周长 ≈ 440（r=70）；各段 dasharray 第一值 = 占比 × 440 -->
<div style="display:flex;align-items:center;justify-content:center;gap:2rem;" class="reveal">
    <svg viewBox="0 0 200 200" style="width:clamp(120px,18vw,180px);flex-shrink:0;">
        <!-- 背景轨道 -->
        <circle cx="100" cy="100" r="70" fill="none" stroke="var(--bg-page,#F5F7FA)" stroke-width="30"/>
        <!-- 分段1：45% = 198 -->
        <circle cx="100" cy="100" r="70" fill="none" style="stroke:var(--primary,#1677FF);"
                stroke-width="30" stroke-dasharray="198 242" stroke-dashoffset="0"
                transform="rotate(-90 100 100)"/>
        <!-- 分段2：30% = 132，偏移 -198 -->
        <circle cx="100" cy="100" r="70" fill="none" style="stroke:var(--primary-light,#4096FF);"
                stroke-width="30" stroke-dasharray="132 308" stroke-dashoffset="-198"
                transform="rotate(-90 100 100)"/>
        <!-- 分段3：25% = 110 -->
        <circle cx="100" cy="100" r="70" fill="none" style="stroke:var(--primary-pale,#E6F4FF);"
                stroke-width="30" stroke-dasharray="110 330" stroke-dashoffset="-330"
                transform="rotate(-90 100 100)"/>
        <!-- 中心文字 -->
        <text x="100" y="96"  text-anchor="middle" style="fill:var(--text-1,#141414);font-size:18px;font-weight:900;">75%</text>
        <text x="100" y="113" text-anchor="middle" style="fill:var(--text-3,#8C8C8C);font-size:10px;">核心指标</text>
    </svg>
    <!-- 图例 -->
    <div style="display:flex;flex-direction:column;gap:0.5rem;">
        <div style="display:flex;align-items:center;gap:0.5rem;">
            <span style="width:12px;height:12px;border-radius:3px;background:var(--primary,#1677FF);flex-shrink:0;"></span>
            <span style="font-size:var(--small-size);color:var(--text-2);">类别 A &nbsp;<strong style="color:var(--text-1);">45%</strong></span>
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem;">
            <span style="width:12px;height:12px;border-radius:3px;background:var(--primary-light,#4096FF);flex-shrink:0;"></span>
            <span style="font-size:var(--small-size);color:var(--text-2);">类别 B &nbsp;<strong style="color:var(--text-1);">30%</strong></span>
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem;">
            <span style="width:12px;height:12px;border-radius:3px;background:var(--primary-pale,#E6F4FF);flex-shrink:0;"></span>
            <span style="font-size:var(--small-size);color:var(--text-2);">类别 C &nbsp;<strong style="color:var(--text-1);">25%</strong></span>
        </div>
    </div>
</div>
```

---

## 页面骨架

除了单个组件，当前模板里已经沉淀出几类更稳定的“整页布局骨架”。生成时优先复用这些骨架，而不是每页都重新拼布局。

### 统一标题区 `slide-header center-stack`
所有内容页的标题和副标题应固定在同一位置，不随正文内容浮动。正文区域统一放到 `slide-body`。

```html
<section class="slide slide-white">
    <div class="slide-header center-stack">
        <span class="header-mark"></span>
        <h2 class="header-title">简短标题</h2>
        <p class="header-sub">一句副标题，解释这一页要回答什么问题。</p>
    </div>
    <div class="slide-body" style="justify-content:center;">
        <!-- 正文内容 -->
    </div>
</section>
```

### 开场钩子页
适合“Opening Hook + 2×2 信息面板 + 背景底纹”的第一页正文。

```html
<section class="slide slide-white decorated-world">
    <div class="slide-header center-stack">
        <h2 class="header-title">整页骨架</h2>
        <p class="header-sub">适合开场问题、外部变化或高势能背景页。</p>
    </div>
    <div class="slide-body" style="justify-content:center;padding-top:clamp(0.8rem,2vh,1.4rem);">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:clamp(0.8rem,1.8vw,1.4rem);width:100%;" class="reveal">
            <div class="info-card">...</div>
            <div class="info-card">...</div>
            <div class="info-card">...</div>
            <div class="info-card">...</div>
        </div>
    </div>
</section>
```

### 分组目录页
适合“为什么 / 做什么 / 怎么做”这类三段式汇报。比纯平铺议程更适合管理层沟通。

```html
<section class="slide slide-white">
    <div class="slide-header center-stack">
        <h2 class="header-title">分组目录</h2>
        <p class="header-sub">目录按阶段聚类，而不是简单平铺。</p>
    </div>
    <div class="slide-body" style="justify-content:center;gap:clamp(0.55rem,1.2vh,0.9rem);max-width:72%;margin:0 auto;">
        <div style="font-size:clamp(0.6rem,0.9vw,0.75rem);font-weight:700;color:var(--text-3);letter-spacing:0.1em;text-transform:uppercase;">为什么</div>
        <div class="agenda-item reveal">...</div>
        <div style="border-top:1.5px solid rgba(0,0,0,0.06);"></div>
        <div style="font-size:clamp(0.6rem,0.9vw,0.75rem);font-weight:700;color:var(--text-3);letter-spacing:0.1em;text-transform:uppercase;">做什么</div>
        <div class="agenda-item reveal">...</div>
        <div style="border-top:1.5px solid rgba(0,0,0,0.06);"></div>
        <div style="font-size:clamp(0.6rem,0.9vw,0.75rem);font-weight:700;color:var(--text-3);letter-spacing:0.1em;text-transform:uppercase;">怎么做</div>
        <div class="agenda-item reveal">...</div>
    </div>
</section>
```

### 双阶段桥接流程
比单行 `step-flow-grid` 更适合表达“先规划，再执行”的两段式推进逻辑。

```html
<section class="slide slide-white">
    <div class="slide-header center-stack">
        <h2 class="header-title">双阶段流程</h2>
        <p class="header-sub">适合表达先搭框架、再落地执行的结构。</p>
    </div>
    <div class="slide-body" style="justify-content:center;max-width:85%;margin:0 auto;">
        <div class="step-flow-top reveal">
            <div class="step-card step-card-1">...</div>
            <div class="step-flow-arrow">→</div>
            <div class="step-card step-card-2">...</div>
        </div>
        <div class="step-flow-bridge reveal"><span>进入执行层</span></div>
        <div class="step-flow-bottom reveal">
            <div class="step-card step-card-3">...</div>
            <div class="step-card step-card-4">...</div>
        </div>
    </div>
</section>
```

### 横向支撑板 `support-board`
适合讲“专项体系”“横向支撑”“保障机制”。信息密度高，但比普通三列卡片更规整。

```html
<div class="support-board reveal">
    <div class="support-board-title">专项示例</div>
    <div class="support-board-main">横向支撑板布局</div>
    <div class="support-board-grid">
        <div class="support-board-col" style="border-left:4px solid var(--primary);">
            <div class="support-board-col-title">🔧 基础保障</div>
            <div class="support-board-items">
                <div class="support-mini-card">
                    <div class="support-mini-card-title">模板引擎 <span class="support-owner">平台</span></div>
                    <div class="support-mini-card-body">说明文字。</div>
                </div>
                <div class="support-mini-card">...</div>
            </div>
        </div>
        <div class="support-board-col">...</div>
        <div class="support-board-col">...</div>
    </div>
</div>
```

### 流转看板 `demand-flow-board`
适合讲跨角色、跨阶段的协同链路。它不是标准图表，更像“过程地图”。

```html
<div class="demand-flow reveal">
    <div class="demand-flow-board">
        <div class="demand-flow-stage-head">
            <span>提出<span class="demand-flow-stage-role">业务方</span></span>
            <span>拆解<span class="demand-flow-stage-role">策划</span></span>
            <span>生成<span class="demand-flow-stage-role">系统</span></span>
            <span>审校<span class="demand-flow-stage-role">专家</span></span>
            <span>交付<span class="demand-flow-stage-role">演讲者</span></span>
        </div>
        <div class="demand-flow-stage-grid">
            <span></span><span></span><span></span><span></span><span></span>
        </div>
        <svg class="demand-flow-lines" viewBox="0 0 1000 240" preserveAspectRatio="none">
            <path d="M60,40 C150,40 170,90 260,90 S370,140 460,140 590,80 700,80 820,150 940,150"
                  fill="none" stroke="rgba(22,119,255,0.18)" stroke-width="6" stroke-linecap="round"/>
        </svg>
        <div class="demand-flow-track">
            <span class="demand-dot" style="left:8%;top:18%;width:12px;height:12px;background:var(--primary);"></span>
            <span class="demand-dot" style="left:25%;top:38%;width:10px;height:10px;background:var(--primary-light);"></span>
        </div>
    </div>
</div>
```

---

## 关键用法提示

1. **所有 clamp 字号**：不要硬编码 px，统一用 `var(--body-size)`、`var(--small-size)`、`var(--h3-size)` 等变量。
2. **间距**：用 `var(--content-gap)` 和 `var(--element-gap)`，或 `clamp(N, Nvw, N)` 格式。
3. **动画**：给外层容器加 `class="reveal"`，子元素会按顺序依次出现（最多 6 个子元素有自动 delay）。
4. **内容页宽度**：`style="max-width:85%;margin:0 auto;"` 控制内容区宽度，防止内容贴边。
5. **颜色变量**：`var(--primary)` 蓝、`var(--red)` 红、`var(--green)` 绿、`var(--orange)` 橙、`var(--text-1/2/3)` 深中浅文字、`var(--bg-page)` 浅灰背景。
