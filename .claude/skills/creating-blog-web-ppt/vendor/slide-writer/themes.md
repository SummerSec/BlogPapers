# Company Theme Library — Slide-Writer

每个主题定义一套 CSS 变量覆盖，插入基础 CSS 之后的 `:root` 块中，即可完整切换品牌色。

---

## 主题识别规则

**自动识别**：从用户请求、署名、部门名称中提取关键词。先匹配子品牌表，再匹配集团表。未识别时使用默认（蚂蚁集团蓝）。

识别逻辑：
1. 在「子品牌归属表」中查找关键词 → 得到「所属集团」和「子品牌 ID」
2. 在「集团主题表」中查找集团 → 得到 CSS 主题
3. Logo 展示 = **集团 logo ＋ 分隔线 ＋ 子品牌 logo**（子品牌有 logo 文件时）；仅集团关键词则只展示集团 logo

### 多品牌冲突处理

当输入里同时出现多个品牌时，不要简单按“最先命中”决定主题，按下面顺序收敛：

1. 用户明确指定主题名或公司名 → 直接采用用户指定。
2. 标题、署名、部门、业务线里出现的品牌 → 优先级高于正文提及的竞品或案例。
3. 如果是“X vs Y”“竞品对比”“行业比较”这类比较型内容，默认使用演讲者所属公司或汇报对象所在公司的主题；若无法判断，退回默认蚂蚁蓝，并在输出说明中点明“内容含多品牌，已使用中性默认主题”。
4. 如果正文只是引用合作方、客户、竞品、生态伙伴，不切换到对方主题。
5. 同时出现集团和子品牌时，主题跟随集团，logo 按子品牌规则补齐。

---

## 集团主题表

| 关键词（集团） | 主题 ID | CSS 主色 |
|---|---|---|
| 蚂蚁集团、Ant Group、蚂蚁 | ant-group | #1677FF |
| 阿里巴巴、Alibaba、阿里 | alibaba | #FF6A00 |
| 腾讯、Tencent | tencent | #0B60D6 |
| 字节跳动、ByteDance、字节 | bytedance | #005FE7 |
| 美团、Meituan | meituan | #F0A500 |
| 京东、JD | jd | #E1251B |
| 百度、Baidu | baidu | #4E6EF2 |
| 华为、Huawei | huawei | #CF0A2C |
| 小米、Xiaomi | xiaomi | #FF6900 |
| 网易、NetEase | netease | #C20C0C |
| 滴滴、DiDi | didi | #FF7200 |
| 微软、Microsoft | microsoft | #0078D4 |
| 谷歌、Google | google | #4285F4 |
| 苹果、Apple | apple | #0071E3 |

---

## 子品牌归属表

子品牌关键词 → 所属集团 + 子品牌 ID（用于 Logo 文件查找）

### 蚂蚁集团旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 支付宝、Alipay、alipay | ant-group | alipay |
| 花呗、Huabei | ant-group | huabei |
| 借呗、Jiebei | ant-group | jiebei |
| 蚂蚁森林、Ant Forest | ant-group | ant-forest |
| 芝麻信用、Sesame Credit | ant-group | sesame-credit |
| 网商银行、MYbank | ant-group | mybank |
| 蚂蚁公益基金会 | ant-group | ant-foundation |
| 余额宝、Yu'e Bao | ant-group | yuebao |

### 阿里巴巴旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 淘宝、Taobao | alibaba | taobao |
| 天猫、Tmall | alibaba | tmall |
| 钉钉、DingTalk | alibaba | dingtalk |
| 饿了么、Eleme | alibaba | eleme |
| 优酷、Youku | alibaba | youku |
| 高德、Amap | alibaba | amap |
| 盒马、Hema | alibaba | hema |
| 阿里云、Alibaba Cloud | alibaba | aliyun |
| 菜鸟、Cainiao | alibaba | cainiao |
| 闲鱼、Xianyu | alibaba | xianyu |
| 1688 | alibaba | 1688 |

### 腾讯旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 微信、WeChat | tencent | wechat |
| QQ | tencent | qq |
| 企微、企业微信、WeCom | tencent | wecom |
| 腾讯游戏、Tencent Games | tencent | tencent-games |
| 腾讯视频、腾讯video | tencent | tencent-video |
| 腾讯云、Tencent Cloud | tencent | tencent-cloud |
| 腾讯音乐、TME | tencent | tme |
| 微信支付、WePay | tencent | wepay |

### 字节跳动旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 抖音、Douyin | bytedance | douyin |
| TikTok | bytedance | tiktok |
| 飞书、Feishu、Lark | bytedance | feishu |
| 今日头条、Toutiao | bytedance | toutiao |
| 西瓜视频 | bytedance | xigua |
| 剪映、CapCut | bytedance | capcut |
| 火山引擎 | bytedance | volcengine |
| 番茄小说 | bytedance | fanqie |

### 美团旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 美团外卖 | meituan | meituan-waimai |
| 大众点评、Dianping | meituan | dianping |
| 美团优选 | meituan | meituan-youxuan |
| 美团买菜、小象超市 | meituan | meituan-maicai |
| 摩拜、Mobike | meituan | mobike |
| 美团闪购 | meituan | meituan-shangou |

### 京东旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 京东物流、JD Logistics | jd | jd-logistics |
| 京东健康、JD Health | jd | jd-health |
| 京东科技、京东金融 | jd | jd-tech |
| 京东云 | jd | jd-cloud |
| 京东工业 | jd | jd-industry |

### 百度旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 爱奇艺、iQiyi | baidu | iqiyi |
| 文心一言、ERNIE | baidu | ernie |
| 百度地图 | baidu | baidu-map |
| 百度云、百度网盘 | baidu | baidu-cloud |
| 百度文库 | baidu | baidu-wenku |

### 华为旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 荣耀、Honor | huawei | honor |
| 华为云 | huawei | huawei-cloud |
| 鸿蒙、HarmonyOS | huawei | harmonyos |
| 华为终端 | huawei | huawei-terminal |

### 小米旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| MIUI、澎湃OS | xiaomi | miui |
| 小米汽车 | xiaomi | xiaomi-car |
| 小米生态链 | xiaomi | xiaomi-eco |
| Redmi | xiaomi | redmi |

### 网易旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 网易游戏 | netease | netease-games |
| 网易云音乐 | netease | netease-music |
| 网易邮箱、163邮箱 | netease | netease-mail |
| 有道、Youdao | netease | youdao |
| 网易严选 | netease | yanxuan |

### 滴滴旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| 花小猪 | didi | huaxiaozhu |
| 青桔单车 | didi | qingju |
| 滴滴货运 | didi | didi-cargo |
| 小桔充电 | didi | xiaoju-charge |

### 微软旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| Azure | microsoft | azure |
| Office、M365 | microsoft | office |
| Teams | microsoft | teams |
| GitHub | microsoft | github |
| LinkedIn | microsoft | linkedin |
| Copilot | microsoft | copilot |

### 谷歌旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| YouTube | google | youtube |
| Android | google | android |
| Chrome | google | chrome |
| Google Cloud | google | google-cloud |
| Gmail | google | gmail |
| Gemini | google | gemini |

### 苹果旗下
| 关键词 | 所属集团 | 子品牌 ID |
|---|---|---|
| iPhone | apple | iphone |
| Mac、macOS | apple | mac |
| iPad | apple | ipad |
| Apple Watch | apple | apple-watch |
| App Store | apple | app-store |
| iCloud | apple | icloud |

---

## Logo 文件索引

Logo 文件存储于当前仓库的 [logos](logos) 目录。
命名规范：`[品牌ID]-white.png`（白色版）和 `[品牌ID]-blue.png` / `[品牌ID]-color.png`（彩色版）。

### 已有 Logo 文件
| 品牌 ID | 白色版 | 彩色版 | 所属集团 |
|---|---|---|---|
| ant-group | `./logos/logo-antgroup-white.png` | `./logos/logo-antgroup-blue.png` | 蚂蚁集团（集团本身） |
| alipay | `./logos/logo-alipay-white.png` | `./logos/logo-alipay-blue.png` | 蚂蚁集团 |
| mybank | `./logos/logo-mybank-white.png` | `./logos/logo-mybank-color.png` | 蚂蚁集团 |
| tencent | `./logos/tencent-white.png` | `./logos/tencent-blue.png` | 腾讯 |

### 其余品牌 Logo
标注「待补充」，用户可随时提供素材，存入 `logos/` 目录后更新本表。

### 文件说明

| 品牌 ID | 白色版文件 | 彩色版文件 | 说明 |
|---|---|---|---|
| ant-group | `./logos/logo-antgroup-white.png` | `./logos/logo-antgroup-blue.png` | 当前仓库已有文件名使用 `blue` 作为彩色版 |
| alipay | `./logos/logo-alipay-white.png` | `./logos/logo-alipay-blue.png` | 当前仓库已有文件名使用 `blue` 作为彩色版 |
| mybank | `./logos/logo-mybank-white.png` | `./logos/logo-mybank-color.png` | 使用网商银行中文品牌标志 |
| tencent | `./logos/tencent-white.png` | `./logos/tencent-blue.png` | 腾讯品牌标志已内聚到 `logos/` 目录 |

---

## 双 Logo 展示规则

**核心原则**：子品牌出现时，始终展示「集团 logo ＋ 分隔线 ＋ 子品牌 logo」。
**尺寸原则**：源 PNG 的像素尺寸、宽高比、透明留白不一致很正常，最终展示必须做视觉归一，而不是按原图大小直接显示。

### 尺寸归一规则

1. 所有 logo 默认使用统一高度基线：
   - 内容页右上角 `#globalLogoGroup img`：`height: clamp(1.4rem, 2.8vw, 2.2rem); max-height: 36px; width: auto; object-fit: contain;`
   - 封面/章节/结尾 `img.logo-img-cover`：`height: clamp(1.4rem, 2.8vw, 2.2rem); max-height: 36px; width: auto; object-fit: contain;`
2. 不允许根据原图像素大小直接放大或缩小到不同高度。
3. 超宽或超扁的 logo 允许更宽，但高度仍受同一上限约束。
4. 如果某个 logo 因透明留白过多而显得偏小，优先微调该 logo 的单独 `max-height` 或容器间距，不要拉伸变形。
5. 分隔线 `.logo-divider` 的高度应与两侧 logo 的视觉高度一致；默认跟随同一 `clamp` 高度。
6. 同一份 deck 内，封面、章节页、内容页、结尾页要保持一致的视觉基线，不要某一页明显更大或更小。

### 情况一：识别到子品牌，且集团 logo + 子品牌 logo 均存在
```html
<!-- 深色背景（封面/章节/结尾）用 white 版 -->
<div style="display:flex;align-items:center;gap:clamp(0.5rem,1vw,0.9rem);margin-right:clamp(0.7rem,1.5vw,1.2rem);">
    <img src="./logos/logo-[集团ID]-white.png" alt="[集团名]"
         style="height:clamp(1.4rem,2.8vw,2.2rem);width:auto;object-fit:contain;max-height:36px;">
    <span style="width:1.5px;height:clamp(1.2rem,2.4vw,1.8rem);display:inline-block;flex-shrink:0;
                 background:linear-gradient(to bottom,transparent 0%,rgba(255,255,255,0.3) 28%,rgba(255,255,255,0.55) 50%,rgba(255,255,255,0.3) 72%,transparent 100%);"></span>
    <img src="./logos/logo-[子品牌ID]-white.png" alt="[子品牌名]"
         style="height:clamp(1.4rem,2.8vw,2.2rem);width:auto;object-fit:contain;max-height:36px;">
</div>

<!-- 白色背景（内容页 globalLogoGroup）用 color 版 -->
<div id="globalLogoGroup">
    <img src="./logos/logo-[集团ID]-color.png" alt="[集团名]">
    <span class="logo-divider"></span>
    <img src="./logos/logo-[子品牌ID]-color.png" alt="[子品牌名]">
</div>
```

### 情况二：识别到子品牌，但子品牌 logo 待补充，集团 logo 存在
只展示集团 logo，不展示分隔线。

### 情况三：只识别到集团，无子品牌
只展示集团 logo。

### 情况四：均无 logo（待补充）
省略所有 logo 元素，封面 cover-top 只保留部门名文字。

---

**注意**：生成 HTML 时，logo 相对路径统一使用 `./logos/...`。若仓库中的彩色版文件名实际为 `blue`（如 `logo-antgroup-blue.png`、`logo-alipay-blue.png`），应以真实文件名为准；`mybank` 当前使用 `./logos/logo-mybank-color.png` 与 `./logos/logo-mybank-white.png`；`tencent` 当前使用 `./logos/tencent-blue.png` 与 `./logos/tencent-white.png`。无论使用哪个 PNG，最终展示都必须服从上面的统一高度规则，而不是服从源文件尺寸。

---

## 如何应用主题

在基础 CSS（从 `index.html` 复制的 `<style>` 块）**末尾**追加对应主题的变量覆盖：

```html
<style>
/* === 基础 CSS（从 index.html 完整复制）=== */
...

/* === 主题覆盖（插入此处）=== */
:root {
    /* 粘贴对应公司的变量覆盖 */
}
.slide-section {
    background: var(--section-bg);
}
</style>
```

---

## 主题定义

### 🔵 蚂蚁集团 / 支付宝（默认）`ant-group`

品牌蓝，来自 Ant Design 设计系统。

```css
:root {
    --primary:       #1677FF;
    --primary-dark:  #0950D9;
    --primary-light: #4096FF;
    --primary-pale:  #E6F4FF;
    --primary-dim:   rgba(22, 119, 255, 0.12);
    --cover-bg:      linear-gradient(125deg, #0A3DA8 0%, #1263EA 35%, #2B8FFF 65%, #5AB6FF 100%);
    --section-bg:    linear-gradient(135deg, #0B2F8A 0%, #1554AD 50%, #1677FF 100%);
    --red:           #E8380D;
    --green:         #52C41A;
    --orange:        #FA8C16;
}
```

---

### 🟠 阿里巴巴 `alibaba`

品牌橙，来自阿里巴巴集团标志色。

```css
:root {
    --primary:       #FF6A00;
    --primary-dark:  #CC4400;
    --primary-light: #FF8C38;
    --primary-pale:  #FFF3E8;
    --primary-dim:   rgba(255, 106, 0, 0.12);
    --cover-bg:      linear-gradient(125deg, #7A2000 0%, #CC3800 35%, #FF6A00 65%, #FF9A50 100%);
    --section-bg:    linear-gradient(135deg, #7A2000 0%, #CC4400 50%, #FF6A00 100%);
    --red:           #CF1322;
    --green:         #389E0D;
    --orange:        #FA8C16;
    /* Header sub color override */
    --header-sub-color: #FF6A00;
}
.header-sub { color: var(--primary) !important; }
.agenda-num { color: var(--primary) !important; }
```

---

### 🔵 腾讯 `tencent`

腾讯蓝为主色，整体应接近企业官网与品牌手册的冷静、克制、科技感表达。微信绿只能作为正向状态或增长提示色，不能与腾讯蓝争主色。

```css
:root {
    --primary:       #0B60D6;
    --primary-dark:  #003FA8;
    --primary-light: #3A85F0;
    --primary-pale:  #EAF3FF;
    --primary-dim:   rgba(11, 96, 214, 0.12);
    --cover-bg:      linear-gradient(125deg, #0A1F52 0%, #0B3C94 38%, #0B60D6 70%, #3A85F0 100%);
    --section-bg:    linear-gradient(135deg, #0A1F52 0%, #0B3C94 52%, #0B60D6 100%);
    --bg-page:       #F5F8FC;
    --border:        #D9E3F0;
    --text-1:        #1F2A3D;
    --text-2:        #46556B;
    --text-3:        #7F8DA3;
    --green:         #07C160;
    --red:           #FA5151;
    --orange:        #FFC300;
    --accent-green:  #07C160;
}
```

#### 腾讯主题补充规则

这些规则用于把“腾讯蓝”从配色提升到版式风格。若命中腾讯主题，生成时一并遵循：

- **主色唯一**：腾讯蓝是唯一主色。大面积主视觉、标题强调、关键数字都优先使用蓝色体系。
- **绿只作状态色**：微信绿只用于“增长、通过、上线、健康”这类正向状态，不用于封面主标题、章节背景或大面积卡片底色。
- **白底优先**：内容页优先白底或极浅蓝灰底，避免蚂蚁/阿里那种高饱和整页铺色。
- **大留白**：模块间距更宽，信息密度略低于默认值，单页尽量控制在 3 个重点模块以内。
- **形状克制**：优先使用矩形卡片、细边框、浅阴影，不使用过多圆润装饰、彩色标签墙或强装饰弧形背景。
- **标题直给**：标题更像企业公告或业务判断，避免口号式、煽动式表达。
- **图表冷静**：图表与数据模块使用蓝、灰、白三色为主，需要正向强调时再引入绿色单点标识。
- **Logo 使用**：默认使用 `./logos/tencent-white.png` 和 `./logos/tencent-blue.png`，并服从本节上方的统一高度规则，不按源 PNG 尺寸直接展示。

#### 腾讯说明

腾讯主题规则当前以本仓库内的 logo 资产、既有主题定义和可执行版式约束为准，不再依赖外部 PDF 参考文件。

---

### ⚫ 字节跳动 `bytedance`

深色极简，来自字节跳动企业品牌的现代感，配以高亮蓝作为主色。

#### 字节跳动主题补充规则

- **深色封面强对比**：封面和章节页接近全黑，文字白色，确保高对比度；不要在深色背景上用浅蓝或灰色文字。
- **数字大而突出**：`stat-block` 和数字类组件可以比默认字号更大，用于强调规模感。
- **卡片用 subtle shadow**：内容页卡片优先用轻阴影（`box-shadow: 0 2px 8px rgba(0,0,0,0.08)`）而非彩色边框，保持克制现代感。
- **主色只做点缀**：蓝色主色用于关键数字、高亮词、进度条，大面积内容页背景保持白/极浅灰。
- **Logo 使用**：当前待补充，封面 cover-top 保留部门名文字，不放 logo 占位符。

```css
:root {
    --primary:       #005FE7;
    --primary-dark:  #0040B0;
    --primary-light: #3382FF;
    --primary-pale:  #EBF2FF;
    --primary-dim:   rgba(0, 95, 231, 0.12);
    --cover-bg:      linear-gradient(125deg, #0A0F1E 0%, #0F1F3D 35%, #1A3A6E 65%, #005FE7 100%);
    --section-bg:    linear-gradient(135deg, #0A0F1E 0%, #0F2040 50%, #005FE7 100%);
    --bg-page:       #F2F3F5;
    --red:           #FE2C55;
    --green:         #25C489;
    --orange:        #FF7C00;
}
/* Cover text stays white — no override needed */
```

---

### 🟡 美团 `meituan`

品牌黄，来自美团标志色，深色文字保持可读性。

```css
:root {
    --primary:       #F0A500;
    --primary-dark:  #C07800;
    --primary-light: #FFC233;
    --primary-pale:  #FFF9E0;
    --primary-dim:   rgba(240, 165, 0, 0.15);
    --cover-bg:      linear-gradient(125deg, #5C3A00 0%, #9A6200 35%, #D08800 65%, #F0A500 100%);
    --section-bg:    linear-gradient(135deg, #5C3A00 0%, #9A6200 50%, #D08800 100%);
    --red:           #E1251B;
    --green:         #0DAD5B;
    --orange:        #F0A500;
}
```

---

### 🔴 京东 `jd`

品牌红，来自京东标志色。

```css
:root {
    --primary:       #E1251B;
    --primary-dark:  #AA0E0A;
    --primary-light: #F05048;
    --primary-pale:  #FFF1F0;
    --primary-dim:   rgba(225, 37, 27, 0.12);
    --cover-bg:      linear-gradient(125deg, #6A0000 0%, #AA0E0A 35%, #E1251B 65%, #F84848 100%);
    --section-bg:    linear-gradient(135deg, #6A0000 0%, #AA0E0A 50%, #E1251B 100%);
    --red:           #E1251B;
    --green:         #16A34A;
    --orange:        #EA580C;
}
```

---

### 🔵 百度 `baidu`

品牌蓝，来自百度搜索框配色，高饱和度蓝紫。

```css
:root {
    --primary:       #4E6EF2;
    --primary-dark:  #2848D0;
    --primary-light: #7890F8;
    --primary-pale:  #EEF1FE;
    --primary-dim:   rgba(78, 110, 242, 0.12);
    --cover-bg:      linear-gradient(125deg, #1228A0 0%, #2848D0 35%, #4E6EF2 65%, #7890F8 100%);
    --section-bg:    linear-gradient(135deg, #1228A0 0%, #2848D0 50%, #4E6EF2 100%);
    --red:           #F5483B;
    --green:         #34C38F;
    --orange:        #F6A623;
}
```

---

### 🔴 华为 `huawei`

品牌红，来自华为标志色，沉稳深红。

```css
:root {
    --primary:       #CF0A2C;
    --primary-dark:  #96001C;
    --primary-light: #E83850;
    --primary-pale:  #FFF0F2;
    --primary-dim:   rgba(207, 10, 44, 0.12);
    --cover-bg:      linear-gradient(125deg, #5A0010 0%, #960018 35%, #CF0A2C 65%, #F03050 100%);
    --section-bg:    linear-gradient(135deg, #5A0010 0%, #960018 50%, #CF0A2C 100%);
    --red:           #CF0A2C;
    --green:         #00A870;
    --orange:        #FF8800;
}
```

---

### 🟠 小米 `xiaomi`

品牌橙，来自小米标志色，明亮活力橙。

```css
:root {
    --primary:       #FF6900;
    --primary-dark:  #CC4400;
    --primary-light: #FF8C38;
    --primary-pale:  #FFF3EC;
    --primary-dim:   rgba(255, 105, 0, 0.12);
    --cover-bg:      linear-gradient(125deg, #7A2800 0%, #CC4400 35%, #FF6900 65%, #FF9040 100%);
    --section-bg:    linear-gradient(135deg, #7A2800 0%, #CC4400 50%, #FF6900 100%);
    --red:           #E1251B;
    --green:         #00B96B;
    --orange:        #FF6900;
}
```

---

### 🔴 网易 `netease`

品牌红，来自网易标志色，正红系。

```css
:root {
    --primary:       #C20C0C;
    --primary-dark:  #8A0000;
    --primary-light: #E03030;
    --primary-pale:  #FFF0F0;
    --primary-dim:   rgba(194, 12, 12, 0.12);
    --cover-bg:      linear-gradient(125deg, #500000 0%, #880000 35%, #C20C0C 65%, #E83232 100%);
    --section-bg:    linear-gradient(135deg, #500000 0%, #880000 50%, #C20C0C 100%);
    --red:           #C20C0C;
    --green:         #2D8F00;
    --orange:        #F07800;
}
```

---

### 🟠 滴滴 `didi`

品牌橙，来自滴滴出行标志色。

```css
:root {
    --primary:       #FF7200;
    --primary-dark:  #CC4C00;
    --primary-light: #FF9438;
    --primary-pale:  #FFF4E8;
    --primary-dim:   rgba(255, 114, 0, 0.12);
    --cover-bg:      linear-gradient(125deg, #7A3000 0%, #CC5000 35%, #FF7200 65%, #FF9A40 100%);
    --section-bg:    linear-gradient(135deg, #7A3000 0%, #CC5000 50%, #FF7200 100%);
    --red:           #E1251B;
    --green:         #00B96B;
    --orange:        #FF7200;
}
```

---

### 🔵 微软 `microsoft`

企业蓝，来自 Microsoft Azure / Office 品牌色。

```css
:root {
    --primary:       #0078D4;
    --primary-dark:  #004E8C;
    --primary-light: #2B88D8;
    --primary-pale:  #E8F2FB;
    --primary-dim:   rgba(0, 120, 212, 0.12);
    --cover-bg:      linear-gradient(125deg, #002050 0%, #004E8C 35%, #0078D4 65%, #2B88D8 100%);
    --section-bg:    linear-gradient(135deg, #002050 0%, #004E8C 50%, #0078D4 100%);
    --red:           #D13438;
    --green:         #107C10;
    --orange:        #CA5010;
}
```

---

### 🔵 谷歌 `google`

品牌蓝，来自 Google Material Design 主色。

```css
:root {
    --primary:       #4285F4;
    --primary-dark:  #1A56C4;
    --primary-light: #6CA0F8;
    --primary-pale:  #EEF3FE;
    --primary-dim:   rgba(66, 133, 244, 0.12);
    --cover-bg:      linear-gradient(125deg, #0D2B7A 0%, #1A4AC0 35%, #4285F4 65%, #6CA0F8 100%);
    --section-bg:    linear-gradient(135deg, #0D2B7A 0%, #1A4AC0 50%, #4285F4 100%);
    --red:           #EA4335;
    --green:         #34A853;
    --orange:        #FBBC04;
}
```

---

### ⚫ 苹果 `apple`

极简深色，来自 Apple 官网深色系。副标题用浅灰代替彩色。

#### 苹果主题补充规则

- **信息密度最低**：每页内容比其他主题少 20–30%，大量留白是设计语言的一部分，不是信息不足。
- **黑白灰为主**：图表、卡片、标签优先用黑、深灰、浅灰；主色蓝（`#0071E3`）只做少量强调点缀，不做大面积底色。
- **字重偏细**：正文和副标题权重优先 `300`/`400`；只有核心判断句、数字用 `700`+。
- **圆角更大**：卡片圆角可以比默认值（6px）更大，如 12–16px；边框极细（0.5px）或省略。
- **封面接近纯黑**：封面渐变是黑→深灰，避免使用彩色装饰弧形；字体颜色纯白，简洁有力。
- **Logo 使用**：当前待补充，封面 cover-top 保留部门名文字。

```css
:root {
    --primary:       #0071E3;
    --primary-dark:  #0055B0;
    --primary-light: #3A9AFF;
    --primary-pale:  #EEF5FF;
    --primary-dim:   rgba(0, 113, 227, 0.12);
    --cover-bg:      linear-gradient(125deg, #000000 0%, #1A1A1A 35%, #2C2C2E 65%, #3A3A3C 100%);
    --section-bg:    linear-gradient(135deg, #000000 0%, #1C1C1E 50%, #2C2C2E 100%);
    --text-1:        #1D1D1F;
    --text-2:        #424245;
    --text-3:        #86868B;
    --bg-page:       #F5F5F7;
    --red:           #FF3B30;
    --green:         #34C759;
    --orange:        #FF9500;
}
.header-sub { color: var(--text-3) !important; font-weight: 300 !important; }
```

---

## 主题使用示例

生成时，在 `<style>` 末尾追加对应主题 CSS，例如阿里巴巴主题：

```html
<style>
/* === 基础 CSS（完整复制自 index.html）=== */
...（约 1300 行）...

/* === 主题：阿里巴巴 === */
:root {
    --primary:       #FF6A00;
    --primary-dark:  #CC4400;
    --primary-light: #FF8C38;
    --primary-pale:  #FFF3E8;
    --primary-dim:   rgba(255, 106, 0, 0.12);
    --cover-bg:      linear-gradient(125deg, #7A2000 0%, #CC3800 35%, #FF6A00 65%, #FF9A50 100%);
    --section-bg:    linear-gradient(135deg, #7A2000 0%, #CC4400 50%, #FF6A00 100%);
}
.slide-section {
    background: var(--section-bg) !important;
}
</style>
```

**注意**：`.slide-section` 的 `background` 是 inline style，需要用 `!important` 覆盖，或直接修改 `.slide-section` 的 CSS 规则中的颜色值。
