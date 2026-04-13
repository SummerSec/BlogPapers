# 苹果主题 `apple`

极简深色，来自 Apple 官网深色系。副标题用浅灰代替彩色。

## Logo
- 待补充（封面 cover-top 保留部门名文字）

## CSS

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
.slide-section { background: linear-gradient(135deg, #000000 0%, #1C1C1E 50%, #2C2C2E 100%) !important; }
.slide-qa      { background: linear-gradient(125deg, #000000 0%, #1A1A1A 35%, #2C2C2E 65%, #3A3A3C 100%) !important; }
.header-sub    { color: var(--text-3) !important; font-weight: 300 !important; }
```

## 补充规则

- **信息密度最低**：每页内容比其他主题少 20–30%，大量留白是设计语言的一部分。
- **黑白灰为主**：图表、卡片、标签优先黑、深灰、浅灰；主色蓝只做少量强调点缀，不做大面积底色。
- **字重偏细**：正文和副标题权重优先 `300`/`400`；只有核心判断句、数字用 `700`+。
- **圆角更大**：卡片圆角可比默认值（6px）更大，如 12–16px；边框极细（0.5px）或省略。
- **封面接近纯黑**：封面渐变是黑→深灰，避免彩色装饰弧形；字体纯白，简洁有力。
