# 阿里巴巴主题 `alibaba`

品牌橙，来自阿里巴巴集团标志色。

## Logo
- 白色页（内容页）：`./logos/alibaba.png`（橙色彩色版）
- 深色页（封面/章节/结尾）：无白色版，使用彩色版 + `filter:brightness(0) invert(1)` 转白

## CSS

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
}
.slide-section { background: linear-gradient(135deg, #7A2000 0%, #CC4400 50%, #FF6A00 100%) !important; }
.slide-qa      { background: linear-gradient(125deg, #7A2000 0%, #CC3800 35%, #FF6A00 65%, #FF9A50 100%) !important; }
.header-sub    { color: var(--primary) !important; }
.agenda-num    { color: var(--primary) !important; }
```
