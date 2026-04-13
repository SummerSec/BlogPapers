# 字节跳动主题 `bytedance`

深色极简，来自字节跳动企业品牌的现代感，配以高亮蓝作为主色。

## Logo
- 待补充（封面 cover-top 保留部门名文字）

## CSS

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
.slide-section { background: linear-gradient(135deg, #0A0F1E 0%, #0F2040 50%, #005FE7 100%) !important; }
.slide-qa      { background: linear-gradient(125deg, #0A0F1E 0%, #0F1F3D 35%, #1A3A6E 65%, #005FE7 100%) !important; }
```

## 补充规则

- **深色封面强对比**：封面和章节页接近全黑，文字白色，高对比度；不在深色背景上用浅蓝或灰色文字。
- **数字大而突出**：`stat-block` 和数字类组件可比默认字号更大，强调规模感。
- **卡片用 subtle shadow**：内容页卡片优先用轻阴影（`box-shadow:0 2px 8px rgba(0,0,0,0.08)`）而非彩色边框。
- **主色只做点缀**：蓝色主色用于关键数字、高亮词、进度条；大面积内容页背景保持白/极浅灰。
