# 腾讯主题 `tencent`

腾讯蓝为主色，整体接近企业官网的冷静、克制、科技感。微信绿只作正向状态色，不争主色。

## Logo
- 深色页：`./logos/tencent-white.png`
- 白色页：`./logos/tencent-blue.png`

## CSS

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
.slide-section { background: linear-gradient(135deg, #0A1F52 0%, #0B3C94 52%, #0B60D6 100%) !important; }
.slide-qa      { background: linear-gradient(125deg, #0A1F52 0%, #0B3C94 38%, #0B60D6 70%, #3A85F0 100%) !important; }
```

## 补充规则

- **主色唯一**：腾讯蓝是唯一主色；大面积主视觉、标题强调、关键数字优先蓝色体系。
- **绿只作状态色**：微信绿只用于"增长、通过、上线、健康"等正向状态，不用于封面或大面积卡片底色。
- **白底优先**：内容页优先白底或极浅蓝灰底，避免高饱和整页铺色。
- **大留白**：模块间距更宽，单页控制在 3 个重点模块以内。
- **形状克制**：矩形卡片、细边框、浅阴影；不使用过多圆润装饰或强装饰弧形背景。
- **标题直给**：标题更像企业公告或业务判断，避免口号式表达。
- **图表冷静**：蓝、灰、白三色为主，正向强调时引入绿色单点标识。
