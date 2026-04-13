<p align="center">
  <img src="logos/slide-writer.png" alt="Slide-Writer" width="200"/>
</p>

# Slide-Writer

[在线演示](https://feei.cn/slide-writer/)
[English](README.md)

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/FeeiCN/slide-writer/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Website](https://img.shields.io/badge/Website-feei.cn-blue.svg)](https://feei.cn/slide-writer/)


> 您只需专注目标、观点与判断，Slide-Writer 负责结构、写作、优化与呈现。

一个专为 PPT 场景设计的写作 Skill。它帮助您将想法、大纲、文档、演讲稿、笔记、数据或现有 PPT，快速整理为结构清晰、表达准确、适合演示的企业级 HTML 演示PPT。

## 背景

做一份好 PPT 往往要花掉大量时间，却和核心表达没有直接关系——找模板、调配色、对齐元素、挑字体……这些都是体力活。Slide-Writer 的目标是把这些都自动化，让你只需关注"说什么"，而不是"怎么排"。

你专注于目标、观点与判断，Slide-Writer 负责结构、写作、优化与呈现。无论你给的是一句话、一份大纲、一篇文档、一段演讲稿，还是已有的旧 deck，Slide-Writer 都能将其整理为表达准确、适合演示的 PPT。

## 核心特性

**简单易用**：无论是输入一句话、大纲、草稿还是演讲稿，都可自动生成一套完整演示文稿。
- 从一个想法生成 PPT
- 从一个主题或目标生成 PPT
- 从演讲稿转成 PPT
- 从大纲扩展为完整 PPT
- 从笔记、文档、报告转成 PPT
- 优化已有 HTML 演示稿
- 压缩长 PPT 或扩展短 PPT
- 基于同一内容生成不同受众版本

**企业级视觉表达**：专为企业汇报、管理层沟通、部门分享、峰会演讲等正式场景设计。
- 内置多家互联网公司品牌主题，支持主题自动识别与切换
- 统一 Logo 展示、配色、排版与视觉规范
- 精确对齐、统一间距、专业字体搭配
- 整体风格更适合正式演示，而非普通网页排版

**完整的演示结构**：不只是“把文字放上页面”，而是自动生成一套更适合演示的结构。
- 自动规划章节与页面顺序
- 内置封面页、目录页、章节过渡页、结尾页
- 根据内容自动拆页，避免信息堆叠
- 支持从文档表达转为演示表达
- 优先复用已经沉淀好的页面骨架，而不是每一页都从零拼布局

**自动润色与内容重构**：不仅负责排版，还会对内容进行演示化改写，让表达更准确、更简练、更适合展示。
- 优化标题层级、要点列表、正文段落
- 将长文、草稿、纪要重构为更清晰的 Slide 结构
- 自动润色每一句话，提升表达的准确性与力量感
- 解决常见问题：内容很多，但结构不清；有判断，但表达不够凝练；有材料，但不知道如何拆页；有初稿，但不像正式演示稿；同一内容需要适配多个场景和受众；大量时间花在润色、改写和调顺序上

**丰富的页面表达能力**：支持多种常见演示内容形式，而不只是普通文字页。
- 动画：元素入场动画、页面切换动画
- 数据可视化：柱状图、折线图、环形图（基于内联 SVG）
- 步骤流程图
- 表格
- 图文混排
- 卡片化信息展示
- 页面级骨架：统一标题区、分组目录、双阶段流程、横向支撑板、流转看板
- 更适合企业汇报与演讲的结构化页面组件

**纯前端单文件交付**：输出标准单个 HTML 文件，浏览器直接打开，无需安装 PowerPoint 或 Keynote。
- CSS / JS / 图片 / 字体全内置
- 支持键盘翻页、导航点、全屏展示
- 响应式布局，适配不同屏幕与投影分辨率
- 图表基于 SVG 内联实现，无需外部图表库
- 动画基于 CSS Transitions 实现
- 纯 HTML + CSS + JavaScript，零依赖，无需构建工具

**自动保持最新**：每次运行时自动从仓库拉取最新版本，主题、组件、生成规则始终是最新的，无需手动更新。

## 模板职责

`index.html` 是当前仓库里唯一的生成基线模板。

- 它既提供运行所需的 CSS / JS 引擎，也承载页面骨架和组件演示。
- 生成新 deck 时，应从 `index.html` 出发，替换其中的示例主题、示例文案和示例页面内容。
- 不要把 `index.html` 当成“只读参考稿”；它的示例内容本身就是为了被替换。
- 如果后续需要长期保留更多展示样例，建议另建独立样例文件，而不是复制出第二套模板基线。

## 快速开始

```bash
# Claude
git clone https://github.com/FeeiCN/slide-writer.git ~/.claude/skills/slide-writer

# Codex
git clone https://github.com/FeeiCN/slide-writer.git ~/.agents/skills/slide-writer
```

使用示例：

```text
/slide-writer 帮我生成一个「人为什么要吃饭」的演讲 PPT，使用支付宝风格。
```

```text
使用 slide-writer，基于演讲稿 examples/tencent-pony-ma.md，生成一个演讲 PPT。
```

```text
我明天有一个演讲，现在有一些初步想法（examples/alibaba-ai-rollout.md），基于此生成一个演讲 PPT。
```

![蚂蚁演示](examples/test-antgroup-eric.png)
![阿里巴巴演示](examples/test-alibaba-jack-ma.png)
![腾讯演示](examples/test-tencent-pony-ma.png)


## 仓库结构

- `README.md`：英文版项目说明与快速开始
- `README.zh-CN.md`：中文版项目说明
- `SKILL.md`：Skill 定义与执行规则
- `themes.md`：主题与 Logo 规则
- `components.md`：页面组件库
- `index.html`：基础模板 + 页面骨架演示
- `examples/`：示例输入输出
- `TESTING.md`：测试说明

### 快速测试

1. 选一个 [examples](examples) 里的样例作为输入。
2. 让模型基于本仓库里的 `SKILL.md` 生成 `test-*.html` 到仓库根目录。
3. 运行：

```bash
./scripts/preview.sh
```

4. 浏览器打开 `http://localhost:8000/test-xxx.html` 预览。

更完整的测试流程和回归清单见 [TESTING.md](TESTING.md)。
