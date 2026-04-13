<p align="center">
  <img src="logos/slide-writer.png" alt="Slide-Writer" width="200"/>
</p>

# Slide-Writer

[Live Demo](https://feei.cn/slide-writer/)
[中文](README.zh-CN.md)

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/FeeiCN/slide-writer/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Website](https://img.shields.io/badge/Website-feei.cn-blue.svg)](https://feei.cn/slide-writer/)

> Focus on goals, viewpoints, and judgment. Slide-Writer handles structure, writing, refinement, and presentation.

Slide-Writer is a writing skill built specifically for presentation workflows. It helps turn ideas, outlines, documents, speech drafts, notes, data, or existing decks into enterprise-grade HTML slide presentations that are structured, clear, and presentation-ready.

## Background

Building a strong presentation usually takes a lot of time, but much of that time has little to do with the core message: finding templates, adjusting colors, aligning elements, choosing fonts. Those are mostly production chores. Slide-Writer is designed to automate that work so you can focus on what to say, not how to lay it out.

You focus on goals, viewpoints, and judgment. Slide-Writer handles structure, writing, refinement, and presentation. Whether you start from a sentence, an outline, a document, a speech draft, or an old deck, Slide-Writer reshapes it into a presentation that is accurate, structured, and ready to present.

## Core Features

**Easy to use**: generate a complete deck from a sentence, outline, draft, or speech manuscript.
- Generate a deck from a single idea
- Generate a deck from a theme or objective
- Turn a speech draft into slides
- Expand an outline into a full presentation
- Convert notes, documents, or reports into slides
- Improve an existing HTML slide deck
- Compress a long deck or expand a short one
- Produce multiple audience-specific versions from the same source

**Enterprise-grade visual language**: built for formal scenarios such as executive reviews, internal communication, cross-team updates, and summit speeches.
- Includes multiple internet-company brand themes with automatic theme detection and switching
- Unifies logo display, colors, typography, and layout conventions
- Provides precise alignment, consistent spacing, and professional visual rhythm
- Produces decks that look like formal presentations rather than generic web pages

**Complete presentation structure**: not just “putting text on slides,” but generating a deck structure that fits presentation delivery.
- Automatically plans sections and slide order
- Includes cover, agenda, section divider, and closing slides
- Splits dense content across slides automatically
- Converts document-style writing into presentation-style writing
- Reuses established page skeletons instead of rebuilding every slide from scratch

**Automatic rewriting and content restructuring**: Slide-Writer does more than layout. It rewrites content into presentation form so it becomes clearer, tighter, and more suitable for speaking.
- Refines titles, bullet hierarchy, and paragraph structure
- Restructures long drafts, notes, and documents into better slide logic
- Polishes wording for stronger clarity and sharper expression
- Helps with common problems: too much content, weak structure, unclear judgment, source material that is hard to split into slides, drafts that do not yet look presentation-ready, or one source that must serve multiple audiences

**Rich page-level expression**: supports many common presentation patterns beyond plain text slides.
- Animations: element reveals and page transitions
- Data visualization: bar charts, line charts, and donut charts with inline SVG
- Step and flow diagrams
- Tables
- Mixed image/text layouts
- Card-based information presentation
- Page skeletons: fixed title area, grouped agenda, dual-phase process, support board, and flow board
- Structured slide components that are better suited for business presentations and speeches

**Single-file frontend delivery**: outputs a standard standalone HTML file that opens directly in a browser, without PowerPoint or Keynote.
- CSS / JS / images / fonts are embedded or bundled for direct use
- Supports keyboard navigation, navigation dots, and fullscreen mode
- Responsive layout for different screens and projector resolutions
- Charts are built with inline SVG, without external chart libraries
- Animations are implemented with CSS transitions
- Pure HTML + CSS + JavaScript, with no build tool and no runtime dependency

**Always up to date**: automatically pulls the latest version from the repository at the start of every run, so you always get the newest themes, components, and generation rules without any manual update.

## Template Role

`index.html` is the single generation baseline in this repository.

- It provides the CSS / JS runtime, the page skeletons, and the component demonstrations.
- New decks should start from `index.html`, replacing the sample theme, sample copy, and sample slide content.
- Do not treat `index.html` as a read-only reference deck. Its example content is meant to be replaced.
- If you need to preserve more showcase decks later, add separate sample files instead of creating a second template baseline.

## Quick Start

```bash
# Claude
git clone https://github.com/FeeiCN/slide-writer.git ~/.claude/skills/slide-writer

# Codex
git clone https://github.com/FeeiCN/slide-writer.git ~/.agents/skills/slide-writer
```

Usage examples:

```text
/slide-writer Generate a presentation on "Why do humans need to eat?" using Alipay style.
```

```text
Use slide-writer and generate a presentation from the speech draft in examples/tencent-pony-ma.md.
```

```text
I have a speech tomorrow and only have some early ideas in examples/alibaba-ai-rollout.md. Use them to generate a presentation.
```

![Ant Group Demo](examples/test-antgroup-eric.png)
![Alibaba Demo](examples/test-alibaba-jack-ma.png)
![Tencent Demo](examples/test-tencent-pony-ma.png)

## Repository Structure

- `README.md`: English project overview and quick start
- `README.zh-CN.md`: Chinese documentation
- `SKILL.md`: skill definition and execution rules
- `themes.md`: theme and logo rules
- `components.md`: page component library
- `index.html`: baseline template and page skeleton gallery
- `examples/`: sample inputs and outputs
- `TESTING.md`: testing notes

### Quick Test

1. Pick one sample from [examples](examples).
2. Ask the model to generate a `test-*.html` file in the repository root based on this repo’s `SKILL.md`.
3. Run:

```bash
./scripts/preview.sh
```

4. Open `http://localhost:8000/test-xxx.html` in a browser.

See [TESTING.md](TESTING.md) for the full testing flow and regression checklist.
