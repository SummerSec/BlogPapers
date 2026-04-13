# Repository Guidelines

## Project Structure & Module Organization

This repository is a prompt-and-template package for generating browser-based slide decks. Core guidance lives in `SKILL.md`, `themes.md`, and `components.md`. The single generation baseline is `index.html`. Example inputs are stored in `examples/`, brand assets in `logos/`, and local preview tooling in `scripts/`. Temporary generated decks should stay in the repo root as `test-*.html` unless they are promoted into a curated sample.

## Build, Test, and Development Commands

There is no build step or package manager in this project. Use:

```bash
./scripts/preview.sh
```

Starts a local static server at `http://localhost:8000`.

```bash
./scripts/preview.sh 9000
```

Starts the same preview flow on a custom port.

Contributors should generate or edit a single self-contained HTML file, then open it in a browser and validate it against `TESTING.md`.

## Coding Style & Naming Conventions

Keep outputs dependency-free and self-contained: HTML, CSS, and JavaScript stay inline unless the repository already provides an asset file. Follow the existing style in `index.html`: semantic section names, descriptive CSS custom properties, and consistent 4-space indentation inside large CSS blocks. Use kebab-case for CSS classes such as `slide-cover` and `info-card`, and prefix throwaway test files as `test-*.html`.

## Testing Guidelines

Testing is manual and browser-based. Follow the regression checklist in `TESTING.md`, especially after changing `SKILL.md`, `themes.md`, `components.md`, or `index.html`. Verify no slide overflows `100vh`, logos load correctly, navigation and fullscreen still work, and different page types keep visual rhythm. When relevant, test both a fresh generation and an edit pass on an existing deck.

## Version Management

When bumping the version number:
1. Update `SKILL.md` frontmatter: `version: x.y.z`
2. Update `README.md` badge: `version-x.y.z-blue.svg`
3. Create a GitHub release: `gh release create vx.y.z --title "vx.y.z" --notes "..." --repo FeeiCN/slide-writer`

## Commit & Pull Request Guidelines

Git history is currently minimal (`Initial commit`), so keep commit subjects short, imperative, and specific, for example `Refine Tencent theme spacing`. Pull requests should explain the user-visible change, list files touched, mention the sample or scenario used for validation, and include screenshots or exported deck previews when layout or theme behavior changes.
