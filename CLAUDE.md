# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A Jekyll-based security research blog hosted at [sumsec.me](https://sumsec.me) via GitHub Pages. Posts are Markdown files organized by year (`2021/`, `2022/`, `2023/`, `2026/`, `PL/`). The site uses a custom dark/sci-fi theme with matrix rain effects.

## Jekyll Commands

```bash
# Build the site
jekyll build

# Serve locally with live reload
jekyll serve --livereload

# Build and serve (production-like)
BUNDLE_WITHOUT="" bundle exec jekyll serve
```

Requires Jekyll 4.x and Dart Sass (not LibSass).

## Site Structure

- `_config.yml` — Jekyll config: markdown engine (kramdown), highlighter (rouge), Sass settings
- `_layouts/default.html` — main layout: sci-fi terminal header + matrix canvas + `scifi.js`
- `assets/css/style.scss` — all theme styles using CSS custom properties (`--bg-primary`, `--accent-blue`, etc.)
- `assets/js/scifi.js` — matrix rain canvas animation
- `README.md` — serves as the site homepage (`/`); contains the post timeline table
- `resources/` — static assets, AboutMe, Archives, sitemap, RSS feeds

## Adding a New Post

1. Create `YYYY/post-title.md` with front matter:
   ```yaml
   ---
   layout: default
   title: Post Title
   ---
   ```
2. Add a row to `README.md` timeline table under the correct year section
3. Update `resources/Archives.md` if needed
4. **Do not** update hard-coded article counts manually — they are static strings in the HTML

## GitHub Actions

Three automated workflows run on push to `master`:

- **AboutMe** (every 6h + push) — syncs `AboutMe.md`, `rss.xml`, `atom.xml`, and `dist/` SVG assets from other SummerSec repos via `wget`
- **SitemapGenerator** — regenerates `resources/sitemap.xml` and `resources/rss.xml` from repo content
- **Update images** — rewrites old image URLs (`raw.githubusercontent.com/SummerSec/Images/main/`) to CDN (`img.sumsec.me/`) across all Markdown files

Do not manually edit `resources/AboutMe.md`, `resources/rss.xml`, `resources/atom.xml`, or `resources/dist/` — they are overwritten by CI.

## Conventions

- Image CDN base: `https://img.sumsec.me/`
- CNAME: `sumsec.me`
- Commit messages historically use emoji prefix (e.g. `🍭Update Sitemap`) — optional
- The `_site/` directory is gitignored (Jekyll build output)
- `resources/` contains some non-blog files (swagger, vless config, etc.) — leave them as-is
