# AGENTS.md

## Cursor Cloud specific instructions

This is a **Jekyll-based static blog** (GitHub Pages) using the `jekyll-theme-hacker` theme. The site renders Markdown articles organized by year into a personal security research blog at `sumsec.me`.

### Running the dev server

```bash
bundle exec jekyll serve --host 0.0.0.0 --port 4000
```

The site is accessible at `http://localhost:4000/`. Jekyll watches for file changes and auto-regenerates.

### Key caveats

- There is **no linting or automated test suite** in this repo — it is a content-only blog.
- The `github-pages` gem pins Jekyll to v3.x; do not attempt to upgrade to Jekyll 4.
- A GitHub Metadata warning (`No GitHub API authentication could be found`) appears during build — this is harmless in local dev and can be ignored.
- `vendor/bundle` is the local gem install path (configured via `.bundle/config`). It is gitignored.
- The `_site/` directory is the build output and is also gitignored.
- Blog posts are plain Markdown files under `2021/`, `2022/`, `2026/`, and `PL/` directories. `README.md` at the root serves as the homepage index.
