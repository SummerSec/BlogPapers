#!/usr/bin/env python3
"""从归档目录与时间轴表格生成 categories/ 下的分类目录与独立分类页。"""

from __future__ import annotations

import html
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

REPO_ROOT = Path(__file__).resolve().parent.parent
RESOURCES = REPO_ROOT / "resources"
ARCHIVES_MD = RESOURCES / "Archives.md"
CONFIG_PATH = REPO_ROOT / "_data" / "article_categories.json"
CATEGORY_DIR = REPO_ROOT / "categories"
FALLBACK_ROOTS = ("2021", "2022", "2023", "2026", "PL")
TABLE_LINK_RE = re.compile(r"\[([^\]]+)\]\((.+?)\)")
ARTICLE_FILENAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.md$")


@dataclass(frozen=True)
class IndexEntry:
    title: str
    year: int | None
    month_day: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class Article:
    path: Path
    title: str
    tags: tuple[str, ...]
    published: datetime
    month_day: str


def discover_post_roots() -> tuple[str, ...]:
    if not ARCHIVES_MD.is_file():
        return FALLBACK_ROOTS
    text = ARCHIVES_MD.read_text(encoding="utf-8", errors="replace")
    roots = []
    for match in re.finditer(r"\(\.\./([^/)]+)/README\.md\s*\)", text, re.IGNORECASE):
        name = match.group(1).strip()
        if name and name not in roots and ".." not in name and "/" not in name:
            roots.append(name)
    return tuple(roots) or FALLBACK_ROOTS


def split_tags(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split("/") if part.strip())


def front_matter_tags(path: Path) -> tuple[str, ...]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines or lines[0].strip() != "---":
        return ()
    tags: list[str] = []
    in_tags = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.startswith("tags:"):
            in_tags = True
            inline = stripped[5:].strip().strip("[]")
            if inline:
                tags.extend(part.strip(" \"'") for part in inline.split(",") if part.strip())
            continue
        if in_tags and stripped.startswith("-"):
            tags.append(stripped[1:].strip(" \"'"))
        elif in_tags and stripped and not line.startswith((" ", "\t")):
            in_tags = False
    return tuple(tag for tag in tags if tag and tag.casefold() != "blog-comments")


def title_from_markdown(path: Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[:60]:
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    if lines and lines[0].strip() == "---":
        for line in lines[1:60]:
            stripped = line.strip()
            if stripped == "---":
                break
            match = re.match(r"^title:\s*(.+?)\s*$", stripped, re.IGNORECASE)
            if match:
                title = match.group(1).strip().strip("\"'")
                if title:
                    return title
    raise ValueError(f"文章缺少 H1 或 front matter title：{path.relative_to(REPO_ROOT).as_posix()}")


def parse_indexes(roots: tuple[str, ...]) -> dict[Path, IndexEntry]:
    entries: dict[Path, IndexEntry] = {}

    homepage = REPO_ROOT / "README.md"
    if homepage.is_file():
        current_year: int | None = None
        for line in homepage.read_text(encoding="utf-8", errors="replace").splitlines():
            heading = re.match(r"^#{2,6}\s+(\d{4})(?:\s|$)", line.strip())
            if heading:
                current_year = int(heading.group(1))
                continue
            if not line.lstrip().startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 3 or not re.fullmatch(r"\d{2}/\d{2}", cells[0]):
                continue
            link = TABLE_LINK_RE.search(cells[1])
            if not link:
                continue
            target = unquote(link.group(2).split("#", 1)[0])
            path = (REPO_ROOT / target).resolve()
            try:
                path.relative_to(REPO_ROOT)
            except ValueError:
                continue
            if path.is_file() and path.suffix.casefold() == ".md":
                entries[path] = IndexEntry(link.group(1).strip(), current_year, cells[0], split_tags(cells[2]))

    for root_name in roots:
        readme = REPO_ROOT / root_name / "README.md"
        if not readme.is_file():
            continue
        for line in readme.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.lstrip().startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 3 or not re.fullmatch(r"\d{2}/\d{2}", cells[0]):
                continue
            link = TABLE_LINK_RE.search(cells[1])
            if not link:
                continue
            target = unquote(link.group(2).split("#", 1)[0])
            if target.startswith(("http://", "https://")):
                continue
            path = (readme.parent / target).resolve()
            try:
                path.relative_to(REPO_ROOT)
            except ValueError:
                continue
            if path.is_file() and path.suffix.casefold() == ".md":
                year = int(root_name) if root_name.isdigit() and len(root_name) == 4 else None
                entries.setdefault(path, IndexEntry(link.group(1).strip(), year, cells[0], split_tags(cells[2])))
    return entries


def git_datetime(path: Path) -> datetime | None:
    rel = path.relative_to(REPO_ROOT).as_posix()
    try:
        value = subprocess.check_output(
            ["git", "-c", "core.quotepath=false", "log", "-1", "--format=%aI", "--", rel],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError):
        return None


def article_datetime(path: Path, month_day: str, indexed_year: int | None) -> datetime:
    root = path.relative_to(REPO_ROOT).parts[0]
    year = indexed_year or (int(root) if root.isdigit() and len(root) == 4 else None)
    if year and month_day:
        try:
            return datetime.strptime(f"{year}/{month_day}", "%Y/%m/%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return git_datetime(path) or datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def tracked_paths(roots: tuple[str, ...]) -> set[Path] | None:
    """Git 可用时只生成已跟踪/已暂存内容，避免引用尚未纳入提交的新文章。"""
    try:
        output = subprocess.check_output(
            ["git", "-c", "core.quotepath=false", "ls-files", "-z", "--", *roots],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return {
        (REPO_ROOT / item.decode("utf-8")).resolve()
        for item in output.split(b"\0")
        if item
    }


def collect_articles(
    roots: tuple[str, ...],
    index: dict[Path, IndexEntry],
    pinned: dict[str, str],
) -> list[Article]:
    articles: list[Article] = []
    tracked = tracked_paths(roots)
    for root_name in roots:
        root = REPO_ROOT / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            if path.name.casefold() == "readme.md":
                continue
            rel = path.relative_to(REPO_ROOT).as_posix().casefold()
            # 显式 articles 归属视为刻意收录，即使尚未被 Git 跟踪
            if tracked is not None and path.resolve() not in tracked and rel not in pinned:
                continue
            if not ARTICLE_FILENAME_RE.fullmatch(path.name):
                raise ValueError(f"文章文件名必须使用小写英文 kebab-case：{path.relative_to(REPO_ROOT).as_posix()}")
            entry = index.get(path.resolve())
            month_day = entry.month_day if entry else ""
            tags = entry.tags if entry and entry.tags else front_matter_tags(path)
            articles.append(
                Article(
                    path=path,
                    title=entry.title if entry else title_from_markdown(path),
                    tags=tags,
                    published=article_datetime(path, month_day, entry.year if entry else None),
                    month_day=month_day,
                )
            )
    return sorted(articles, key=lambda article: article.published, reverse=True)


def load_categories() -> list[dict]:
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    categories = data.get("categories", [])
    if not categories or sum(bool(item.get("fallback")) for item in categories) != 1:
        raise ValueError("分类配置必须包含 categories，且只能有一个 fallback 分类。")
    return categories


def explicit_assignments(categories: list[dict]) -> dict[str, str]:
    """配置里 articles 显式指定的归属，优先级高于 tags/keywords/roots。"""
    pinned: dict[str, str] = {}
    for category in categories:
        for rel in category.get("articles", []):
            normalized = unquote(str(rel)).replace("\\", "/").lstrip("./")
            pinned[normalized.casefold()] = category["slug"]
    return pinned


def classify(article: Article, categories: list[dict], pinned: dict[str, str]) -> str:
    rel = article.path.relative_to(REPO_ROOT).as_posix().casefold()
    if rel in pinned:
        return pinned[rel]

    tag_map: dict[str, str] = {}
    for category in categories:
        for tag in category.get("tags", []):
            tag_map.setdefault(tag.casefold(), category["slug"])
    for tag in article.tags:
        if tag.casefold() in tag_map:
            return tag_map[tag.casefold()]

    haystack = " ".join((article.title, *article.tags, article.path.as_posix())).casefold()
    for category in categories:
        if any(keyword.casefold() in haystack for keyword in category.get("keywords", [])):
            return category["slug"]

    root_name = article.path.relative_to(REPO_ROOT).parts[0].casefold()
    for category in categories:
        if root_name in {root.casefold() for root in category.get("roots", [])}:
            return category["slug"]
    return next(category["slug"] for category in categories if category.get("fallback"))


def article_href(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT)
    html_path = rel.with_suffix(".html").as_posix()
    return "../" + "/".join(quote(part, safe="") for part in html_path.split("/"))


def render_index(
    categories: list[dict],
    grouped: dict[str, list[Article]],
    year_counts: list[tuple[str, int]],
) -> str:
    total = sum(len(items) for items in grouped.values())
    lines = [
        "---",
        "layout: default",
        "title: 主题分类",
        "comments: false",
        "---",
        "",
        '<div class="category-browser">',
        '  <header class="category-browser__header">',
        '    <p class="category-browser__eyebrow">TOPIC DIRECTORY / SUMSEC</p>',
        "    <h1>主题分类</h1>",
        "    <p>按主题或年份两个维度浏览全部文章。主题分类在下面按组展示，年份归档见页底；文章原有链接不会改变。</p>",
        f'    <div class="category-browser__summary"><strong>{total}</strong> 篇文章 <span aria-hidden="true">/</span> <strong>{len(categories)}</strong> 条主题路径</div>',
        "  </header>",
        '  <nav class="category-directory" aria-label="主题分类目录">',
    ]
    for category in categories:
        count = len(grouped[category["slug"]])
        group = (category.get("group") or "").strip()
        lines.append(
            f'    <a class="category-directory__link" data-topic="{html.escape(category["accent"])}" href="./{html.escape(category["slug"])}.html">'
        )
        if group:
            lines.append(f'      <span class="category-directory__group">{html.escape(group)}</span>')
        lines.extend(
            [
                f'      <span class="category-directory__code">{html.escape(category["code"])}</span>',
                f'      <span class="category-directory__name">{html.escape(category["name"])}</span>',
                f'      <span class="category-directory__count">{count:02d}</span>',
                "    </a>",
            ]
        )
    lines.extend(["  </nav>"])
    if year_counts:
        lines.extend(
            [
                '  <section class="category-archive" aria-label="按年份浏览">',
                '    <div class="category-page__section-title"><h2>按年份浏览</h2><span><a href="../resources/Archives.html">全部归档</a></span></div>',
                '    <div class="category-archive__grid">',
            ]
        )
        for year, count in year_counts:
            lines.extend(
                [
                    f'      <a class="category-archive__link" href="../{year}/README.html">',
                    f'        <span class="category-archive__year">{year}</span>',
                    f'        <span class="category-archive__count">{count:02d} 篇</span>',
                    "      </a>",
                ]
            )
        lines.extend(["    </div>", "  </section>"])
    lines.extend(["</div>", ""])
    return "\n".join(lines)


def render_article_rows(items: list[Article], indent: str = "      ") -> list[str]:
    lines: list[str] = []
    for article in items:
        root_name = article.path.relative_to(REPO_ROOT).parts[0]
        if article.month_day:
            display_date = article.published.strftime("%Y · %m/%d")
            iso_date = article.published.date().isoformat()
        elif root_name.isdigit() and len(root_name) == 4:
            display_date = root_name
            iso_date = root_name
        else:
            display_date = "更新 " + article.published.strftime("%Y · %m/%d")
            iso_date = article.published.date().isoformat()
        tags = article.tags[:3]
        lines.extend(
            [
                f"{indent}<li>",
                f'{indent}  <a class="category-article__title" href="{article_href(article.path)}">{html.escape(article.title)}</a>',
                f'{indent}  <div class="category-article__meta">',
                f'{indent}    <time datetime="{iso_date}">{display_date}</time>',
            ]
        )
        if tags:
            lines.append(f'{indent}    <span class="category-article__tags" aria-label="文章标签">')
            for tag in tags:
                lines.append(f"{indent}      <span>{html.escape(tag)}</span>")
            lines.append(f"{indent}    </span>")
        lines.extend([f"{indent}  </div>", f"{indent}</li>"])
    return lines


def render_category_page(category: dict, items: list[Article]) -> str:
    name = html.escape(category["name"])
    lines = [
        "---",
        "layout: default",
        f'title: "{category["name"]}"',
        "comments: false",
        "---",
        "",
        f'<div class="category-page" data-topic="{html.escape(category["accent"])}">',
        '  <nav class="category-breadcrumb" aria-label="页面路径"><a href="./README.html">主题分类</a><span aria-hidden="true">/</span><span aria-current="page">' + name + "</span></nav>",
        '  <header class="category-page__header">',
        f'    <p class="category-page__code">{html.escape(category["code"])}</p>',
        f"    <h1>{name}</h1>",
        f'    <p class="category-page__description">{html.escape(category["description"])}</p>',
        f'    <div class="category-page__count"><strong>{len(items)}</strong> 篇文章</div>',
        "  </header>",
        '  <section class="category-page__articles" aria-labelledby="category-articles-title">',
        '    <div class="category-page__section-title"><h2 id="category-articles-title">文章</h2><span>按时间倒序</span></div>',
        '    <ol class="category-article-list">',
    ]
    lines.extend(render_article_rows(items))
    lines.extend(["    </ol>", "  </section>", "</div>", ""])
    return "\n".join(lines)


def main() -> int:
    try:
        roots = discover_post_roots()
        categories = load_categories()
        pinned = explicit_assignments(categories)
        articles = collect_articles(roots, parse_indexes(roots), pinned)
        grouped = {category["slug"]: [] for category in categories}
        for article in articles:
            grouped[classify(article, categories, pinned)].append(article)
        per_root: dict[str, int] = {}
        for article in articles:
            root_name = article.path.relative_to(REPO_ROOT).parts[0]
            per_root[root_name] = per_root.get(root_name, 0) + 1
        year_counts = sorted(
            ((name, count) for name, count in per_root.items() if name.isdigit() and len(name) == 4),
            key=lambda item: item[0],
            reverse=True,
        )
        CATEGORY_DIR.mkdir(parents=True, exist_ok=True)
        (CATEGORY_DIR / "README.md").write_text(
            render_index(categories, grouped, year_counts), encoding="utf-8", newline="\n"
        )
        expected = {"readme.md"}
        for category in categories:
            expected.add(f'{category["slug"]}.md'.casefold())
            (CATEGORY_DIR / f'{category["slug"]}.md').write_text(
                render_category_page(category, grouped[category["slug"]]),
                encoding="utf-8",
                newline="\n",
            )
        # 清理已下线分类遗留的旧页面
        for stale in CATEGORY_DIR.glob("*.md"):
            if stale.name.casefold() not in expected:
                stale.unlink()
                print(f"已删除下线分类页：{stale.name}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"生成主题分类失败：{exc}", file=sys.stderr)
        return 1
    summary = "，".join(f'{category["name"]} {len(grouped[category["slug"]])}' for category in categories)
    print(f"已写入 categories/ 分类目录与 {len(categories)} 个独立分类页：共 {len(articles)} 篇；{summary}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
