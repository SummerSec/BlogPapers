#!/usr/bin/env python3
"""
从仓库内的 Markdown 生成 resources/rss.xml、resources/atom.xml、resources/sitemap.xml，
与线上文章列表保持一致（不依赖外链 blog-rss，也不爬 sumsec.me）。

博文根目录从 resources/Archives.md 中自动解析：凡出现指向 ../<段>/README.md 的链接（相对
Archives.md 所在目录），即把 <段> 视为仓库根下的一层归档目录（如 2026、PL）。新增年份时
只需编辑 Archives.md，不必改本脚本。

依赖：Python 3.10+ 标准库；可选 git 用于每篇文章的最近提交时间。
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent
RESOURCES = REPO_ROOT / "resources"
SITE = "https://sumsec.me"
SITE_DESC = "像清水一般清澈透明"
CHANNEL_TITLE = "SUMSEC"

ARCHIVES_MD = RESOURCES / "Archives.md"
# Archives 未配置任何归档链接时的回退（避免 CI 直接失败）
_FALLBACK_POST_ROOTS = ("2021", "2022", "2023", "2026", "PL")

# 固定收录的站内页（与旧 sitemap 中「导航/说明」一致，不含杂项静态文件）
STATIC_SITEMAP_PATHS = (
    "/",
    "/resources/Archives.html",
    "/resources/AboutMe.html",
    "/resources/README.html",
    "/resources/Advertisements.html",
    "/resources/subdomain.html",
    "/resources/rss.xml",
    "/resources/atom.xml",
)


def git_last_commit_datetime(rel_posix: str) -> datetime | None:
    try:
        out = subprocess.check_output(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "log",
                "-1",
                "--format=%aI",
                "--",
                rel_posix,
            ],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if not out:
            return None
        # 2024-01-01T12:00:00+08:00
        return datetime.fromisoformat(out.replace("Z", "+00:00"))
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return None


def file_mtime_utc(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def title_from_md(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path.stem
    for line in text.splitlines()[:60]:
        s = line.strip()
        if s.startswith("# "):
            return s[2:].strip()
    return path.stem


def discover_post_roots() -> tuple[str, ...]:
    """
    从 Archives.md 提取归档目录名：匹配 (../NAME/README.md)（不区分 README 大小写）。
    NAME 为仓库根下的一级目录；排除 resources（其下 md 由 sitemap 另段处理）。
    """
    if not ARCHIVES_MD.is_file():
        print(
            f"警告：未找到 {ARCHIVES_MD.relative_to(REPO_ROOT).as_posix()}，使用回退归档列表。",
            file=sys.stderr,
        )
        return _FALLBACK_POST_ROOTS
    text = ARCHIVES_MD.read_text(encoding="utf-8", errors="replace")
    pat = re.compile(r"\(\.\./([^/)]+)/README\.md\s*\)", re.IGNORECASE)
    order: list[str] = []
    seen: set[str] = set()
    for m in pat.finditer(text):
        name = m.group(1).strip()
        if not name or name in seen:
            continue
        if name == "resources" or ".." in name or "/" in name:
            continue
        seen.add(name)
        order.append(name)
    if not order:
        print(
            "警告：Archives.md 中未解析到任何 (../<目录>/README.md) 链接，使用回退归档列表。",
            file=sys.stderr,
        )
        return _FALLBACK_POST_ROOTS
    return tuple(order)


def url_for_md(rel: Path) -> str:
    """Jekyll 默认：2026/foo.md -> https://sumsec.me/2026/foo.html"""
    parts = rel.as_posix().split("/")
    stem = parts[-1][:-3]  # .md
    dir_parts = parts[:-1]
    enc_dir = "/".join(quote(seg, safe="") for seg in dir_parts)
    enc_stem = quote(stem, safe="")
    if enc_dir:
        return f"{SITE}/{enc_dir}/{enc_stem}.html"
    return f"{SITE}/{enc_stem}.html"


def collect_posts(post_roots: tuple[str, ...]) -> list[tuple[Path, str, datetime]]:
    """返回 (绝对路径, repo 相对 posix, 排序用时间)。"""
    rows: list[tuple[Path, str, datetime]] = []
    for root_name in post_roots:
        root = REPO_ROOT / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            if path.name == "README.md":
                continue
            rel = path.relative_to(REPO_ROOT)
            rel_posix = rel.as_posix()
            dt = git_last_commit_datetime(rel_posix) or file_mtime_utc(path)
            rows.append((path, rel_posix, dt))
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows


def collect_sitemap_urls(
    posts: list[tuple[Path, str, datetime]], post_roots: tuple[str, ...]
) -> list[str]:
    urls: list[str] = []
    for p in STATIC_SITEMAP_PATHS:
        urls.append(SITE.rstrip("/") + p)

    # 各归档目录 README（与 Archives 中列出的根一致）
    for root_name in post_roots:
        readme = REPO_ROOT / root_name / "README.md"
        if readme.is_file():
            urls.append(url_for_md(readme.relative_to(REPO_ROOT)))

    # resources 下说明向 md
    if RESOURCES.is_dir():
        for path in sorted(RESOURCES.glob("*.md")):
            rel = path.relative_to(REPO_ROOT)
            urls.append(url_for_md(rel))

    for path, _, _ in posts:
        rel = path.relative_to(REPO_ROOT)
        urls.append(url_for_md(rel))
        # 同目录同名 -ppt.html 等独立页
        for extra in path.parent.glob(f"{path.stem}-*.html"):
            rel_html = extra.relative_to(REPO_ROOT)
            segs = [quote(s, safe="") for s in rel_html.as_posix().split("/")]
            urls.append(SITE + "/" + "/".join(segs))

    # 去重保持顺序
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def write_sitemap(urls: list[str]) -> None:
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")
    for loc in urls:
        u = ET.SubElement(urlset, "url")
        ET.SubElement(u, "loc").text = loc
    tree = ET.ElementTree(urlset)
    ET.indent(tree, space="  ")
    out_path = RESOURCES / "sitemap.xml"
    tree.write(out_path, encoding="utf-8", xml_declaration=True, default_namespace=None)
    # ElementTree 默认 standalone 无；与旧文件风格接近即可


def write_rss(posts: list[tuple[Path, str, datetime]]) -> None:
    now = datetime.now(timezone.utc)
    lines = [
        "<?xml version='1.0' encoding='UTF-8'?>",
        '<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0">',
        "<channel>",
        f"<title>{html.escape(CHANNEL_TITLE)}</title>",
        f"<link>{SITE}</link>",
        f"<description>{html.escape(SITE_DESC)}</description>",
        "<docs>http://www.rssboard.org/rss-specification</docs>",
        "<generator>BlogPapers generate_feed_and_sitemap.py</generator>",
        "<language>zh-CN</language>",
        f"<lastBuildDate>{format_datetime(now)}</lastBuildDate>",
        f'<atom:link href="{SITE}/resources/rss.xml" rel="self" type="application/rss+xml"/>',
    ]
    for path, rel_posix, dt in posts:
        link = url_for_md(path.relative_to(REPO_ROOT))
        title = html.escape(title_from_md(path))
        pub = format_datetime(dt.astimezone(timezone.utc))
        guid = html.escape(link)
        lines.append("<item>")
        lines.append(f"<title>{title}</title>")
        lines.append(f"<link>{html.escape(link)}</link>")
        lines.append(f"<guid isPermaLink=\"true\">{guid}</guid>")
        lines.append(f"<pubDate>{pub}</pubDate>")
        lines.append("</item>")
    lines.append("</channel></rss>")
    (RESOURCES / "rss.xml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_atom(posts: list[tuple[Path, str, datetime]]) -> None:
    now = datetime.now(timezone.utc)
    feed = ET.Element(
        "feed",
        {
            "xmlns": "http://www.w3.org/2005/Atom",
            "xml:lang": "zh-CN",
        },
    )
    ET.SubElement(feed, "id").text = SITE + "/"
    ET.SubElement(feed, "title").text = CHANNEL_TITLE
    ET.SubElement(feed, "updated").text = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    ET.SubElement(feed, "link", {"href": f"{SITE}/resources/atom.xml", "rel": "self"})
    ET.SubElement(feed, "link", {"href": SITE, "rel": "alternate"})
    ET.SubElement(feed, "generator", uri="https://github.com/SummerSec/BlogPapers", version="1").text = (
        "BlogPapers generate_feed_and_sitemap.py"
    )
    ET.SubElement(feed, "subtitle").text = SITE_DESC

    for path, rel_posix, dt in posts:
        link = url_for_md(path.relative_to(REPO_ROOT))
        entry = ET.SubElement(feed, "entry")
        ET.SubElement(entry, "id").text = link
        ET.SubElement(entry, "title").text = title_from_md(path)
        ET.SubElement(entry, "updated").text = dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        ET.SubElement(entry, "link", href=link, rel="alternate")

    ET.indent(feed, space="  ")
    atom_path = RESOURCES / "atom.xml"
    tree = ET.ElementTree(feed)
    tree.write(atom_path, encoding="utf-8", xml_declaration=True, default_namespace=None)


def main() -> int:
    if not REPO_ROOT.joinpath("_config.yml").is_file():
        print("请在 BlogPapers 仓库根目录运行。", file=sys.stderr)
        return 1
    post_roots = discover_post_roots()
    posts = collect_posts(post_roots)
    if not posts:
        print("未发现任何博文 Markdown。", file=sys.stderr)
        return 1
    write_rss(posts)
    write_atom(posts)
    urls = collect_sitemap_urls(posts, post_roots)
    write_sitemap(urls)
    print(
        f"已写入 {len(posts)} 条 feed 条目，sitemap {len(urls)} 个 URL；"
        f"归档根目录（来自 Archives.md）：{', '.join(post_roots)}。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
