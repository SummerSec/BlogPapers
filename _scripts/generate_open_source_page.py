#!/usr/bin/env python3
"""
Generate resources/OpenSource.md from SummerSec public GitHub repositories.

The page is static so GitHub Pages can build it without client-side API calls.
Run locally or in CI:

    python3 _scripts/generate_open_source_page.py
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "resources" / "OpenSource.md"
README_ROOT = REPO_ROOT / "resources" / "open-source"
GITHUB_USER = "SummerSec"
API_ROOT = f"https://api.github.com/users/{GITHUB_USER}/repos"
USER_AGENT = "BlogPapers-open-source-page"
README_VARIANTS = (
    ("readme", "README"),
    ("readme_cn", "README_CN"),
    ("readme_en", "README_en"),
)
README_OUTPUT_NAMES = {
    "readme": "README.md",
    "readme_cn": "README_CN.md",
    "readme_en": "README_en.md",
}


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        token = local_gh_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def local_gh_token() -> str:
    try:
        return subprocess.check_output(
            ["gh", "auth", "token"],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        ).strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""


def fetch_json(url: str) -> list[dict]:
    req = Request(url, headers=github_headers())
    for attempt in range(1, 4):
        try:
            with urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8")
            data = json.loads(body)
            return data if isinstance(data, list) else []
        except HTTPError as exc:
            print(f"GitHub API error {exc.code}: {exc.reason}", file=sys.stderr)
            return []
        except URLError as exc:
            if attempt == 3:
                print(f"GitHub API request failed: {exc.reason}", file=sys.stderr)
                return []
            continue


def fetch_text(url: str) -> str:
    req = Request(url, headers=github_headers())
    for attempt in range(1, 4):
        try:
            with urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError) as exc:
            if attempt == 3:
                print(f"README request failed: {url} ({exc})", file=sys.stderr)
                return ""
            continue
    return ""


def fetch_bytes(url: str) -> bytes:
    req = Request(url, headers=github_headers())
    for attempt in range(1, 4):
        try:
            with urlopen(req, timeout=30) as resp:
                return resp.read()
        except (HTTPError, URLError):
            if attempt == 3:
                return b""
            continue
    return b""


def repo_contents(repo: dict) -> list[dict]:
    owner = repo.get("owner", {}).get("login") or GITHUB_USER
    name = repo.get("name", "")
    branch = repo.get("default_branch") or "master"
    url = f"https://api.github.com/repos/{owner}/{name}/contents?ref={branch}"
    return fetch_json(url)


def readme_files(repo: dict) -> dict[str, dict[str, str]]:
    wanted = {key for key, _ in README_VARIANTS}
    by_stem: dict[str, dict[str, str]] = {}
    for item in repo_contents(repo):
        if item.get("type") != "file":
            continue
        filename = str(item.get("name") or "")
        stem = filename.rsplit(".", 1)[0].lower()
        if stem in wanted:
            by_stem[stem] = {
                "name": filename,
                "path": str(item.get("path") or filename),
                "html_url": str(item.get("html_url") or ""),
                "download_url": str(item.get("download_url") or ""),
            }
    return by_stem


def collect_repos() -> list[dict]:
    repos: list[dict] = []
    page = 1
    while True:
        url = (
            f"{API_ROOT}?per_page=100&page={page}"
            "&type=owner&sort=updated&direction=desc"
        )
        batch = fetch_json(url)
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    public_owner_repos = [
        repo for repo in repos
        if not repo.get("fork") and not repo.get("private")
        and int(repo.get("stargazers_count") or 0) > 0
    ]
    sorted_repos = sorted(
        public_owner_repos,
        key=lambda repo: (
            int(repo.get("stargazers_count") or 0),
            int(repo.get("forks_count") or 0),
            repo.get("name", "").lower(),
        ),
        reverse=True,
    )
    for repo in sorted_repos:
        repo["readme_files"] = readme_files(repo)
    return sorted_repos


def fmt_int(value: object) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def esc_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def esc_html(value: object) -> str:
    text = esc_cell(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def yaml_text(value: object) -> str:
    return esc_cell(value).replace("\\", "\\\\").replace('"', '\\"')


def url_path(path: str) -> str:
    return "/".join(quote(part) for part in path.replace("\\", "/").split("/"))


def raw_repo_url(repo: dict, path: str) -> str:
    owner = repo.get("owner", {}).get("login") or GITHUB_USER
    name = repo.get("name", "")
    branch = repo.get("default_branch") or "master"
    return f"https://raw.githubusercontent.com/{owner}/{name}/{branch}/{url_path(path)}"


def github_blob_url(repo: dict, path: str) -> str:
    owner = repo.get("owner", {}).get("login") or GITHUB_USER
    name = repo.get("name", "")
    branch = repo.get("default_branch") or "master"
    return f"https://github.com/{owner}/{name}/blob/{branch}/{url_path(path)}"


def same_repo_github_path(repo: dict, url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        return ""
    owner = repo.get("owner", {}).get("login") or GITHUB_USER
    name = str(repo.get("name") or "")
    if parts[0].lower() != owner.lower() or parts[1].lower() != name.lower():
        return ""
    return posixpath.normpath("/".join(parts[4:]))


def resolve_repo_path(readme_path: str, link: str) -> str:
    parsed = urlparse(link)
    path = parsed.path
    if path.startswith("/"):
        resolved = posixpath.normpath(path.lstrip("/"))
    else:
        base = posixpath.dirname(readme_path)
        resolved = posixpath.normpath(posixpath.join(base, path))
    return "" if resolved.startswith("../") else resolved


def should_keep_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.scheme or url.startswith("#") or url.startswith("//"))


def local_readme_link(repo: dict, path: str) -> str:
    if posixpath.dirname(path):
        return ""
    basename = posixpath.basename(path).rsplit(".", 1)[0].lower()
    links = repo.get("local_readme_links") or {}
    if basename in links:
        return posixpath.basename(links[basename])
    return ""


def split_markdown_target(target: str) -> tuple[str, str]:
    text = target.strip()
    if text.startswith("<") and ">" in text:
        end = text.find(">")
        return text[1:end], text[end + 1:]
    match = re.match(r"([^ \t]+)(.*)$", text, flags=re.S)
    if not match:
        return text, ""
    return match.group(1), match.group(2)


def mirror_image_url(repo: dict, readme_path: str, repo_dir: Path, url: str) -> str:
    if should_keep_url(url):
        return url
    parsed = urlparse(url)
    resolved = resolve_repo_path(readme_path, url)
    if not resolved:
        return url
    raw_url = raw_repo_url(repo, resolved)
    data = fetch_bytes(raw_url)
    if not data:
        return raw_url
    asset_path = repo_dir / "assets" / Path(resolved)
    asset_path.parent.mkdir(parents=True, exist_ok=True)
    asset_path.write_bytes(data)
    rel = posixpath.relpath(
        asset_path.relative_to(repo_dir).as_posix(),
        start=posixpath.dirname(README_OUTPUT_NAMES["readme"]),
    )
    suffix = ""
    if parsed.query:
        suffix += f"?{parsed.query}"
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return f"./{url_path(rel)}{suffix}"


def rewrite_readme_content(repo: dict, readme_path: str, repo_dir: Path, content: str) -> str:
    def rewrite_image(match: re.Match) -> str:
        prefix, target, suffix = match.group(1), match.group(2), match.group(3)
        url, title = split_markdown_target(target)
        return f"{prefix}{mirror_image_url(repo, readme_path, repo_dir, url)}{title}{suffix}"

    def rewrite_link(match: re.Match) -> str:
        prefix, target, suffix = match.group(1), match.group(2), match.group(3)
        url, title = split_markdown_target(target)
        same_repo_path = same_repo_github_path(repo, url)
        if same_repo_path:
            local = local_readme_link(repo, same_repo_path)
            if local:
                return f"{prefix}{local}{title}{suffix}"
        if should_keep_url(url):
            return match.group(0)
        resolved = resolve_repo_path(readme_path, url)
        if not resolved:
            return match.group(0)
        local = local_readme_link(repo, resolved)
        if local:
            return f"{prefix}{local}{title}{suffix}"
        return f"{prefix}{github_blob_url(repo, resolved)}{title}{suffix}"

    def rewrite_img_attr(match: re.Match) -> str:
        return f"{match.group(1)}{mirror_image_url(repo, readme_path, repo_dir, match.group(2))}{match.group(3)}"

    def rewrite_href_attr(match: re.Match) -> str:
        href = match.group(2)
        same_repo_path = same_repo_github_path(repo, href)
        if same_repo_path:
            local = local_readme_link(repo, same_repo_path)
            if local:
                return f"{match.group(1)}{local}{match.group(3)}"
        if should_keep_url(href):
            return match.group(0)
        resolved = resolve_repo_path(readme_path, href)
        if not resolved:
            return match.group(0)
        local = local_readme_link(repo, resolved)
        if local:
            return f"{match.group(1)}{local}{match.group(3)}"
        return f"{match.group(1)}{github_blob_url(repo, resolved)}{match.group(3)}"

    content = re.sub(r"(!\[[^\]]*\]\()([^)]+)(\))", rewrite_image, content)
    content = re.sub(r"(?<!!)(\[[^\]]+\]\()([^)]+)(\))", rewrite_link, content)
    content = re.sub(r"(<img\b[^>]*\bsrc=[\"'])([^\"']+)([\"'])", rewrite_img_attr, content, flags=re.I)
    content = re.sub(r"(<a\b[^>]*\bhref=[\"'])([^\"']+)([\"'])", rewrite_href_attr, content, flags=re.I)
    return content


def write_local_readmes(repos: list[dict]) -> None:
    if README_ROOT.exists():
        shutil.rmtree(README_ROOT)
    README_ROOT.mkdir(parents=True, exist_ok=True)

    for repo in repos:
        name = str(repo.get("name") or "")
        html_url = str(repo.get("html_url") or "")
        repo_dir = README_ROOT / name
        repo_dir.mkdir(parents=True, exist_ok=True)
        local_links: dict[str, str] = {
            key: f"./open-source/{url_path(name)}/{README_OUTPUT_NAMES[key].replace('.md', '.html')}"
            for key in (repo.get("readme_files") or {})
            if key in README_OUTPUT_NAMES
        }
        repo["local_readme_links"] = local_links
        for key, label in README_VARIANTS:
            info = (repo.get("readme_files") or {}).get(key)
            if not info:
                continue
            source = fetch_text(info.get("download_url", ""))
            if not source:
                continue
            output_name = README_OUTPUT_NAMES[key]
            output_path = repo_dir / output_name
            title = f"{name} {label}"
            body = rewrite_readme_content(repo, info.get("path", output_name), repo_dir, source)
            output_path.write_text(
                f"---\nlayout: default\ntitle: \"{yaml_text(title)}\"\ncomments: false\n---\n\n"
                f"<p class=\"open-source-readme-nav\"><a href=\"../../OpenSource.html\">返回 Github开源项目</a> · "
                f"<a href=\"{esc_html(html_url)}\">GitHub 仓库</a></p>\n\n"
                f"{{% raw %}}\n{body}\n{{% endraw %}}\n",
                encoding="utf-8",
                newline="\n",
            )


def repo_row(index: int, repo: dict) -> str:
    name = esc_html(repo.get("name", ""))
    url = esc_html(repo.get("html_url", ""))
    readmes = repo.get("local_readme_links") or {}
    readme_links_html = []
    for key, label in README_VARIANTS:
        readme_url = esc_html(readmes.get(key, ""))
        if readme_url:
            readme_links_html.append(f'<a href="{readme_url}">{label}</a>')
    readme_cell = " ".join(readme_links_html) if readme_links_html else '<span class="muted">-</span>'
    desc = esc_html(repo.get("description") or "")
    stars = fmt_int(repo.get("stargazers_count"))
    updated = esc_html((repo.get("pushed_at") or repo.get("updated_at") or "")[:10])
    return f"""  <tr>
    <td class="num">{index}</td>
    <td class="project"><a href="{url}">{name}</a></td>
    <td class="num">{stars}</td>
    <td>{updated}</td>
    <td class="readme-links">{readme_cell}</td>
    <td>{desc}</td>
  </tr>"""


def render_page(repos: list[dict]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_stars = sum(int(repo.get("stargazers_count") or 0) for repo in repos)
    rows = "\n".join(repo_row(i, repo) for i, repo in enumerate(repos, 1))
    return f"""---
layout: default
title: Github开源项目
comments: false
---

# Github开源项目

这里按 Star 数量从高到低列出 [SummerSec](https://github.com/{GITHUB_USER}) 名下公开、非 fork 的 GitHub 仓库。README 链接会同步为本站镜像页，原文中的相对图片会尽量本地化。

> 数据生成时间：{generated}；共 {len(repos)} 个项目，累计 {fmt_int(total_stars)} Stars。

<div class="open-source-table-wrap">
<table class="open-source-table">
  <thead>
    <tr>
      <th>#</th>
      <th>项目</th>
      <th>Stars</th>
      <th>最近更新</th>
      <th>README</th>
      <th>简介</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</div>
"""


def main() -> int:
    if not (REPO_ROOT / "_config.yml").is_file():
        print("Please run this script inside the BlogPapers repository.", file=sys.stderr)
        return 1
    repos = collect_repos()
    if not repos:
        print("No public owner repositories found.", file=sys.stderr)
        return 1
    write_local_readmes(repos)
    OUT_PATH.write_text(render_page(repos), encoding="utf-8", newline="\n")
    print(f"Wrote {OUT_PATH.relative_to(REPO_ROOT).as_posix()} with {len(repos)} repositories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
