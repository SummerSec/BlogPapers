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
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "resources" / "OpenSource.md"
GITHUB_USER = "SummerSec"
API_ROOT = f"https://api.github.com/users/{GITHUB_USER}/repos"
USER_AGENT = "BlogPapers-open-source-page"
README_VARIANTS = (
    ("readme", "README"),
    ("readme_cn", "README_CN"),
    ("readme_en", "README_en"),
)


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


def repo_contents(repo: dict) -> list[dict]:
    owner = repo.get("owner", {}).get("login") or GITHUB_USER
    name = repo.get("name", "")
    branch = repo.get("default_branch") or "master"
    url = f"https://api.github.com/repos/{owner}/{name}/contents?ref={branch}"
    return fetch_json(url)


def readme_links(repo: dict) -> dict[str, str]:
    wanted = {key for key, _ in README_VARIANTS}
    by_stem: dict[str, str] = {}
    for item in repo_contents(repo):
        if item.get("type") != "file":
            continue
        filename = str(item.get("name") or "")
        stem = filename.rsplit(".", 1)[0].lower()
        if stem in wanted:
            by_stem[stem] = str(item.get("html_url") or "")

    base = str(repo.get("html_url") or "")
    if "readme" not in by_stem and base:
        by_stem["readme"] = f"{base}#readme"
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
        repo["readme_links"] = readme_links(repo)
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


def repo_row(index: int, repo: dict) -> str:
    name = esc_html(repo.get("name", ""))
    url = esc_html(repo.get("html_url", ""))
    readmes = repo.get("readme_links") or {}
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

这里按 Star 数量从高到低列出 [SummerSec](https://github.com/{GITHUB_USER}) 名下公开、非 fork 的 GitHub 仓库。README 链接会按仓库根目录实际存在的文件生成。

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
    OUT_PATH.write_text(render_page(repos), encoding="utf-8", newline="\n")
    print(f"Wrote {OUT_PATH.relative_to(REPO_ROOT).as_posix()} with {len(repos)} repositories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
