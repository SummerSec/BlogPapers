#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 Cloudflare DNS API 拉取指定域名的全部记录，生成 Markdown 表格，
写入 resources/subdomain.md 中 <!--CLOUDFLARE_DNS_SYNC_BEGIN--> … END 之间。

用法（仓库根目录）：
  set CLOUDFLARE_API_TOKEN=你的令牌
  python _scripts/fetch_cloudflare_subdomains.py --write

可选环境变量：
  CLOUDFLARE_ZONE_NAME   默认 sumsec.me
  CLOUDFLARE_ZONE_ID     若已填写则跳过按名称查 zone

令牌权限（最小）：Zone → Zone → Read，Zone → DNS → Read

不写 --write 时只打印将要写入的片段到 stdout，不修改文件。
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from collections import defaultdict
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_BASE = "https://api.cloudflare.com/client/v4"
ROOT = Path(__file__).resolve().parent.parent
SUBDOMAIN_MD = ROOT / "resources" / "subdomain.md"
BEGIN = "<!--CLOUDFLARE_DNS_SYNC_BEGIN-->"
END = "<!--CLOUDFLARE_DNS_SYNC_END-->"


def _request(path: str, token: str) -> dict:
    url = f"{API_BASE}{path}"
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    ctx = ssl.create_default_context()
    try:
        with urlopen(req, timeout=60, context=ctx) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        raise SystemExit(f"HTTP {e.code} {path}\n{err_body}") from e
    except URLError as e:
        raise SystemExit(f"请求失败: {e}") from e
    data = json.loads(body)
    if not data.get("success", False):
        errs = data.get("errors") or data
        raise SystemExit(f"Cloudflare API 错误: {errs}")
    return data


def get_zone_id(token: str, zone_name: str) -> str:
    q = zone_name.replace(" ", "%20")
    data = _request(f"/zones?name={q}", token)
    zones = data.get("result") or []
    if not zones:
        raise SystemExit(f"未找到名为 {zone_name!r} 的 Zone，请检查域名与令牌权限。")
    return zones[0]["id"]


def fetch_all_records(token: str, zone_id: str) -> list[dict]:
    page = 1
    out: list[dict] = []
    while True:
        data = _request(
            f"/zones/{zone_id}/dns_records?page={page}&per_page=100",
            token,
        )
        out.extend(data.get("result") or [])
        info = data.get("result_info") or {}
        total_pages = int(info.get("total_pages") or 1)
        if page >= total_pages:
            break
        page += 1
    return out


def _esc_cell(s: str, max_len: int = 72) -> str:
    s = s.replace("\n", " ").replace("\r", "").strip()
    s = s.replace("|", "\\|")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s or "—"


def build_table(zone_name: str, records: list[dict]) -> str:
    by_name: dict[str, list[dict]] = defaultdict(list)
    zl = zone_name.lower()
    for r in records:
        name = (r.get("name") or "").strip().lower()
        if not name.endswith(zl):
            continue
        by_name[name].append(r)

    lines = [
        "| 主机名 | 类型 | 内容（节选） | Proxied |",
        "| ------ | ---- | ------------ | ------- |",
    ]
    for name in sorted(by_name.keys()):
        rows = by_name[name]
        types = sorted({(x.get("type") or "?").upper() for x in rows})
        type_str = ", ".join(types)
        # 合并同类型多条时取第一条内容展示
        parts = []
        for x in rows:
            t = (x.get("type") or "").upper()
            c = x.get("content") or ""
            if t == "MX":
                prio = x.get("priority")
                parts.append(f"{t} prio={prio} → {_esc_cell(c, 40)}")
            else:
                parts.append(f"{t}: {_esc_cell(c, 48)}")
        content_cell = _esc_cell("；".join(parts), 96)
        proxied_any = "是" if any(x.get("proxied") for x in rows) else "否"
        host = name
        url = f"https://{host}/" if host == zl else f"https://{host}/"
        link = f"[{host}]({url})"
        lines.append(f"| {link} | {_esc_cell(type_str, 24)} | {content_cell} | {proxied_any} |")
    if len(lines) == 2:
        lines.append("| — | — | 无记录 | — |")
    return "\n".join(lines)


def patch_markdown(path: Path, inner: str) -> None:
    text = path.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        raise SystemExit(
            f"{path} 中缺少标记 {BEGIN} 或 {END}，请先按模板加入区块。"
        )
    before, rest = text.split(BEGIN, 1)
    _, after = rest.split(END, 1)
    new_block = f"{BEGIN}\n\n{inner.strip()}\n\n{END}"
    path.write_text(before + new_block + after, encoding="utf-8", newline="\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="从 Cloudflare 同步 DNS 表到 subdomain.md")
    ap.add_argument(
        "--write",
        action="store_true",
        help=f"写入 {SUBDOMAIN_MD.relative_to(ROOT)}（默认仅 stdout）",
    )
    args = ap.parse_args()

    token = (os.environ.get("CLOUDFLARE_API_TOKEN") or "").strip()
    if not token:
        print(
            "请设置环境变量 CLOUDFLARE_API_TOKEN（Zone + DNS 读权限）。",
            file=sys.stderr,
        )
        sys.exit(1)

    zone_name = (os.environ.get("CLOUDFLARE_ZONE_NAME") or "sumsec.me").strip().lower()
    zone_id = (os.environ.get("CLOUDFLARE_ZONE_ID") or "").strip()
    if not zone_id:
        zone_id = get_zone_id(token, zone_name)

    records = fetch_all_records(token, zone_id)
    hostnames = {
        (r.get("name") or "").strip().lower()
        for r in records
        if (r.get("name") or "").strip().lower().endswith(zone_name)
    }
    inner_lines = [
        f"> 以下由 `_scripts/fetch_cloudflare_subdomains.py` 根据 Cloudflare API 生成（共 **{len(records)}** 条原始记录，**{len(hostnames)}** 个主机名）。TXT 等内容已截断。",
        "",
        build_table(zone_name, records),
    ]
    inner = "\n".join(inner_lines)

    if args.write:
        patch_markdown(SUBDOMAIN_MD, inner)
        print(f"已写入: {SUBDOMAIN_MD}", file=sys.stderr)
    print(inner)


if __name__ == "__main__":
    main()
