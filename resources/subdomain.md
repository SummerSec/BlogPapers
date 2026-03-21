---
tags:
- blog-comments
---

## 个人使用子域名工具集合

以下为 **sumsec.me** 相关子域整理。**截图**列中：带 GitHub `user-assets` 的为已上传的固定图；标「—」的尚未配图，可自行截图后上传到图床（如 `img.sumsec.me`）再替换该单元格为 `![说明](图片URL)`。

### 站点说明与截图（手工维护）

| 子域名 | 描述 | 截图 |
| ------ | ---- | ---- |
| [sumsec.me](https://sumsec.me/) | 主站 / GitHub Pages 博客 | — |
| [old.sumsec.me](https://old.sumsec.me/) | 旧版博客（导航「NOTEBOOK」） | — |
| [bing.sumsec.me](https://bing.sumsec.me/) | Bing / Chat（曾用，可能不可用） | — |
| [capi.sumsec.me](https://capi.sumsec.me/) | 博客访问统计 API（Worker，返回 JSON） | — |
| [codeql.sumsec.me](https://codeql.sumsec.me/) | CodeQL / GitHub 相关项目页 | ![codeql](https://github.com/SummerSec/BlogPapers/assets/47944478/48b0999e-b6b9-44ad-add2-03a92a26c932) |
| [gd.sumsec.me](https://gd.sumsec.me/) | Google Dork / Bug Bounty 辅助 | ![gd](https://github.com/SummerSec/BlogPapers/assets/47944478/6706bb43-e95f-4145-b221-396dad4b94f2) |
| [gemini.sumsec.me](https://gemini.sumsec.me/) | Gemini 对话前端 | ![gemini](https://github.com/SummerSec/BlogPapers/assets/47944478/9509386c-0011-4b5e-87ae-c9593535f541) |
| [gh.sumsec.me](https://gh.sumsec.me/) | GitHub 文件加速 | ![gh](https://github.com/SummerSec/BlogPapers/assets/47944478/75cd3731-9023-4ca5-a2aa-5c14c3b24d76) |
| [gpt.sumsec.me](https://gpt.sumsec.me/) | ChatGPT 类对话 | ![gpt](https://github.com/SummerSec/BlogPapers/assets/47944478/05f07add-b653-4d72-9bac-b7942ae37d1f) |
| [gs.sumsec.me](https://gs.sumsec.me/) | GitHub Star 工具 | ![gs](https://github.com/SummerSec/BlogPapers/assets/47944478/7eefc891-649e-49cd-bb5e-087e0b3c9bb5) |
| [ht.sumsec.me](https://ht.sumsec.me/) | 糊涂工具箱 | ![ht](https://github.com/SummerSec/BlogPapers/assets/47944478/5dbddfc9-07f1-48ba-a7bf-28cab0f5193f) |
| [img.sumsec.me](https://img.sumsec.me/) | 图床 CDN（博客图片；根路径未必有站点首页） | — |
| [jb.sumsec.me](https://jb.sumsec.me/) | IDE 相关工具 | ![jb](https://github.com/SummerSec/BlogPapers/assets/47944478/f28bc39e-986a-4c9f-bbf9-788e690f934d) |
| [life.sumsec.me](https://life.sumsec.me/) | 阅读笔记（久未更新） | ![life](https://github.com/SummerSec/BlogPapers/assets/47944478/6c3c9b2b-09a9-40bb-b9a3-f31bccbc9627) |
| [sl.sumsec.me](https://sl.sumsec.me/sl) | 短链服务 | ![sl](https://github.com/SummerSec/BlogPapers/assets/47944478/9279b0ac-00f4-4115-9e43-4cb192f3ffe1) |
| [sy.sumsec.me](https://sy.sumsec.me/) | 图片水印工具 | ![sy](https://github.com/SummerSec/BlogPapers/assets/47944478/44a17963-a6ba-4593-af6a-34b7d0e643f9) |
| [vless.sumsec.me](https://vless.sumsec.me/) | VLESS 配置中的节点域名（见 `resources/vless.yaml`，通常非 Web 首页） | — |
| [webcheck.sumsec.me](https://webcheck.sumsec.me/) | WebCheck 站点检测 | ![webcheck](https://github.com/SummerSec/BlogPapers/assets/47944478/03702ed0-7078-4b09-83a5-efaf4a946a8d) |

### Cloudflare DNS 全量（脚本同步）

**GitHub Actions（推荐）**：在仓库 **Settings → Secrets and variables → Actions** 中新增 Secret **`CLOUDFLARE_API_TOKEN`**（Cloudflare 令牌，需 Zone + DNS 读权限），然后在 **Actions** 里运行工作流 **Sync Cloudflare DNS (subdomain.md)**；亦可每日 **UTC 0:00** 自动同步（无变更则不提交）。详见 `_scripts/README.md`。

**本地**：设置环境变量 `CLOUDFLARE_API_TOKEN` 后，在仓库根目录执行 `python _scripts/fetch_cloudflare_subdomains.py --write`（不写 `--write` 则只打印片段）。可选：`CLOUDFLARE_ZONE_NAME`、`CLOUDFLARE_ZONE_ID`。

<!--CLOUDFLARE_DNS_SYNC_BEGIN-->

> 以下由 `_scripts/fetch_cloudflare_subdomains.py` 根据 Cloudflare API 生成（共 **67** 条原始记录，**55** 个主机名）。TXT 等内容已截断。

| 主机名 | 类型 | 内容（节选） | Proxied |
| ------ | ---- | ------------ | ------- |
| [69cd55c1fa2af3f77b47341d33c387b8.sumsec.me](https://69cd55c1fa2af3f77b47341d33c387b8.sumsec.me/) | CNAME | CNAME: verify.bing.com | 是 |
| [_acme-challenge.sumsec.me](https://_acme-challenge.sumsec.me/) | TXT | TXT: uO5fmJLkmmJdeOJpDJVLOOdErZY5Ulp1dGuoY_m86Jw | 否 |
| [_dmarc.sumsec.me](https://_dmarc.sumsec.me/) | TXT | TXT: v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto… | 否 |
| [_dnslink.jb.sumsec.me](https://_dnslink.jb.sumsec.me/) | TXT | TXT: "dnslink=/ipns/3.jetbra.in" | 否 |
| [_github-pages-challenge-summersec.sumsec.me](https://_github-pages-challenge-summersec.sumsec.me/) | TXT | TXT: f5348f974e140dd9ff5af3dedb7bd8 | 否 |
| [_mailchannels.sumsec.me](https://_mailchannels.sumsec.me/) | TXT | TXT: v=mc1 cfid=sumsec.me | 否 |
| [ait.sumsec.me](https://ait.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [arl.sumsec.me](https://arl.sumsec.me/) | CNAME | CNAME: 413a8c38-4ac9-4828-97cd-828c83f75e69.cfargotunn… | 是 |
| [awvs.sumsec.me](https://awvs.sumsec.me/) | CNAME | CNAME: c424a3e4-916b-4174-8d44-c9e59b54fbb5.cfargotunn… | 是 |
| [bing.sumsec.me](https://bing.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [capi.sumsec.me](https://capi.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [cf-ai.sumsec.me](https://cf-ai.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [cf2024-1._domainkey.sumsec.me](https://cf2024-1._domainkey.sumsec.me/) | TXT | TXT: "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w… | 否 |
| [chat.sumsec.me](https://chat.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [code-e62txx8fdi.sumsec.me](https://code-e62txx8fdi.sumsec.me/) | CNAME | CNAME: ziyuan.baidu.com | 是 |
| [codeql.sumsec.me](https://codeql.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [ddns.sumsec.me](https://ddns.sumsec.me/) | AAAA | AAAA: 2409:8a28:8b7:a2c0:fdc5:5815:2e17:d262 | 否 |
| [deeplx.sumsec.me](https://deeplx.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [draw.sumsec.me](https://draw.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [gd.sumsec.me](https://gd.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [gemini.sumsec.me](https://gemini.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 否 |
| [gh.sumsec.me](https://gh.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [gpt.sumsec.me](https://gpt.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [gs.sumsec.me](https://gs.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [ht.sumsec.me](https://ht.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [img.sumsec.me](https://img.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [jb.sumsec.me](https://jb.sumsec.me/) | CNAME | CNAME: ipfs.cloudflare.com | 是 |
| [life.sumsec.me](https://life.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [linux.sumsec.me](https://linux.sumsec.me/) | CNAME | CNAME: sumsec.me | 是 |
| [loader.sumsec.me](https://loader.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [love.sumsec.me](https://love.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [mac.sumsec.me](https://mac.sumsec.me/) | CNAME | CNAME: 85d9e87f-3dcd-4c1f-b6a3-84e72ebc896d.cfargotunn… | 是 |
| [mailchannels._domainkey.sumsec.me](https://mailchannels._domainkey.sumsec.me/) | TXT | TXT: v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBC… | 否 |
| [mvnc.sumsec.me](https://mvnc.sumsec.me/) | CNAME | CNAME: 85d9e87f-3dcd-4c1f-b6a3-84e72ebc896d.cfargotunn… | 是 |
| [nawvs.sumsec.me](https://nawvs.sumsec.me/) | CNAME | CNAME: c424a3e4-916b-4174-8d44-c9e59b54fbb5.cfargotunn… | 是 |
| [old.sumsec.me](https://old.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [proxy.sumsec.me](https://proxy.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [school.sumsec.me](https://school.sumsec.me/) | CNAME | CNAME: 413a8c38-4ac9-4828-97cd-828c83f75e69.cfargotunn… | 是 |
| [serverless-dns.sumsec.me](https://serverless-dns.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [shiro.sumsec.me](https://shiro.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [sl.sumsec.me](https://sl.sumsec.me/) | AAAA | AAAA: 100:: | 是 |
| [spat.sumsec.me](https://spat.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [sumsec.me](https://sumsec.me/) | A, AAAA, MX, TXT | A: 185.199.111.153；A: 185.199.110.153；A: 185.199.109.153；A: 185.199.108.153；AAAA: 2606:50c0:800… | 是 |
| [sumsec.sumsec.me](https://sumsec.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [svgedit.sumsec.me](https://svgedit.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [sy.sumsec.me](https://sy.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [tools.sumsec.me](https://tools.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [tv.sumsec.me](https://tv.sumsec.me/) | CNAME | CNAME: cname.vercel-dns.com | 是 |
| [ubuntu.sumsec.me](https://ubuntu.sumsec.me/) | CNAME | CNAME: c424a3e4-916b-4174-8d44-c9e59b54fbb5.cfargotunn… | 是 |
| [uvnc.sumsec.me](https://uvnc.sumsec.me/) | CNAME | CNAME: b5c0ffe9-340b-41ff-9de9-b391adb59334.cfargotunn… | 是 |
| [vnc.sumsec.me](https://vnc.sumsec.me/) | CNAME | CNAME: c424a3e4-916b-4174-8d44-c9e59b54fbb5.cfargotunn… | 是 |
| [vps.sumsec.me](https://vps.sumsec.me/) | A | A: 107.175.245.109 | 否 |
| [webcheck.sumsec.me](https://webcheck.sumsec.me/) | CNAME | CNAME: cute-hotteok-8af4f6.netlify.app | 是 |
| [www.sumsec.me](https://www.sumsec.me/) | CNAME | CNAME: summersec.github.io | 是 |
| [xget.sumsec.me](https://xget.sumsec.me/) | AAAA | AAAA: 100:: | 是 |

<!--CLOUDFLARE_DNS_SYNC_END-->

> **说明**：若你还有其它 DNS 记录未在表中列出，在 DNS 面板核对后按行追加即可。API / CDN / 代理类子域若无独立网页，可不配图或仅配管理后台截图。手工表以说明与截图为准；下方 Cloudflare 表以 DNS 事实为准。
