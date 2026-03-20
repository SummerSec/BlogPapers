# 浏览量统计 Worker（Cloudflare）

比第三方 CountAPI 更稳：走你自己的 Worker + KV，不易被广告插件误杀（域名可挂在同站子域，如 `stats.sumsec.me`）。

## 免费额度（概览）

- Workers：每日请求量有免费档（见 [Cloudflare 定价](https://developers.cloudflare.com/workers/platform/pricing/)）。
- KV：读/写有免费档；计数为「读改写」非强一致，极高并发时可能少计几次，博客流量足够用。

## 部署步骤

1. 安装 [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) 并登录：`wrangler login`
2. 创建 KV 命名空间：
   ```bash
   cd workers/page-stats
   wrangler kv namespace create STATS
   ```
3. 将输出的 `id` 填入 `wrangler.toml` 里 `[[kv_namespaces]]` 的 `id =`
4. 编辑 `wrangler.toml` 中 `[vars] ALLOW_ORIGINS`，加入你的站点源（含 `https://xxx.github.io` 等 GitHub Pages 预览域如需）
5. 部署：
   ```bash
   wrangler deploy
   ```
6. （推荐）在 Cloudflare 控制台为该 Worker 绑定自定义域，例如 `stats.sumsec.me`，并确保 DNS 橙云代理开启。
7. 在博客仓库 `_config.yml` 设置：
   ```yaml
   stats_endpoint: "https://stats.sumsec.me"
   ```
   留空则继续使用 CountAPI。

## API

- `GET /hit?ns=sumsecme&key=site-total` → `{"value":123}`（与 `scifi.js` 中 ns/key 一致）
- `GET /` → 健康检查 JSON

## 安全说明

- 通过 `ALLOW_ORIGINS` 限制可写计数的来源，避免被任意网站盗刷请求。
- 勿把 Worker URL 当作秘密；计数本身可伪造，仅作展示用途。
