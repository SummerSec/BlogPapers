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
   wrangler kv namespace create page-stats-kv
   ```
3. 将输出的 `id` 填入 `wrangler.toml` 里 `[[kv_namespaces]]` 的 `id =`；**`binding = "capi"`** 勿改（与 Worker 里 `env.capi` 一致）。
4. 编辑 `wrangler.toml` 中 `[vars]`：
   - **`ALLOW_HOST_SUFFIX`**：默认 `sumsec.me`，会放行所有 `https://*.sumsec.me` 与 `https://sumsec.me`（避免漏配 `www` 等子域导致 CORS 403，页面上访问量变成 **—**）。
   - **`ALLOW_ORIGINS`**：需**完整写出**的 Origin（如本地 `http://127.0.0.1:4000`、`https://xxx.github.io` 预览站等）；后缀匹配不到时才靠这里。
5. 部署：
   ```bash
   wrangler deploy
   ```
6. （推荐）在 Cloudflare 控制台为该 Worker 绑定自定义域，例如 `stats.sumsec.me`，并确保 DNS 橙云代理开启。
7. 在博客仓库 `_config.yml` 设置：
   ```yaml
   stats_endpoint: "https://capi.sumsec.me"
   ```
   留空则继续使用 CountAPI。

## API

- `GET /hit?ns=sumsecme&key=site-total` → `{"value":123}`（与 `scifi.js` 中 ns/key 一致）
- `GET /` → 健康检查 JSON

## 页面上一直显示 **—**？

1. 浏览器 **F12 → 网络**，找 `capi.xxx/hit?...`：若为 **403**，多半是 **Origin 未放行**（例如用了 `www` 而只配了 apex）。改 `ALLOW_ORIGINS` / `ALLOW_HOST_SUFFIX` 后执行 `wrangler deploy`；若 Dashboard 里给 Worker 配了 **Variables**，会覆盖仓库里的 `wrangler.toml`，两边要一致。
2. 若 Worker 失败，前端会回退 **CountAPI**；广告拦截可能屏蔽 `api.countapi.xyz`，也会显示 **—**。
3. 修改 Worker 后务必 **`wrangler deploy`**，否则线上仍是旧逻辑。

## 安全说明

- 通过 **`ALLOW_HOST_SUFFIX` + `ALLOW_ORIGINS`** 限制可写计数的来源；勿随意把后缀设为 `.com` 这类过宽的值。
- 勿把 Worker URL 当作秘密；计数本身可伪造，仅作展示用途。
