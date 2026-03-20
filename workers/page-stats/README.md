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
- `GET /hit?ns=…&key=…&callback=fn` → `application/javascript`，正文 `fn({"value":123});`，供前端 **JSONP** 在 CORS 异常时仍能拉到计数（`callback` 须为合法 JS 标识符）
- `GET /` → 健康检查 JSON

修改 Worker 后请执行 `wrangler deploy`。

博客端对 Worker **只使用 JSONP（`<script src>`）**，不依赖 `fetch` CORS。`/hit` **不会因 Origin/Referer 返回 403**（与带 `callback` 时一致）；`ALLOW_ORIGINS` / `ALLOW_HOST_SUFFIX` 仅影响 **JSON 响应上的 CORS 头**（浏览器 `fetch` 读 body 时用），控制台误配不会再把整次计数请求挡掉。

### 本机验证（Windows）

- PowerShell 里 **`curl` 是 `Invoke-WebRequest` 别名**，请用 **`curl.exe`**，例如：  
  `curl.exe -sS -i "https://capi.sumsec.me/hit?ns=sumsecme&key=site-total&callback=cb"`  
  期望首行 `HTTP/1.1 200`，正文 `cb({"value":…});`。
- 若出现 **`schannel: failed to receive handshake`**，可试：`curl.exe --ssl-no-revoke` 或换终端/WSL；与 Worker 逻辑无关。
- 页面是否走 Worker：打开首页源代码，应存在 `<meta name="stats-endpoint" content="https://capi.sumsec.me">`；若无，说明站点尚未用带 `stats_endpoint` 的配置构建发布。

## 页面上一直显示 **—**？

1. 浏览器 **F12 → 网络**，找 `capi.xxx/hit?...&callback=...`：应为 **200**、`content-type: application/javascript`。若 **脚本红字失败**，看是否被扩展拦截、或 **CSP**（Cloudflare / Pages）未允许该子域脚本。
2. 若 Worker 失败，前端会回退 **CountAPI**；广告拦截可能屏蔽 `api.countapi.xyz`，也会显示 **—**。
3. 修改 Worker 后务必 **`wrangler deploy`**，否则线上仍是旧逻辑。

## 安全说明

- **`ALLOW_HOST_SUFFIX` + `ALLOW_ORIGINS`** 只影响返回 JSON 时的 **CORS**，不当作「防刷票」；任何人可用 curl/JSONP 递增计数，仅作展示用途。
- 勿把 Worker URL 当作秘密。
