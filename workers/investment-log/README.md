# 投资操作日志 Worker

使用 Cloudflare Worker + D1 保存浏览器扩展捕获的投资操作、每日账户快照、持仓快照和历史资产趋势，并向博客页面提供实时只读数据。

## 接口

- `POST /api/operations`：写入操作，需要 `Authorization: Bearer <INGEST_TOKEN>`。
- `GET /api/operations?days=90&limit=1000`：博客公开读取的脱敏记录。
- `POST /api/snapshots`：批量写入账户与持仓快照，需要写入令牌。
- `GET /api/portfolio?days=365`：实时返回历史账户快照、最新持仓和近期操作。
- `GET /health`：健康检查。

服务端只接收操作时间、动作、证券代码/名称、方向、数量、价格、金额、备注和来源接口，不接收同花顺 Cookie、userid 或原始接口响应。

## 部署

```bash
wrangler d1 create sumsec-investment-log
# 将数据库 ID 写入 wrangler.toml
wrangler d1 migrations apply sumsec-investment-log --remote
wrangler secret put INGEST_TOKEN
wrangler deploy
```
