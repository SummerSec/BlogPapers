# 投资操作日志 Worker

使用 Cloudflare Worker + D1 保存浏览器扩展捕获的分类账户、交易记录、每日账户快照、持仓快照和历史资产趋势，并向博客页面提供实时只读数据。

## 接口

- `POST /api/operations`：单条或批量写入交易记录，需要 `Authorization: Bearer <INGEST_TOKEN>`。
- `GET /api/operations?days=90&limit=1000`：博客公开读取的脱敏记录。
- `POST /api/snapshots`：批量写入账户与持仓快照，需要写入令牌；仅接受上海日期当天之前的 T+1 已结算快照。
- `GET /api/portfolio?days=365`：返回 T+1 历史账户快照、最新已结算持仓和近期操作。
- `GET /health`：健康检查。

服务端接收账户显示名称、脱敏后的账户键、账户与持仓指标及交易记录，不接收同花顺 Cookie、userid 或原始接口响应。`GET` 接口是公开的，因此其中的账户名称、持仓与交易数据会对博客访问者可见。

## 部署

```bash
wrangler d1 create sumsec-investment-log
# 将数据库 ID 写入 wrangler.toml
wrangler d1 migrations apply sumsec-investment-log --remote
wrangler secret put INGEST_TOKEN
wrangler deploy
```
