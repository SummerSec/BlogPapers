# 投资操作日志 Worker

使用 Cloudflare Worker + D1 保存浏览器扩展捕获的分类账户、交易记录、每日账户快照、持仓快照和历史资产趋势，并向博客页面提供实时只读数据。

## 接口

- `POST /api/operations`：单条或批量写入真实交易流水，需要 `Authorization: Bearer <INGEST_TOKEN>`；仅接受 `get_money_history` 来源且包含成交字段的记录。
- `POST /api/login`：使用访问密码换取 12 小时有效的签名会话令牌。
- `GET /api/operations?days=90&limit=1000`：读取交易记录，需要登录接口签发的会话令牌。
- `POST /api/snapshots`：批量写入账户与持仓快照，需要写入令牌；允许上海时间 18:00 后暂存当天数据，但股票实时快照日期必须与采集日期一致。
- `GET /api/portfolio?days=365`：返回 T+1 历史账户快照、最新已结算持仓和近期操作，需要会话令牌。
- `GET /health`：健康检查。

服务端接收账户显示名称、脱敏后的账户键、账户与持仓指标及交易记录，不接收同花顺 Cookie、userid 或原始接口响应。投资读取接口受密码会话保护，健康检查保持公开。

## 部署

```bash
wrangler d1 create sumsec-investment-log
# 将数据库 ID 写入 wrangler.toml
wrangler d1 migrations apply sumsec-investment-log --remote
wrangler secret put INGEST_TOKEN
wrangler secret put READ_PASSWORD
wrangler secret put SESSION_SECRET
wrangler deploy
```

本地开发时，将 `.dev.vars.example` 复制为 `.dev.vars` 并填写实际值。`.dev.vars` 已被 Git 忽略，不要把访问密码或会话签名密钥提交到仓库。

## 同步到本地

在仓库根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File workers\investment-log\scripts\sync-local.ps1
```

脚本会完整导出远程 D1，并在 `workers/investment-log/local-data/` 生成：

- `sumsec-investment-log-YYYYMMDD-HHMMSS.sql`：每次同步的完整 SQL 备份。
- `latest.sql`：最近一次完整导出。
- `latest.sqlite`：可直接用于 Python、R、DataGrip 或 DB Browser for SQLite 的分析库。

本地数据目录已被 Git 忽略，不会随博客源码上传。需要自定义保存位置时可传入 `-OutputDirectory D:\investment-data`。
