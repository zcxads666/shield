# Shield WAF API 文档

> 本文档后续补充。

## 代理服务

- `GET/POST/PUT/DELETE /*` -- 代理到后端服务

## 管理面板

- `GET /health` -- 健康检查
- `GET /stats` -- 统计信息
- `GET /blacklist` -- 黑名单列表

## 响应头

- `X-Block-Reason` -- 当请求被拦截时返回的阻断原因
