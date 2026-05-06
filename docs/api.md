# Shield WAF 文档

> 本文档后续补充。

## 代理服务

- `GET/POST/PUT/DELETE /*` -- 代理到后端服务

## CLI 命令

通过 `shield --config <path> <command>` 管理：

- `shield start` -- 启动服务（自动校验配置）
- `shield status` -- 查看运行状态
- `shield stats` -- 查看实时指标
- `shield logs --lines 50` -- 查看日志
- `shield blacklist list|add|remove` -- 黑名单管理
- `shield mapping list|add|remove|update` -- 端口映射管理

## 响应头

- `X-Block-Reason` -- 当请求被拦截时返回的阻断原因
