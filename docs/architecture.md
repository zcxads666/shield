# Shield WAF 架构设计

> 本文档由 Architect 补充完善。

## 项目概述

Shield 是一个轻量级 Web 应用防火墙（WAF），采用 Go 语言编写，遵循标准 Go 项目布局。

## 分层架构

- **Handler 层**：HTTP 入口，解析请求、调用 Service、格式化响应
- **Service 层**：业务编排，调用 Repository 和 Engine
- **Domain 层**：核心数据结构定义
- **Repository 层**：数据持久化/查询
- **Engine 层**：攻击检测、规则匹配、响应生成
- **App 层**：依赖注入、生命周期管理

## 数据流

```
[请求] -> Handler -> Service -> [Engine 检测] -> Repository
                          |
                    [响应/阻断]
```

## 设计原则

1. 依赖注入：通过构造函数注入，禁止全局变量
2. 接口隔离：每层通过接口交互
3. 领域模型纯净：不依赖框架/库
4. Error 传播：底层错误包装后向上传递
