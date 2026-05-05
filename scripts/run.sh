#!/bin/bash
# Shield WAF 快速启动脚本（前台运行，用于测试）

cd "$(dirname "$0")"

if [ ! -f "bin/shield" ]; then
    echo "错误: 未找到 bin/shield"
    exit 1
fi

if [ ! -f "config.yaml" ]; then
    echo "错误: 未找到 config.yaml"
    exit 1
fi

mkdir -p data logs

echo "启动 Shield WAF..."
echo "配置文件: $(pwd)/config.yaml"
echo "代理目标: $(grep "target_url:" config.yaml | sed 's/.*target_url: //')"
echo "监听地址: $(grep "bind_addr:" config.yaml | sed 's/.*bind_addr: //')"
echo "Admin API: $(grep "admin_bind_addr:" config.yaml | sed 's/.*admin_bind_addr: //')"
echo ""
echo "按 Ctrl+C 停止"
echo ""

exec ./bin/shield -config config.yaml
