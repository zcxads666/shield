# Shield WAF 部署指南

## Docker 部署

```bash
cd deployments/docker-compose
docker-compose up -d
```

## systemd 部署

```bash
sudo cp deployments/systemd/shield.service /etc/systemd/system/
sudo useradd -r -s /bin/false shield
sudo mkdir -p /opt/shield/{configs,logs,data}
sudo cp configs/config.yaml /opt/shield/configs/
sudo cp bin/shield /opt/shield/
sudo systemctl daemon-reload
sudo systemctl enable --now shield
```

## 目录说明

- `deployments/docker/`：Docker 构建文件
- `deployments/docker-compose/`：Docker Compose 编排
- `deployments/kubernetes/`：K8s 部署清单（预留）
- `deployments/systemd/`：systemd 服务配置
- `configs/`：配置文件模板
