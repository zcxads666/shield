.PHONY: build test run clean deploy install

build:
	go build -o bin/shield ./cmd/shield

test:
	go test -v ./...

run:
	go run ./cmd/shield -config configs/config.yaml

clean:
	rm -rf bin/

deploy: build
	@echo "=== Installing shield to /opt/shield ==="
	install -d /opt/shield/configs /opt/shield/logs /opt/shield/data
	install -m 755 bin/shield /opt/shield/shield
	@if [ -f configs/config.yaml ]; then install -m 644 configs/config.yaml /opt/shield/configs/config.yaml; fi
	@if [ -f deployments/systemd/shield.service ]; then install -m 644 deployments/systemd/shield.service /etc/systemd/system/shield.service; fi
	@echo "=== Reloading systemd and restarting service ==="
	systemctl daemon-reload || true
	systemctl enable shield || true
	systemctl restart shield || true
	@echo "=== Checking service status ==="
	systemctl status shield --no-pager || true

install:
	install -m 755 bin/shield /usr/local/bin/shield
