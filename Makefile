.PHONY: build test run clean deploy install bump-version

VERSION_FILE = pkg/version/version.go

build:
	go build -o bin/shield ./cmd/shield

test:
	go test -v ./...

run:
	go run ./cmd/shield -c configs/config.yaml start

clean:
	rm -rf bin/

bump-version:
	@CURRENT=$$(grep -oP 'Version = "\K[^"]+' $(VERSION_FILE)); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	sed -i "s/Version = \"$$CURRENT\"/Version = \"$$NEW_VERSION\"/" $(VERSION_FILE); \
	echo "Version bumped: $$CURRENT -> $$NEW_VERSION"

deploy: bump-version build
	@VERSION=$$(grep -oP 'Version = "\K[^"]+' $(VERSION_FILE)); \
	echo "=== Deploying shield $$VERSION to /opt/shield ==="; \
	install -d /opt/shield/configs /opt/shield/logs /opt/shield/data; \
	install -m 755 bin/shield /opt/shield/shield; \
	if [ -f configs/config.yaml ]; then install -m 644 configs/config.yaml /opt/shield/configs/config.yaml; fi; \
	if [ -f deployments/systemd/shield.service ]; then install -m 644 deployments/systemd/shield.service /etc/systemd/system/shield.service; fi; \
	echo "=== Reloading systemd and restarting service ==="; \
	systemctl daemon-reload || true; \
	systemctl enable shield || true; \
	systemctl restart shield || true; \
	echo "=== Checking service status ==="; \
	systemctl status shield --no-pager || true; \
	echo "=== Tagging version $$VERSION ==="; \
	git add $(VERSION_FILE) bin/shield; \
	git commit -m "deploy: bump to $$VERSION" || true; \
	git tag -a "v$$VERSION" -m "Deploy $$VERSION" || true

install:
	install -m 755 bin/shield /usr/local/bin/shield
