REPO_OWNER=optionfactory
REPO_NAME=docker-intrude


build:
	cargo build

build-release:
	@cargo build --release --target x86_64-unknown-linux-musl

run:
	cargo run

install: build-release
	@sudo cp target/x86_64-unknown-linux-musl/release/docker-intrude /usr/local/bin/docker-intrude
	@sudo chown root:docker /usr/local/bin/docker-intrude
	@sudo chmod 750 /usr/local/bin/docker-intrude	
	@sudo setcap cap_sys_admin,cap_sys_ptrace,cap_setpcap+ep /usr/local/bin/docker-intrude

clean:
	-@rm -rf target

check-deps:
	#cargo install cargo-edit
	@echo "checking for upgrades..."
	@echo ""
	@cargo upgrade --dry-run
	@echo ""
	@echo "checking for updates..."
	@echo ""
	@cargo update --dry-run


publish-github: build-release
	$(eval VERSION=v$(shell cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version'))
	@cp target/x86_64-unknown-linux-musl/release/$(REPO_NAME) target/$(REPO_NAME)-linux-amd64-musl
	@cd target && sha256sum $(REPO_NAME)-linux-amd64-musl > SHA256SUMS
	@gh release create "$(VERSION)" \
		"target/$(REPO_NAME)-linux-amd64-musl" \
		"target/SHA256SUMS" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "$(VERSION)" \
		--target "master" \
		--notes ""
	-@rm target/$(REPO_NAME)-linux-amd64-musl target/SHA256SUMS
