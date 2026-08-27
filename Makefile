REPO_OWNER=optionfactory
REPO_NAME=docker-heist
TARGET=x86_64-unknown-linux-musl
TOOLS=docker-intrude docker-bluff
BINDIR=/usr/local/bin
RELDIR=target/$(TARGET)/release
VERSION=v$(shell grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

build:
	cargo build

build-release:
	@cargo build --release --target $(TARGET)

test:
	cargo test

clean:
	-@rm -rf target

check-deps:
	@echo "checking for upgrades..." && cargo upgrade --dry-run
	@echo "" && echo "checking for updates..." && cargo update --dry-run

# Each tool runs as the invoking user with only the file capabilities it needs
# (never setuid-root), executable by the docker group only. See each crate's
# README for why each capability is required.
install: install-docker-intrude install-docker-bluff

install-docker-intrude: build-release
	@sudo cp $(RELDIR)/docker-intrude $(BINDIR)/docker-intrude
	@sudo chown root:docker $(BINDIR)/docker-intrude
	@sudo chmod 750 $(BINDIR)/docker-intrude
	@sudo setcap cap_sys_admin,cap_sys_ptrace,cap_setpcap+ep $(BINDIR)/docker-intrude
	@echo "installed $(BINDIR)/docker-intrude"

install-docker-bluff: build-release
	@sudo cp $(RELDIR)/docker-bluff $(BINDIR)/docker-bluff
	@sudo chown root:docker $(BINDIR)/docker-bluff
	@sudo chmod 750 $(BINDIR)/docker-bluff
	@sudo setcap cap_sys_admin,cap_setuid,cap_setgid,cap_setfcap,cap_sys_ptrace+ep $(BINDIR)/docker-bluff
	@# docker-bluff needs /run/docker-bluff, which a capability-only (non-root)
	@# process can't create in root-owned /run; a tmpfiles.d entry recreates it each boot.
	@printf 'd /run/docker-bluff 0770 root docker -\n' | sudo tee /usr/lib/tmpfiles.d/docker-bluff.conf >/dev/null
	@sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/docker-bluff.conf 2>/dev/null \
		|| sudo install -d -m 0770 -o root -g docker /run/docker-bluff
	@echo "installed $(BINDIR)/docker-bluff"


publish-github: build-release
	@rm -f target/SHA256SUMS
	@for t in $(TOOLS); do cp $(RELDIR)/$$t target/$$t-linux-amd64-musl; done
	@cd target && sha256sum $(addsuffix -linux-amd64-musl,$(TOOLS)) > SHA256SUMS
	@gh release create "$(VERSION)" \
		$(addprefix target/,$(addsuffix -linux-amd64-musl,$(TOOLS))) \
		"target/SHA256SUMS" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "$(VERSION)" \
		--target "master" \
		--notes ""
	-@rm -f $(addprefix target/,$(addsuffix -linux-amd64-musl,$(TOOLS))) target/SHA256SUMS

.PHONY: build build-release test clean check-deps install install-docker-intrude install-docker-bluff publish-github
