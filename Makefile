SHELL       := /usr/bin/env bash
VERSION     ?= 1.3.1
PROJECT     := system-suite
SCRIPT      := system_suite.sh
INSTALL_DIR ?= $(HOME)/.local/bin
MAN_DIR     ?= $(HOME)/.local/share/man/man1
BASH_COMP   ?= $(HOME)/.local/share/bash-completion/completions
ZSH_COMP    ?= $(HOME)/.local/share/zsh/site-functions
DIST_DIR    := dist

# ─── Development ──────────────────────────────────────────────────────────────

.PHONY: build
build: ## Validate syntax and make script executable
	@bash -n $(SCRIPT)
	@chmod +x $(SCRIPT)
	@echo "Syntax OK: ./$(SCRIPT)"

.PHONY: run
run: ## Run system-suite locally (pass args with ARGS="...")
	@./$(SCRIPT) $(ARGS)

.PHONY: man
man: ## Preview or export man page
	@mkdir -p man
	@./$(SCRIPT) man man/
	@echo "Man pages ready in man/"

.PHONY: install
install: build man ## Install binary, man pages, and completions to $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)
	@cp -f $(SCRIPT) $(INSTALL_DIR)/$(PROJECT)
	@chmod 755 $(INSTALL_DIR)/$(PROJECT)
	@mkdir -p $(MAN_DIR)
	@cp -f man/$(PROJECT).1 $(MAN_DIR)/$(PROJECT).1 2>/dev/null || true
	@mkdir -p $(BASH_COMP) 2>/dev/null || true
	@cp -f completions/$(PROJECT).bash $(BASH_COMP)/$(PROJECT) 2>/dev/null || true
	@mkdir -p $(ZSH_COMP) 2>/dev/null || true
	@cp -f completions/$(PROJECT).zsh $(ZSH_COMP)/_$(PROJECT) 2>/dev/null || true
	@echo "Installed $(INSTALL_DIR)/$(PROJECT)"
	@echo "Installed man page to $(MAN_DIR)/$(PROJECT).1"

.PHONY: uninstall
uninstall: ## Remove installed binary, man pages, and completions
	@rm -f $(INSTALL_DIR)/$(PROJECT)
	@rm -f $(MAN_DIR)/$(PROJECT).1
	@rm -f $(BASH_COMP)/$(PROJECT)
	@rm -f $(ZSH_COMP)/_$(PROJECT)
	@echo "Removed $(PROJECT) from $(INSTALL_DIR) and man/completion dirs"

# ─── Quality & Testing ────────────────────────────────────────────────────────

.PHONY: test
test: ## Run smoke test suite
	@bash test/smoke.sh

.PHONY: test-ci
test-ci: ## Simulate bare CI environment
	@env -i HOME="$$HOME" PATH="/usr/bin:/bin:/usr/local/bin" bash test/smoke.sh

.PHONY: lint
lint: ## Run ShellCheck across all scripts
	@shellcheck $(SCRIPT) test/smoke.sh install.sh
	@echo "ShellCheck passed cleanly."

.PHONY: check
check: lint test ## Run lint + tests (CI-friendly)

.PHONY: clean
clean: ## Clean build and distribution artifacts
	@rm -rf $(DIST_DIR)
	@rm -f /tmp/system_suite_*.out /tmp/system_suite_*.err
	@echo "Cleaned build artifacts."

# ─── Packaging & Distribution ─────────────────────────────────────────────────

.PHONY: dist
dist: build man ## Create release tarball and SHA256 checksums in dist/
	@mkdir -p $(DIST_DIR)
	@tar -czf $(DIST_DIR)/$(PROJECT)-v$(VERSION).tar.gz \
		--exclude='.git*' \
		--exclude='dist' \
		--exclude='.system_suite*' \
		$(SCRIPT) install.sh man completions README.md LICENSE UPDATING.md
	@cd $(DIST_DIR) && shasum -a 256 $(PROJECT)-v$(VERSION).tar.gz > checksums.txt
	@echo "Built release archive in $(DIST_DIR)/:"
	@ls -lh $(DIST_DIR)

.PHONY: deb
deb: build man ## Build Debian .deb package (requires dpkg-deb)
	@which dpkg-deb >/dev/null 2>&1 || { echo "Error: dpkg-deb not found"; exit 1; }
	@mkdir -p $(DIST_DIR)
	@PKG_DIR="$(DIST_DIR)/$(PROJECT)_$(VERSION)_all"; \
	rm -rf "$$PKG_DIR" && \
	mkdir -p "$$PKG_DIR/DEBIAN" "$$PKG_DIR/usr/bin" "$$PKG_DIR/usr/share/man/man1" \
		"$$PKG_DIR/usr/share/doc/$(PROJECT)" \
		"$$PKG_DIR/usr/share/bash-completion/completions" \
		"$$PKG_DIR/usr/share/zsh/vendor-completions" && \
	install -m 0755 $(SCRIPT) "$$PKG_DIR/usr/bin/$(PROJECT)" && \
	install -m 0644 man/$(PROJECT).1 "$$PKG_DIR/usr/share/man/man1/$(PROJECT).1" && \
	install -m 0644 completions/$(PROJECT).bash "$$PKG_DIR/usr/share/bash-completion/completions/$(PROJECT)" && \
	install -m 0644 completions/$(PROJECT).zsh "$$PKG_DIR/usr/share/zsh/vendor-completions/_$(PROJECT)" && \
	install -m 0644 README.md LICENSE "$$PKG_DIR/usr/share/doc/$(PROJECT)/" && \
	printf "Package: %s\nVersion: %s\nSection: utils\nPriority: optional\nArchitecture: all\nMaintainer: Hamim Lohani <hamimlohani@gmail.com>\nDepends: bash (>= 4.0), curl\nHomepage: https://github.com/hamimLohani/system_suite\nDescription: Terminal-based system maintenance and monitoring toolkit\n A comprehensive system maintenance and monitoring toolkit for macOS, Linux,\n and Unix-like systems. Provides system monitoring, disk cleanup, package\n updates, network speed testing, file management, and more.\n" "$(PROJECT)" "$(VERSION)" > "$$PKG_DIR/DEBIAN/control" && \
	dpkg-deb --build "$$PKG_DIR" && \
	echo "Built Debian package in $(DIST_DIR)/" && \
	ls -lh $(DIST_DIR)/*.deb

.PHONY: tag
tag: ## Create and push a version tag. Usage: make tag VERSION=v1.3.0
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then \
		echo "Usage: make tag VERSION=v1.3.0"; exit 1; fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "Tagged and pushed $(VERSION)"

# ─── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help menu
	@printf "\n\033[1msystem-suite — available targets\033[0m\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

.DEFAULT_GOAL := help
