# Crucible — run ./configure first
-include config.mk

.PHONY: all configure test clean engines release install deploy tls-deps acceptance accept-test

all: release engines

configure:
	@./configure

tls-deps:
	@test -f config.mk || (echo "Run ./configure first" && exit 1)
	@cd "$(ROOT)" && if echo "$(CARGO_FEATURES)" | grep -q tls_boring; then \
		CRUCIBLE_ROOT="$(ROOT)" sh "$(ROOT)/scripts/build_boringssl.sh"; \
	fi
	@cd "$(ROOT)" && if echo "$(CARGO_FEATURES)" | grep -q tls_tomcrypt; then \
		CRUCIBLE_ROOT="$(ROOT)" sh "$(ROOT)/scripts/build_libtomcrypt.sh"; \
	fi

engines:
	@test -f config.mk || (echo "Run ./configure first" && exit 1)
	@unset CARGO_TARGET_DIR; export CARGO_TARGET_DIR="$(ROOT)/target"; \
		GO_ENGINE_MODE="$(GO_ENGINE_MODE)" CC="$(CC)" \
		bash "$(ROOT)/scripts/build_app_engines.sh"

release: tls-deps
	@test -f config.mk || (echo "Run ./configure first" && exit 1)
	@cd "$(ROOT)" && unset CARGO_TARGET_DIR; export CARGO_TARGET_DIR="$(ROOT)/target"; \
		export PATH="$(PATH)"; \
		export BORING_BSSL_PATH="$(ROOT)/target/tls-libs/boringssl/lib"; \
		export BORING_BSSL_INCLUDE_PATH="$(ROOT)/target/tls-libs/boringssl/include"; \
		if [ -d /usr/local/llvm19/lib ]; then export LIBCLANG_PATH=/usr/local/llvm19/lib; \
		elif [ -d /usr/local/llvm20/lib ]; then export LIBCLANG_PATH=/usr/local/llvm20/lib; \
		elif [ -d /usr/local/llvm21/lib ]; then export LIBCLANG_PATH=/usr/local/llvm21/lib; fi; \
		cargo build --release --features "$(CARGO_FEATURES)"

test: tls-deps
	@test -f config.mk || (echo "Run ./configure first" && exit 1)
	@unset CARGO_TARGET_DIR; export CARGO_TARGET_DIR="$(ROOT)/target"; \
		export BORING_BSSL_PATH="$(ROOT)/target/tls-libs/boringssl/lib"; \
		export BORING_BSSL_INCLUDE_PATH="$(ROOT)/target/tls-libs/boringssl/include"; \
		if [ -d /usr/local/llvm19/lib ]; then export LIBCLANG_PATH=/usr/local/llvm19/lib; \
		elif [ -d /usr/local/llvm20/lib ]; then export LIBCLANG_PATH=/usr/local/llvm20/lib; \
		elif [ -d /usr/local/llvm21/lib ]; then export LIBCLANG_PATH=/usr/local/llvm21/lib; fi; \
		cargo test --bin webserver --features "$(CARGO_FEATURES)"

clean:
	rm -rf "$(ROOT)/target" "$(ROOT)/build/crucible-build.toml"
	@$(MAKE) -s -C "$(ROOT)" -f /dev/null config.mk 2>/dev/null || rm -f config.mk

install:
	@test -f "$(ROOT)/target/release/webserver" || (echo "Build first: make all" && exit 1)
	install -d "$(PREFIX)/bin"
	install -m 755 "$(ROOT)/target/release/webserver" "$(PREFIX)/bin/webserver"

restart:
	@bash "$(ROOT)/scripts/start_server.sh"

acceptance:
	@bash "$(ROOT)/scripts/acceptance.sh"

accept-test:
	@bash "$(ROOT)/scripts/seed_and_accept.sh"

deploy:
	@python3 "$(ROOT)/sync_remote.py"
