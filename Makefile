SHELL      := bash
.SHELLFLAGS := -eo pipefail -c

# --- Pinned toolchain --------------------------------------------------------

TOOLCHAIN_VERSION := 2025.08-1
TOOLCHAIN_TARBALL := x86-64--musl--stable-$(TOOLCHAIN_VERSION).tar.xz
TOOLCHAIN_URL     := https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64/tarballs/$(TOOLCHAIN_TARBALL)
# taken from https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64/tarballs/x86-64--musl--stable-2025.08-1.sha256
TOOLCHAIN_SHA256  := 09fca3aa89540f1b01b5f4210d488cbeb00f522044c53e9989b1dd8a38076912

TOOLCHAIN_DIR    := toolchain
TOOLCHAIN_STAMP  := $(TOOLCHAIN_DIR)/.installed
TOOLCHAIN_PREFIX := $(CURDIR)/$(TOOLCHAIN_DIR)/bin/x86_64-buildroot-linux-musl-
CC               := $(TOOLCHAIN_PREFIX)gcc

# --- Repository layout -------------------------------------------------------

LINUX_SRC    := linux
KERNEL_BUILD := .kernel-build
VMLINUZ      := $(KERNEL_BUILD)/arch/x86/boot/bzImage

GUEST_INIT := guest/init

VMM    := target/release/deterministic-vmm
MKCPIO := target/release/mkcpio

# --- Reproducibility knobs ---------------------------------------------------
#
# Exported into every recipe so any sub-make / sub-process sees them.

export SOURCE_DATE_EPOCH    := 0
export KBUILD_BUILD_TIMESTAMP := @0
export KBUILD_BUILD_USER    := repro
export KBUILD_BUILD_HOST    := repro
export KBUILD_BUILD_VERSION := 0
export LC_ALL := C
export TZ     := UTC

.PHONY: all build clean run verify check-paranoid set-paranoid kernel vmm rootfs toolchain

all: verify

build: guest/rootfs.cpio $(VMM) $(VMLINUZ)

# --- Toolchain download + verify ---------------------------------------------

toolchain: $(TOOLCHAIN_STAMP)

$(TOOLCHAIN_STAMP):
	@mkdir -p $(TOOLCHAIN_DIR)
	@if [ ! -f $(TOOLCHAIN_DIR)/$(TOOLCHAIN_TARBALL) ]; then \
		echo "Downloading $(TOOLCHAIN_TARBALL)..."; \
		curl -fL --output $(TOOLCHAIN_DIR)/$(TOOLCHAIN_TARBALL) $(TOOLCHAIN_URL); \
	fi
	@actual=$$(sha256sum $(TOOLCHAIN_DIR)/$(TOOLCHAIN_TARBALL) | awk '{print $$1}'); \
	if [ "$$actual" != "$(TOOLCHAIN_SHA256)" ]; then \
		echo ""; \
		echo "ERROR: toolchain sha256 mismatch"; \
		echo "  expected: $(TOOLCHAIN_SHA256)"; \
		echo "  actual:   $$actual"; \
		echo ""; \
		echo "If you trust this download, update TOOLCHAIN_SHA256 in the Makefile to:"; \
		echo "  $$actual"; \
		exit 1; \
	fi
	@echo "sha256 OK, extracting..."
	@tar xf $(TOOLCHAIN_DIR)/$(TOOLCHAIN_TARBALL) -C $(TOOLCHAIN_DIR) --strip-components=1
	@touch $@
	@echo "Toolchain installed at $(TOOLCHAIN_DIR)/"

# --- Prerequisites -----------------------------------------------------------

check-paranoid:
	@val=$$(cat /proc/sys/kernel/perf_event_paranoid); \
	if [ "$$val" -gt 1 ]; then \
		echo "ERROR: perf_event_paranoid = $$val (must be <= 1)"; \
		echo "The VMM uses perf hardware counters to count guest instructions."; \
		echo "Run 'make set-paranoid' to lower it, or set it yourself:"; \
		echo "  sudo sysctl -w kernel.perf_event_paranoid=1"; \
		exit 1; \
	else \
		echo "OK: perf_event_paranoid = $$val"; \
	fi

set-paranoid:
	@echo "This will run: sudo sysctl -w kernel.perf_event_paranoid=1"
	@echo -n "Proceed? [y/N] " && read ans && [ "$$ans" = "y" ] || { echo "Aborted."; exit 1; }
	sudo sysctl -w kernel.perf_event_paranoid=1

# --- Guest kernel (built from the linux/ submodule with pinned toolchain) ----

kernel: $(VMLINUZ)

$(VMLINUZ): guest/kernel.config $(LINUX_SRC)/Makefile $(TOOLCHAIN_STAMP)
	mkdir -p $(KERNEL_BUILD)
	$(MAKE) -C $(LINUX_SRC) O=$(CURDIR)/$(KERNEL_BUILD) \
		ARCH=x86_64 CROSS_COMPILE=$(TOOLCHAIN_PREFIX) \
		HOSTCC=$(CC) HOSTCFLAGS=-static KBUILD_HOSTLDFLAGS=-static \
		tinyconfig </dev/null
	cd $(KERNEL_BUILD) && $(CURDIR)/$(LINUX_SRC)/scripts/kconfig/merge_config.sh \
		-O $(CURDIR)/$(KERNEL_BUILD) \
		$(CURDIR)/$(KERNEL_BUILD)/.config \
		$(CURDIR)/guest/kernel.config </dev/null
	$(MAKE) -C $(LINUX_SRC) O=$(CURDIR)/$(KERNEL_BUILD) \
		ARCH=x86_64 CROSS_COMPILE=$(TOOLCHAIN_PREFIX) \
		HOSTCC=$(CC) HOSTCFLAGS=-static KBUILD_HOSTLDFLAGS=-static \
		LOCALVERSION= \
		-j$$(nproc) bzImage </dev/null

# --- Guest /init (static, built with pinned toolchain) -----------------------

$(GUEST_INIT): guest/init.c $(TOOLCHAIN_STAMP)
	$(CC) -O2 -static \
		-ffile-prefix-map=$(CURDIR)=. \
		-fdebug-prefix-map=$(CURDIR)=. \
		-Wl,--build-id=none \
		-o $@ $<

# --- Guest rootfs cpio -------------------------------------------------------

rootfs: guest/rootfs.cpio

$(MKCPIO): tools/mkcpio/src/main.rs tools/mkcpio/Cargo.toml
	cargo build --release -p mkcpio

guest/rootfs.cpio: $(GUEST_INIT) $(MKCPIO)
	$(MKCPIO) $(GUEST_INIT) $@

# --- VMM binary --------------------------------------------------------------

vmm: $(VMM)

$(VMM): $(wildcard src/*.rs) Cargo.toml
	cargo build --release

# --- Run ---------------------------------------------------------------------

run: check-paranoid guest/rootfs.cpio $(VMM) $(VMLINUZ)
	$(VMM) $(VMLINUZ) cpu.toml guest/rootfs.cpio

run-native: $(GUEST_INIT)
	$(GUEST_INIT)

# --- Determinism check -------------------------------------------------------
#
# Run the VMM twice and diff the output. Identical output across runs is the
# headline guarantee of this project.

verify: check-paranoid guest/rootfs.cpio $(VMM) $(VMLINUZ)
	@tmp=$$(mktemp -d) && trap 'rm -rf $$tmp' EXIT && \
		echo "run 1..." && VMM_QUIET=1 $(VMM) $(VMLINUZ) cpu.toml guest/rootfs.cpio 2>&1 | tee $$tmp/run1 && \
		echo "run 2..." && VMM_QUIET=1 $(VMM) $(VMLINUZ) cpu.toml guest/rootfs.cpio 2>&1 | tee $$tmp/run2 && \
		if diff -q $$tmp/run1 $$tmp/run2 >/dev/null; then \
			echo "OK: $$(wc -l < $$tmp/run1) lines, byte-identical across runs"; \
		else \
			echo "FAIL: runs diverged"; diff -u $$tmp/run1 $$tmp/run2; exit 1; \
		fi

# --- Clean -------------------------------------------------------------------

clean:
	rm -rf guest/init guest/rootfs.cpio $(KERNEL_BUILD)
	cargo clean

# `make distclean` also removes the downloaded toolchain.
distclean: clean
	rm -rf $(TOOLCHAIN_DIR)
