API ?= 35

# Auto-detect NDK
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(firstword     $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*     $(subst \,/,$(ANDROID_HOME))/ndk/*     D:/AndroidSDK/ndk/*)))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  CLANG_BASE := aarch64-linux-android$(API)-clang
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG_BASE).cmd
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  PREBUILT := linux-x86_64
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
endif

SRCS := \
  src/main.c \
  src/util.c \
  src/fops.c

HDRS := $(wildcard src/*.h src/*/*.h)

CFLAGS_COMMON = -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare \
  -Wno-unused-function -Wno-trigraphs -Isrc
CFLAGS = $(CFLAGS_COMMON)
LDFLAGS := -fPIE -pie -pthread -flto

.PHONY: all product clean

all: ghostlock_ruby

ghostlock_ruby: $(SRCS) $(HDRS)
	@echo "Using NDK compiler: $(NDK_CC)"
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o ghostlock_ruby

product: ghostlock_ruby
	@echo "=== ghostlock_ruby binary ready: ./ghostlock_ruby ==="
	@echo "push it to /data/local/tmp and run it from adb shell"

clean:
	rm -f ghostlock_ruby
