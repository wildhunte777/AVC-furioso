# Makefile for avc_guard.kpm
# Target: Linux 3.18+ arm64 (validated on 4.14 MT6893)

ifeq ($(OS), Windows_NT)
  PLATFORM := windows-x86_64
else
  PLATFORM := linux-x86_64
endif

ifndef NDK_PATH
  NDK_PATH := $(ANDROID_NDK_HOME)
endif
ifndef KP_DIR
  KP_DIR := ../SukiSU_KernelPatch_patch
endif

TARGET_COMPILE := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
CC  := $(TARGET_COMPILE)aarch64-linux-android31-clang
LD  := $(TARGET_COMPILE)ld.lld
STRIP := $(TARGET_COMPILE)llvm-strip
READELF := $(TARGET_COMPILE)llvm-readelf

INCLUDE_DIRS := \
  $(KP_DIR)/kernel/include \
  $(KP_DIR)/kernel/patch/include \
  $(KP_DIR)/kernel/patch/include/uapi \
  $(KP_DIR)/kernel/linux/include \
  $(KP_DIR)/kernel/linux/arch/arm64/include \
  $(KP_DIR)/kernel/linux/arch/arm64/include/generated/uapi \
  $(KP_DIR)/kernel/linux/arch/arm64/include/uapi \
  $(KP_DIR)/kernel/linux/include/uapi \
  $(KP_DIR)/kernel/linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

CFLAGS := -Wall -O2 -g \
  -fno-PIC -fno-pie \
  -fno-asynchronous-unwind-tables \
  -fno-stack-protector \
  -fno-unwind-tables \
  -fno-semantic-interposition \
  -fno-common \
  -fvisibility=hidden \
  -U_FORTIFY_SOURCE \
  $(INCLUDE_FLAGS) \
  -DKP_MODULE

LDFLAGS := -r -nostdlib -no-pie

TARGET := avc_guard.kpm
OBJS   := avc_guard.o

.PHONY: all clean check

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@
	$(STRIP) --strip-debug \
	  --remove-section=.comment \
	  --remove-section=.note.GNU-stack \
	  $@
	@echo "=== Built: $@ ==="
	@echo "=== Section headers (check for SHF_ALLOC on .kpm.*) ==="
	@$(READELF) -S $@ | grep -E '\.kpm|\.symtab|\.strtab'
	@echo "=== File info ==="
	@file $@

clean:
	rm -f $(OBJS) $(TARGET)
