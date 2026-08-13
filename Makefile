# Makefile for avc_guard.kpm
# Target: Linux 3.18+ arm64 (validated on 4.14 MT6893)
# Based on KernelPatch KPM spec (SukiSU-Ultra fork)

ifeq ($(OS), Windows_NT)
  PLATFORM := windows-x86_64
else
  PLATFORM := linux-x86_64
endif

# --- Configurable paths ---
ifndef NDK_PATH
  NDK_PATH := $(ANDROID_NDK_HOME)
endif
ifndef KP_DIR
  KP_DIR := ../SukiSU_KernelPatch_patch
endif

# --- Toolchain ---
TARGET_COMPILE := $(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
CC  := $(TARGET_COMPILE)aarch64-linux-android31-clang
LD  := $(TARGET_COMPILE)ld.lld
STRIP := $(TARGET_COMPILE)llvm-strip

# --- Includes (verified against SukiSU KernelPatch repo structure) ---
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

# --- Flags ---
# -fno-PIC: KPM is a relocatable object, not a position-independent executable
# -fvisibility=hidden: minimize symbol table, only exported callbacks visible
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
LDS    := avc_guard.lds

.PHONY: all clean check

all: $(TARGET)

%.o: %.c $(LDS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -T $(LDS) $^ -o $@
	$(STRIP) -g --strip-unneeded --strip-debug \
	  --remove-section=.comment \
	  --remove-section=.note.GNU-stack \
	  $@
	@echo "=== Built: $@ ==="
	@echo "=== Sections ==="
	@$(TARGET_COMPILE)llvm-readelf -S $@ | grep -E '\.kpm|\.text|\.rodata|\.data'
	@echo "=== File info ==="
	@file $@

clean:
	rm -f $(OBJS) $(TARGET)
