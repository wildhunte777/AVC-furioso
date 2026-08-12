# Makefile for avc_guard.kpm
#
# Build environment:
#   1. Android NDK (r25c or newer)
#   2. KernelPatch source tree (SukiSU fork recommended)
#
# Usage:
#   make KP_DIR=/path/to/KernelPatch NDK_PATH=/path/to/ndk
#

KP_DIR   ?= ../KernelPatch
NDK_PATH ?= $(ANDROID_NDK_HOME)

CC = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
LD = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld

INCLUDES = \
    -I$(KP_DIR)/kernel/include \
    -I$(KP_DIR)/kernel/linux/include \
    -I$(KP_DIR)/kernel/linux/arch/arm64/include \
    -I$(KP_DIR)/kernel/linux/arch/arm64/include/generated/uapi \
    -I$(KP_DIR)/kernel/linux/include/uapi \
    -I$(KP_DIR)/kernel/patch/include \
    -I$(KP_DIR)/kernel/patch/linux/include

CFLAGS  = -O2 -g -fPIC -fno-PIE -fno-stack-protector -nostdlib \
          $(INCLUDES) -DKP_MODULE -D__KERNEL__ \
          -Wno-error=date-time

LDFLAGS = -r -nostdlib -no-pie

TARGET  = avc_guard.kpm
OBJS    = avc_guard.o

.PHONY: all clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@
	@echo "=== Built: $@ ==="

clean:
	rm -f $(OBJS) $(TARGET)
