# Makefile for avc_guard.kpm
# Based on dsp_bypass's proven build config

KP_DIR ?= ./KernelPatch
NDK_HOME ?= $(ANDROID_NDK_HOME)

CC := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
CC  := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
STRIP := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip

INC := -I$(KP_DIR)/kernel/include \
       -I$(KP_DIR)/kernel/patch/include \
       -I$(KP_DIR)/kernel/patch/include/uapi \
       -I$(KP_DIR)/kernel/linux/include \
       -I$(KP_DIR)/kernel/linux/arch/arm64/include \
       -I$(KP_DIR)/kernel/linux/arch/arm64/include/generated/uapi \
       -I$(KP_DIR)/kernel/linux/arch/arm64/include/uapi \
       -I$(KP_DIR)/kernel/linux/include/uapi \
       -I$(KP_DIR)/kernel/linux/tools/arch/arm64/include

CFLAGS := -O2 -Wall -nostdinc -ffreestanding -fno-stack-protector \
          -fno-pic -fno-pie -fno-common -mgeneral-regs-only \
          -DKP_MODULE

TARGET := avc_guard.kpm
OBJ := avc_guard.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -r -nostdlib -no-pie -o $@ $^
		$(STRIP) --strip-debug \
	  --remove-section=.comment \
	  --remove-section=.note.GNU-stack \
	  $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	rm -f *.o *.kpm

.PHONY: all clean
