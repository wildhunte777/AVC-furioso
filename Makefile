# Makefile for avc_guard.kpm
# Target: Linux 4.14+ arm64 (MT6893 / generic)

KP_DIR ?= ./KernelPatch

# NDK path: use ANDROID_NDK_HOME if NDK_HOME not set
NDK_HOME ?= $(ANDROID_NDK_HOME)

CC  := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
STRIP := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
READELF := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf

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
OBJ    := avc_guard.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -r -nostdlib -o $@ $^
	$(STRIP) --strip-debug \
	  --remove-section=.comment \
	  --remove-section=.note.GNU-stack \
	  $@
	@echo "=== Built: $@ ==="
	@echo "=== Section headers ==="
	@$(READELF) -S $@ | grep -E '\.kpm|\.symtab|\.strtab'
	@echo "=== Relocations (must NOT contain type 283) ==="
	@$(READELF) -r $@ | grep -c '283' && echo "WARNING: type 283 found" || echo "OK: no type 283"
	@echo "=== File info ==="
	@file $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
