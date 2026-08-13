# Makefile for avc_guard.kpm
# Target: Linux 4.14+ arm64 (MT6893 / generic)

KP_DIR ?= ./KernelPatch

CC    := aarch64-linux-gnu-gcc
LD    := aarch64-linux-gnu-ld
STRIP := aarch64-linux-gnu-strip
READELF := aarch64-linux-gnu-readelf

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
          -mcmodel=large \
          -DKP_MODULE

TARGET := avc_guard.kpm
OBJ    := avc_guard.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) -r -nostdlib -o $@ $^
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
