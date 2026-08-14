# Makefile for avc_guard.kpm
# Target: Linux 4.14+ arm64 (SukiSU / KernelPatch)

ifndef TARGET_COMPILE
  $(error TARGET_COMPILE is not set. Use: make TARGET_COMPILE=aarch64-none-elf-)
endif

ifndef KP_DIR
  KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
OBJDUMP = $(TARGET_COMPILE)objdump
READELF = $(TARGET_COMPILE)readelf
NM = $(TARGET_COMPILE)nm
SIZE = $(TARGET_COMPILE)size

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS := -O2 -Wall -nostdinc -ffreestanding -fno-stack-protector \
          -fno-pic -fno-pie -fno-common -mgeneral-regs-only \
          -mcmodel=large -fno-jump-tables \
          -g \
          -DKP_MODULE

# 关键：使用链接器脚本合并所有段
LDFLAGS := -r -nostdlib -T avc_guard.lds

TARGET := avc_guard.kpm
OBJ := avc_guard.o

.PHONY: all clean check diagnose

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "=== Built: $@ ==="
	@echo "=== Section layout ==="
	$(READELF) -S $@ | grep -E ' \.text | \.rodata | \.data | \.bss | \.kpm'

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

check: $(TARGET)
	@echo "=== ADRP instructions in object file ==="
	$(OBJDUMP) -d $(OBJ) | grep -c adrp || echo "0"
	@echo "=== ADRP relocations ==="
	$(READELF) -r $(TARGET) | grep -cE 'ADR_PREL_PG_HI21|283' || echo "0"
	@echo "=== All relocation types ==="
	$(READELF) -r $(TARGET) | awk '{print $$3}' | sort | uniq -c | sort -rn | head -n 20

diagnose: $(TARGET)
	@echo "=== Section headers (check segment merge) ==="
	$(READELF) -S $(TARGET)
	@echo ""
	@echo "=== ADRP sites with source lines ==="
	$(OBJDUMP) -S $(OBJ) > avc_guard.disasm.txt
	grep -n -B 3 -A 3 'adrp' avc_guard.disasm.txt | head -n 200 || echo "No ADRP found"
	@echo ""
	@echo "=== Symbol table ==="
	$(NM) $(TARGET) | head -n 50
	@echo ""
	@echo "=== Section sizes ==="
	$(SIZE) $(OBJ)
	$(SIZE) $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) avc_guard.disasm.txt
