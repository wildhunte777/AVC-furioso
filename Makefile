ifndef TARGET_COMPILE
  $(error TARGET_COMPILE is not set. Use: make TARGET_COMPILE=aarch64-none-elf-)
endif

ifndef KP_DIR
  KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS := -O2 -Wall -nostdinc -ffreestanding -fno-stack-protector \
          -fno-pic -fno-pie -fno-common -mgeneral-regs-only \
          -mcmodel=large -fno-jump-tables \
          -DKP_MODULE

TARGET := avc_guard.kpm
OBJ := avc_guard.o

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -r -nostdlib -o $@ $^
	@echo "=== Built: $@ ==="

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

check: $(TARGET)
	@echo "=== ADRP instructions in binary ==="
	$(TARGET_COMPILE)objdump -d $(TARGET) | grep -c adrp || true
	@echo "=== ADRP relocations ==="
	$(TARGET_COMPILE)readelf -r $(TARGET) | grep -cE 'ADR_PREL_PG_HI21|283' || true
	@echo "=== Full relocation dump ==="
	$(TARGET_COMPILE)readelf -r $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
