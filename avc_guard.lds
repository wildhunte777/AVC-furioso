/* KPM Linker Script for avc_guard */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

SECTIONS
{
    /* KPM metadata and callbacks must be first */
    .kpm.info : {
        *(.kpm.info)
    }
    .kpm.init : {
        *(.kpm.init)
    }
    .kpm.ctl0 : {
        *(.kpm.ctl0)
    }
    .kpm.ctl1 : {
        *(.kpm.ctl1)
    }
    .kpm.exit : {
        *(.kpm.exit)
    }

    /* Code and read-only data */
    .text : {
        *(.text .text.*)
    }
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : {
        *(.data .data.*)
    }

    /* BSS */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* Discard unnecessary sections to reduce size */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
