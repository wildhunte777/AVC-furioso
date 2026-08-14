SECTIONS
{
    . = 0x0;

    /*
     * 合并所有段到 .text，确保 KPM 加载器只映射一块连续内存。
     * .bss 也合并进来（以 0 填充），避免加载器独立分配 .bss。
     */
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.bss .bss.*)
        *(.kpm.init .kpm.init.*)
        *(.kpm.exit .kpm.exit.*)
        *(.kpm.ctl0 .kpm.ctl0.*)
        *(.kpm.info .kpm.info.*)
    }
}
