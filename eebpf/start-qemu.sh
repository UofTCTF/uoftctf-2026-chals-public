#!/bin/sh
exec qemu-system-x86_64 \
    -m 128M  \
    -smp 1 \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 quiet kaslr panic=0 oops=panic"

