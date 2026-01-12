FROM archlinux:latest AS app

# Set environment variables to avoid prompts during installation
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PACMAN_KEYRING=/etc/pacman.d/gnupg

# Update system and install required packages
RUN pacman -Syu --noconfirm \
    && pacman -S --noconfirm qemu-base qemu-system-x86 \
    && pacman -Scc --noconfirm

FROM pwn.red/jail

COPY --from=app / /srv

RUN mkdir -p /srv/app
WORKDIR /srv/app
COPY --chmod=555 start-qemu.sh run
COPY bzImage initramfs.cpio.gz .

ENV JAIL_PIDS=10 JAIL_MEM=200M JAIL_TIME=600 JAIL_POW=10000
