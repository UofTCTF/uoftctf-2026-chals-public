#!/bin/sh
set -e

ARCH_DIR=$(gcc -print-multiarch 2>/dev/null || echo "x86_64-linux-gnu")
echo "[*] Compiling eBPF program..."
clang -O3 -g -target bpf \
  -I"/usr/include/${ARCH_DIR}" \
  -c /src/firewall.c -o /src/firewall.o

echo "[*] Setting up tc clsact on eth0..."
if ! tc qdisc show dev eth0 | grep -q clsact; then
  tc qdisc add dev eth0 clsact
fi

echo "[*] Attaching eBPF filter"

tc filter add dev eth0 ingress bpf da \
  obj /src/firewall.o sec tc/ingress

tc filter add dev eth0 egress bpf da \
  obj /src/firewall.o sec tc/ingress

echo "[*] eBPF filter loaded"

echo "[*] Starting flag server"
nginx -g "daemon off;"