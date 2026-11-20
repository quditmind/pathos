#!/usr/bin/env bash
# Writes a firmware-like test blob from test data only:
#   make-firmware.sh <elf> <out>
# [64-byte header][gzip of a small root filesystem tar][padding][the ELF][padding]
set -euo pipefail
elf="$1" out="$2"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/rootfs/etc" "$tmp/rootfs/bin"
printf 'hostname=fixture\nadmin_url=/admin/config\n' > "$tmp/rootfs/etc/device.conf"
cp "$elf" "$tmp/rootfs/bin/app"
tar -C "$tmp/rootfs" -cf "$tmp/rootfs.tar" .
gzip -9 -n -c "$tmp/rootfs.tar" > "$tmp/rootfs.tar.gz"
{
  printf 'PATHOSFW'; head -c 56 /dev/zero
  cat "$tmp/rootfs.tar.gz"
  head -c 4096 /dev/zero
  cat "$elf"
  head -c 4096 /dev/zero
} > "$out"
