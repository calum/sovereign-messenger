#!/usr/bin/env bash
# Signs one update APK for the P2P update gate (wire format v2). Run it on the
# offline machine that holds the developer's Ed25519 private key.
#
#   sign-update.sh KEY_FILE VERSION APK_FILE OUT_SIG
#
#   KEY_FILE  PEM or DER Ed25519 private key. Read by openssl only; never echoed.
#   VERSION   the update's version, a positive decimal integer. It must be higher
#             than the installed version or the phones refuse it as a downgrade.
#   APK_FILE  the signed release APK.
#   OUT_SIG   where to write the 64-byte raw detached signature.
#
# The signed bytes are exactly what rust-core/src/update.rs checks:
#   "sovereign-p2p update v2" || VERSION as 8-byte big-endian || APK bytes
# The script does not set -x and never prints the key or the message.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: sign-update.sh KEY_FILE VERSION APK_FILE OUT_SIG" >&2
  exit 2
fi
key="$1"
version="$2"
apk="$3"
out="$4"

# Digits only, and short enough that the value fits in a signed 64-bit shell integer.
case "$version" in
  '' | *[!0-9]*)
    echo "VERSION must be a positive decimal integer" >&2
    exit 2
    ;;
esac
if [ "${#version}" -gt 18 ]; then
  echo "VERSION is too large" >&2
  exit 2
fi
# 10# forces decimal, so "010" is not read as octal.
version=$((10#$version))
if [ "$version" -lt 1 ]; then
  echo "VERSION must be at least 1" >&2
  exit 2
fi

if [ ! -r "$key" ]; then
  echo "cannot read KEY_FILE" >&2
  exit 2
fi
if [ ! -r "$apk" ]; then
  echo "cannot read APK_FILE" >&2
  exit 2
fi

# Eight big-endian bytes of the version, as raw bytes on stdout.
be64() {
  local v="$1" i esc=""
  for i in 7 6 5 4 3 2 1 0; do
    esc+="$(printf '\\x%02x' $(((v >> (8 * i)) & 255)))"
  done
  printf '%b' "$esc"
}

# openssl's one-shot Ed25519 mode needs a file, not a pipe, because it reads the
# size first. The staged message holds only public data (the APK and its version),
# so it is not a secret. It is still removed on exit, whatever happens.
msg="$(mktemp)"
trap 'rm -f -- "$msg"' EXIT
{
  printf '%s' 'sovereign-p2p update v2'
  be64 "$version"
  cat -- "$apk"
} > "$msg"
openssl pkeyutl -sign -inkey "$key" -rawin -in "$msg" -out "$out"

# An Ed25519 signature is exactly 64 bytes. Anything else is not a signature.
if [ "$(wc -c < "$out")" -ne 64 ]; then
  rm -f -- "$out"
  echo "signing did not produce a 64-byte signature; output removed" >&2
  exit 1
fi
echo "wrote $out (64 bytes, version $version)"
