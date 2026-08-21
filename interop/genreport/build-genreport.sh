#!/bin/sh
# Build and install ISC's genreport — the EDNS compliance battery behind
# dnsflagday.net — into /usr/local/bin, where a non-login WSL shell finds it.
#
# Run once per machine:
#     wsl -u root -e sh interop/genreport/build-genreport.sh
#
# Needs: git, gcc, make, autoconf, automake, pkg-config, libssl-dev.
# Does NOT need bind9-dev: the README asks for libresolv, which glibc provides.
set -eu

SRC="${GENREPORT_SRC:-/tmp/genreport-src}"
REPO="https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing.git"

if [ ! -d "$SRC/.git" ]; then
    rm -rf "$SRC"
    git clone --depth 1 "$REPO" "$SRC"
fi

cd "$SRC"
autoreconf -fi
./configure

# configure detects <resolv.h> but does not add -lresolv, so the link fails on
# ns_makecanon/ns_put16/ns_get16 — all public in glibc's libresolv.so.2. Passing
# LIBS here rather than patching keeps the checkout as ISC published it.
make LIBS="-L/usr/lib -lcrypto -lresolv"

install -m 0755 "$SRC/genreport" /usr/local/bin/genreport
echo "installed: $(command -v genreport)"
genreport -L | head -3
