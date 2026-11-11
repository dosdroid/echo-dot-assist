#!/bin/sh
# Builds Shairport Sync, the AirPlay receiver hassmic runs beside itself (src/hassmic/airplay.c), as one static binary.
#   tools/airplay/build.sh host   -> build/airplay/host/shairport-sync   (the PC's, for tests/fake_airplay.py)
#   tools/airplay/build.sh arm    -> build/airplay/arm/shairport-sync    (every Echo's: ARMv7, musl, no library of the
#                                    firmware used, so one binary for all models)
#
# Why not in hassmic and not against bionic: Shairport Sync is the AirPlay receiver that is kept working against
# Apple's senders (the one Music Assistant's AirPlay Receiver runs too; the version pinned here is the one its image
# builds), and it is built on pthread_cancel, which bionic does not have.  musl has it, and a static musl binary needs
# nothing of Android.  `arm` cross-compiles with zig cc (PyPI's ziglang: no toolchain to install; ZIG names another).
#
# Classic AirPlay ("AirPlay 1") only: AirPlay 2 needs PTP on UDP 319/320 as root (nqptp) and four more libraries.
# The sources are fetched at pinned commits (git checks what it fetched against them); nothing of them is in this repo.
set -e
cd "$(dirname "$0")/../.."
T=${1:-host}
case $T in host | arm) ;; *) echo "usage: tools/airplay/build.sh host|arm" >&2; exit 2 ;; esac
SRC=$PWD/build/airplay/src W=$PWD/build/airplay/$T
J=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)

# name, repository, tag, the commit that tag must be
SOURCES="shairport-sync https://github.com/mikebrady/shairport-sync 4.3.7 0b1c4391ffd398e7b145eb4b98416261380adeea
popt https://github.com/rpm-software-management/popt popt-1.19-release 916e61045d268f7e37ade5ec047eb77e8299e6ad
libconfig https://github.com/hyperrealm/libconfig v1.7.3 525922a6b49ca19235cdf307376e7c9c539d1b93
mbedtls https://github.com/Mbed-TLS/mbedtls v2.28.10 2fc8413bfcb51354c8e679141b17b3f1a5942561"

mkdir -p "$SRC" "$W"
echo "$SOURCES" | while read -r name url tag commit; do
    [ "$(git -C "$SRC/$name" rev-parse HEAD 2>/dev/null)" = "$commit" ] && continue
    rm -rf "$SRC/$name"; git init -q "$SRC/$name"
    git -C "$SRC/$name" fetch -q --depth 1 "$url" "refs/tags/$tag"
    git -C "$SRC/$name" -c advice.detachedHead=false checkout -q FETCH_HEAD
    [ "$(git -C "$SRC/$name" rev-parse HEAD)" = "$commit" ] || { echo "$name: $tag is not $commit" >&2; exit 1; }
done

if [ $T = arm ]; then
    # zig cc as a compiler of one word (configure and make want that), and its ar
    if [ -z "$ZIG" ]; then
        for z in "$PWD/.venv/bin/python -m ziglang" "python3 -m ziglang" zig; do
            $z version > /dev/null 2>&1 && { ZIG=$z; break; }
        done
    fi
    [ -n "$ZIG" ] || { echo "no zig: uv sync (ziglang), or ZIG=<zig>" >&2; exit 1; }
    mkdir -p "$W/bin"
    # ARMv7-A with VFPv3-D16, no NEON asked for: the oldest Echo's SoC (MT8163, Cortex-A53) and every later one run it
    printf '#!/bin/sh\nexec %s cc -target arm-linux-musleabihf -mcpu=cortex_a7 "$@"\n' "$ZIG" > "$W/bin/cc"
    printf '#!/bin/sh\nexec %s c++ -target arm-linux-musleabihf -mcpu=cortex_a7 "$@"\n' "$ZIG" > "$W/bin/c++"
    printf '#!/bin/sh\nexec %s ar "$@"\n' "$ZIG" > "$W/bin/ar"
    printf '#!/bin/sh\nexec %s ranlib "$@"\n' "$ZIG" > "$W/bin/ranlib"
    chmod +x "$W/bin/cc" "$W/bin/c++" "$W/bin/ar" "$W/bin/ranlib"
    CC=$W/bin/cc CXX=$W/bin/c++ AR=$W/bin/ar RANLIB=$W/bin/ranlib HOST="--host=arm-linux-musleabihf"
else
    CC=${CC:-cc} CXX=${CXX:-c++} AR=${AR:-ar} RANLIB=${RANLIB:-ranlib} HOST=
fi
CFLAGS="-O2 -ffunction-sections -fdata-sections"
P=$W/prefix; mkdir -p "$P/lib" "$P/include"

# popt and libconfig: a handful of C files each, compiled as they are (their autotools want gettext, bison, flex)
if [ ! -f "$P/lib/libpopt.a" ]; then
    mkdir -p "$W/popt"
    printf '#define HAVE_STDLIB_H 1\n#define HAVE_STRING_H 1\n#define HAVE_UNISTD_H 1\n#define HAVE_FNMATCH_H 1\n#define HAVE_FLOAT_H 1\n#define HAVE_STPCPY 1\n#define HAVE_STRERROR 1\n#define HAVE_VASPRINTF 1\n#define HAVE_SRANDOM 1\n#define PACKAGE "popt"\n#define POPT_SYSCONFDIR "/etc"\n' > "$W/popt/config.h"
    for f in popt poptparse poptconfig popthelp poptint lookup3; do
        $CC $CFLAGS -D_GNU_SOURCE -DHAVE_CONFIG_H -I"$W/popt" -I"$SRC/popt/src" -c "$SRC/popt/src/$f.c" -o "$W/popt/$f.o"
    done
    $AR rcs "$P/lib/libpopt.a" "$W"/popt/*.o; cp "$SRC/popt/src/popt.h" "$P/include/"
fi
if [ ! -f "$P/lib/libconfig.a" ]; then
    mkdir -p "$W/libconfig"
    for f in grammar libconfig scanctx scanner strbuf strvec util wincompat; do
        $CC $CFLAGS -D_GNU_SOURCE -DHAVE_USELOCALE=1 -DHAVE_NEWLOCALE=1 -DHAVE_FREELOCALE=1 \
            -I"$SRC/libconfig/lib" -c "$SRC/libconfig/lib/$f.c" -o "$W/libconfig/$f.o"
    done
    $AR rcs "$P/lib/libconfig.a" "$W"/libconfig/*.o; cp "$SRC/libconfig/lib/libconfig.h" "$P/include/"
fi
# Mbed TLS: RSA with the AirPort Express key and AES for classic AirPlay's audio; no TLS is spoken
if [ ! -f "$P/lib/libmbedcrypto.a" ]; then
    rm -rf "$W/mbedtls"; mkdir -p "$W/mbedtls"; cp -r "$SRC/mbedtls/library" "$SRC/mbedtls/include" "$W/mbedtls/"
    [ ! -d "$SRC/mbedtls/3rdparty" ] || cp -r "$SRC/mbedtls/3rdparty" "$W/mbedtls/"
    make -s -j"$J" -C "$W/mbedtls/library" CC="$CC" AR="$AR" CFLAGS="$CFLAGS" libmbedcrypto.a libmbedx509.a libmbedtls.a > /dev/null
    cp "$W"/mbedtls/library/*.a "$P/lib/"; cp -r "$W/mbedtls/include/mbedtls" "$W/mbedtls/include/psa" "$P/include/"
fi

# Shairport Sync itself.  stdout: the PCM goes down a pipe to hassmic, which plays it on the music stream; metadata:
# what plays and every event (begin, end, flush, volume) on a second pipe; external mDNS: it runs
# "avahi-publish-service" with the name and TXT records it wants announced, which airplay.c answers to with a program
# of that name that writes them into the stock avahi's service folder (no second mDNS responder on the Echo).
rm -rf "$W/shairport-sync"; cp -r "$SRC/shairport-sync" "$W/shairport-sync"; rm -rf "$W/shairport-sync/.git"
cd "$W/shairport-sync"
autoreconf -fi > "$W/autoreconf.log" 2>&1 || { tail -20 "$W/autoreconf.log" >&2; exit 1; }
./configure $HOST CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" CFLAGS="$CFLAGS -I$P/include" \
    LDFLAGS="-static -s -L$P/lib -Wl,--gc-sections" --without-pkg-config \
    --with-stdout --with-metadata --with-external-mdns --with-ssl=mbedtls \
    --without-avahi --without-alsa --without-libdaemon --without-soxr --without-configfiles \
    --sysconfdir=/etc > "$W/configure.log" 2>&1 || { tail -30 "$W/configure.log" >&2; exit 1; }
make -s -j"$J" shairport-sync > "$W/make.log" 2>&1 || { tail -40 "$W/make.log" >&2; exit 1; }
cp shairport-sync "$W/shairport-sync.bin"
cd "$W"; rm -rf shairport-sync.dir; mv shairport-sync shairport-sync.dir; mv shairport-sync.bin shairport-sync
chmod 755 shairport-sync
ls -l "$W/shairport-sync"
