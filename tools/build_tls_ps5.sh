#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Build the TLS library behind Wine's schannel for the console: nettle (with
# its own mini-gmp, so no GMP) and GnuTLS (with its included libtasn1 and
# libunistring; no p11-kit, IDN, TPM, zlib, brotli or zstd), as static
# archives the PS5 build links into libgnutls.prx (tools/build_wine_ps5.sh).
# The SDK has no libm, so an empty one stands in for the -lm the build asks.
#
# With them, the root certificates crypt32 trusts on the console (patch
# 0878): Mozilla's store as curl publishes it, a dated file pinned by
# SHA-256 like the tarballs, so a release carries a known bundle whoever
# builds it; and the licence texts of what libgnutls.prx links, which
# tools/package_release.sh ships (THIRD_PARTY.md says which covers what).
#
# Usage: tools/build_tls_ps5.sh [--work DIR] [--sdk DIR] [--jobs N]
#   work   .deps/wine-ps5/tls by default: tarballs, source trees and root/
#   sdk    the payload SDK (PS5_PAYLOAD_SDK, or the pinned foundation's)
# LLVM_CONFIG may select an LLVM 18 executable (default llvm-config-18).
# Other LLVM majors are unsupported. Its canonical path, real backend tools
# and clang resource headers become part of the verified build identity.
# root/ holds lib/ and include/ for the Wine build, ca-certificates.crt and
# licenses/{gnutls,nettle}.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=${PROSPERO_WINE_PS5_WORK:-$root/.deps/wine-ps5}/tls
sdk=${PS5_PAYLOAD_SDK:-$root/.deps/ps5-native-app-boilerplate/.deps/native/ps5-payload-sdk}
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
NETTLE_VERSION=3.10.1
NETTLE_SHA256=b0fcdd7fc0cdea6e80dcf1dd85ba794af0d5b4a57e26397eee3bc193272d9132
NETTLE_URL=https://ftp.gnu.org/gnu/nettle/nettle-$NETTLE_VERSION.tar.gz
GNUTLS_VERSION=3.8.13
GNUTLS_SHA256=ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e
GNUTLS_URL=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-$GNUTLS_VERSION.tar.xz
# Mozilla's root store, extracted by curl's mk-ca-bundle (MPL-2.0); the
# dated files at https://curl.se/docs/caextract.html do not change.
CA_BUNDLE_DATE=2026-09-25
CA_BUNDLE_SHA256=a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505
CA_BUNDLE_URL=https://curl.se/ca/cacert-$CA_BUNDLE_DATE.pem
fail() { echo "build_tls_ps5: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case $1 in
    --work) work=$2; shift ;;
    --sdk) sdk=$2; shift ;;
    --jobs) jobs=$2; shift ;;
    *) fail "unknown argument $1" ;;
    esac
    shift
done
[ -x "$sdk/bin/prospero-clang" ] || fail "no PS5 payload SDK at $sdk"
out=$work/root
mkdir -p "$out/lib" "$work"
fetch() {
    [ -f "$work/$2" ] || curl -sSfL -o "$work/$2" "$1" || fail "cannot download $1"
    [ "$(sha256sum "$work/$2" | cut -c1-64)" = "$3" ] || fail "$2 does not match its pinned SHA-256"
}
fetch "$NETTLE_URL" "nettle-$NETTLE_VERSION.tar.gz" "$NETTLE_SHA256"
fetch "$GNUTLS_URL" "gnutls-$GNUTLS_VERSION.tar.xz" "$GNUTLS_SHA256"
fetch "$CA_BUNDLE_URL" "cacert-$CA_BUNDLE_DATE.pem" "$CA_BUNDLE_SHA256"
# The SDK wrappers dispatch to host LLVM. Pin their one supported backend
# before any SDK command; a bare LLVM_CONFIG name is resolved here rather
# than left to the SDK wrapper's working-directory-relative readlink.
LLVM_CONFIG=$(python3 "$root/tools/tls_manifest.py" select-llvm --sdk "$sdk") ||
    fail "cannot select the supported LLVM 18 toolchain"
export LLVM_CONFIG
# An archive's existence says nothing about which source or SDK built it.
# Check all installed artifacts and their input identity before reusing any
# of them; replace a stale/incomplete installation as one dependency set.
python3 "$root/tools/tls_manifest.py" inputs --script "$root/tools/build_tls_ps5.sh" \
    --sdk "$sdk" > "$work/tls-inputs.json" || fail "cannot identify TLS build inputs"
if ! python3 "$root/tools/tls_manifest.py" verify --root "$out" \
        --inputs "$work/tls-inputs.json"; then
    rm -rf "$out"
    mkdir -p "$out/lib"
fi
[ -f "$out/lib/libm.a" ] || "$sdk/bin/llvm-ar" rcs "$out/lib/libm.a"
export CC="$sdk/bin/prospero-clang" CXX="$sdk/bin/prospero-clang++" AR="$sdk/bin/llvm-ar" \
       RANLIB="$sdk/bin/llvm-ranlib" NM="$sdk/bin/llvm-nm" STRIP=true \
       CFLAGS="-O2 -fPIC" LDFLAGS="-L$out/lib" \
       PKG_CONFIG_LIBDIR="$out/lib/pkgconfig" PKG_CONFIG_PATH="$out/lib/pkgconfig"
host=x86_64-unknown-freebsd11
# Configure and make run with a fixed environment: inherited configure
# cache/site variables, CPPFLAGS, LIBS and user CXXFLAGS must not silently
# change an installation whose identity says it used this recipe.
build_env() {
    env -i PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" \
        LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1000000000 CONFIG_SITE=/dev/null \
        PS5_PAYLOAD_SDK="$sdk" \
        LLVM_CONFIG="$LLVM_CONFIG" \
        CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" NM="$NM" STRIP=true \
        CFLAGS="$CFLAGS" CXXFLAGS="$CFLAGS" CPPFLAGS= LIBS= LDFLAGS="$LDFLAGS" \
        PKG_CONFIG_LIBDIR="$PKG_CONFIG_LIBDIR" PKG_CONFIG_PATH="$PKG_CONFIG_PATH" "$@"
}
if [ ! -f "$out/lib/libhogweed.a" ]; then
    rm -rf "$work/nettle-$NETTLE_VERSION"
    tar -xzf "$work/nettle-$NETTLE_VERSION.tar.gz" -C "$work"
    patch --batch --forward --fuzz=0 -p1 -d "$work/nettle-$NETTLE_VERSION" \
        < "$root/tools/patches/nettle-3.10.1-ed448-canonical.patch" ||
        fail "cannot apply the Nettle Ed448 canonical-signature fix"
    (cd "$work/nettle-$NETTLE_VERSION" &&
        build_env ./configure --host=$host --prefix="$out" --enable-mini-gmp --disable-shared --enable-static \
            --disable-documentation --disable-assembler --disable-openssl > configure.log 2>&1 &&
        build_env make -j"$jobs" > make.log 2>&1 && build_env make install > install.log 2>&1) ||
        fail "nettle did not build; see $work/nettle-$NETTLE_VERSION/*.log"
    echo "built nettle $NETTLE_VERSION"
fi
if [ ! -f "$out/lib/libgnutls.a" ]; then
    rm -rf "$work/gnutls-$GNUTLS_VERSION"
    tar -xJf "$work/gnutls-$GNUTLS_VERSION.tar.xz" -C "$work"
    patch --batch --forward --fuzz=0 -p1 -d "$work/gnutls-$GNUTLS_VERSION" \
        < "$root/tools/patches/gnutls-3.8.13-kern-arnd-headers.patch" ||
        fail "cannot apply the GnuTLS BSD entropy-probe header fix"
    (cd "$work/gnutls-$GNUTLS_VERSION" &&
        build_env ./configure --host=$host --prefix="$out" --disable-shared --enable-static \
            --with-included-libtasn1 --with-included-unistring --without-p11-kit --without-idn \
            --without-tpm --without-tpm2 --without-zlib --without-brotli --without-zstd \
            --disable-doc --disable-tests --disable-tools --disable-cxx --disable-libdane \
            --disable-nls --disable-guile --disable-gcc-warnings --disable-hardware-acceleration \
            NETTLE_CFLAGS="-I$out/include" NETTLE_LIBS="-L$out/lib -lnettle" \
            HOGWEED_CFLAGS="-I$out/include" HOGWEED_LIBS="-L$out/lib -lhogweed" \
            GMP_CFLAGS="-I$out/include" GMP_LIBS="-L$out/lib -lhogweed" > configure.log 2>&1 &&
        # Top-level make still enters src/gl/tests with --disable-tools
        # and --disable-tests. Build only the runtime library: gl supplies
        # libgnu.la; lib owns all crypto backends, public headers and .pc.
        build_env make -C gl -j"$jobs" > make.log 2>&1 &&
        build_env make -C lib -j"$jobs" >> make.log 2>&1 &&
        build_env make -C lib install > install.log 2>&1) ||
        fail "GnuTLS did not build; see $work/gnutls-$GNUTLS_VERSION/*.log"
    echo "built GnuTLS $GNUTLS_VERSION"
fi
# The licence texts, from the sources that were built (extracted again if
# the trees are gone): GnuTLS's LGPL-2.1 and GPL-3 texts and authors, with
# its included inih's notice; nettle's LGPL-3, GPL-2 and GPL-3 texts and
# authors. libtasn1 and libunistring, included in GnuTLS, are covered by
# those texts (THIRD_PARTY.md).
licenses() {
    [ -d "$work/$1" ] || tar -xf "$work/$1.tar.$3" -C "$work" || fail "cannot extract $1"
    rm -rf "$out/licenses/$2"
    mkdir -p "$out/licenses/$2"
    for file in $4; do
        cp "$work/$1/$file" "$out/licenses/$2/$(echo "$file" | tr / -)" || fail "no $file in $1"
    done
}
if [ ! -d "$out/licenses/gnutls" ]; then
    licenses "gnutls-$GNUTLS_VERSION" gnutls xz "COPYING.LESSERv2 COPYING AUTHORS lib/inih/LICENSE.txt"
fi
if [ ! -d "$out/licenses/nettle" ]; then
    licenses "nettle-$NETTLE_VERSION" nettle gz "COPYING.LESSERv3 COPYINGv2 COPYINGv3 AUTHORS"
fi
# The bundle, as the PS5 build stages it beside the runtime.
if [ "$(sha256sum "$out/ca-certificates.crt" 2>/dev/null | cut -c1-64)" != "$CA_BUNDLE_SHA256" ]; then
    cp "$work/cacert-$CA_BUNDLE_DATE.pem" "$out/ca-certificates.crt"
    echo "root certificates: cacert-$CA_BUNDLE_DATE.pem"
fi
python3 "$root/tools/tls_manifest.py" record --root "$out" --inputs "$work/tls-inputs.json" \
    --script "$root/tools/build_tls_ps5.sh" --sdk "$sdk" ||
    fail "TLS build did not produce a complete verified artifact set"
echo "$out"
