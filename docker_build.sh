#!/bin/bash
set -e

EMDIR="/emsdk/upstream/emscripten"
TOR_SRC="/tor-src"
SOCKET_IWA="/socket-iwa"
PREFIX="/build/install"
BUILDDIR="/build"
OUTDIR="/tor-iwa/iwa/public"

NPROC=$(nproc 2>/dev/null || echo 4)

echo "=========================================="
echo " tor-iwa: Building Tor for WebAssembly"
echo "=========================================="
echo "emscripten: $EMDIR"
echo "tor source: $TOR_SRC"
echo "socket-iwa: $SOCKET_IWA"
echo "prefix:     $PREFIX"
echo "nproc:      $NPROC"
echo ""

mkdir -p "$PREFIX" "$BUILDDIR" "$OUTDIR"

# ============================================================================
# PHASE 1: Apply socket-iwa patches to emscripten
# ============================================================================
echo ""
echo "=== Phase 1: Applying socket-iwa patches to emscripten ==="
echo ""

# 1a. Add DIRECT_SOCKETS setting to settings.js
if ! grep -q 'var DIRECT_SOCKETS' "$EMDIR/src/settings.js"; then
  sed -i '/^var PROXY_POSIX_SOCKETS = false;/a\
var DIRECT_SOCKETS = false;' "$EMDIR/src/settings.js"
  echo "  Patched settings.js"
fi

# 1b. Guard default socket syscalls in libsyscall.js
if ! grep -q 'DIRECT_SOCKETS' "$EMDIR/src/lib/libsyscall.js"; then
  sed -i 's/^#if PROXY_POSIX_SOCKETS == 0 && WASMFS == 0$/#if PROXY_POSIX_SOCKETS == 0 \&\& WASMFS == 0 \&\& DIRECT_SOCKETS == 0/' \
    "$EMDIR/src/lib/libsyscall.js"
  echo "  Patched libsyscall.js guard"
fi

# 1c. Patch fd_close in libwasi.js
if ! grep -q 'DIRECT_SOCKETS' "$EMDIR/src/lib/libwasi.js"; then
python3 -c "
path = '$EMDIR/src/lib/libwasi.js'
with open(path) as f:
    content = f.read()

old_block = '''#elif PROXY_POSIX_SOCKETS
    // close() is a tricky function because it can be used to close both regular file descriptors
    // and POSIX network socket handles, hence an implementation would need to track for each
    // file descriptor which kind of item it is. To simplify, when using PROXY_POSIX_SOCKETS
    // option, use shutdown() to close a socket, and this function should behave like a no-op.
    warnOnce('To close sockets with PROXY_POSIX_SOCKETS bridge, prefer to use the function shutdown() that is proxied, instead of close()')
    return 0;'''

new_block = old_block + '''
#elif DIRECT_SOCKETS
    // Pipes are not in the FS, handle them explicitly
    if (typeof DIRECT_SOCKETS_PIPES !== 'undefined' && DIRECT_SOCKETS_PIPES.closePipeFd(fd)) {
      return 0;
    }
    // Socket fds are registered in the FS via FS.createStream(), so fall
    // through to let the normal FS.close() path handle them.  That will
    // call stream_ops.close() which triggers DIRECT_SOCKETS._closeSocket().'''

content = content.replace(old_block, new_block)
with open(path, 'w') as f:
    f.write(content)
print('  Patched libwasi.js (fd_close)')
"
fi

# 1d. Copy libdirectsockets.js
cp "$SOCKET_IWA/emscripten/src/lib/libdirectsockets.js" "$EMDIR/src/lib/libdirectsockets.js"
echo "  Copied libdirectsockets.js"

# 1e. Register in modules.mjs
if ! grep -q 'libdirectsockets' "$EMDIR/src/modules.mjs"; then
python3 -c "
path = '$EMDIR/src/modules.mjs'
with open(path) as f:
    content = f.read()

old = '''  if (!WASMFS) {
    libraries.push('libsyscall.js');
  }'''

new = '''  if (!WASMFS) {
    libraries.push('libsyscall.js');
  }

  if (DIRECT_SOCKETS) {
    libraries.push('libdirectsockets.js');
  }'''

content = content.replace(old, new)
with open(path, 'w') as f:
    f.write(content)
print('  Patched modules.mjs')
"
fi

# 1f. Remove C stubs that conflict with our JS implementations
STUBS_FILE="$EMDIR/system/lib/libc/emscripten_syscall_stubs.c"
if [ -f "$STUBS_FILE" ]; then
python3 -c "
import re
path = '$STUBS_FILE'
with open(path) as f:
    content = f.read()
changed = False

# Stubs to remove
stubs = [
    ('__syscall_setsockopt', r'weak int __syscall_setsockopt\([^)]*\)\s*\{[^}]*REPORT\(setsockopt\)[^}]*\}'),
    ('__syscall_poll', r'weak int __syscall_poll\([^)]*\)\s*\{[^}]*REPORT\(poll\)[^}]*\}'),
    ('__syscall_pselect6', r'weak int __syscall_pselect6\([^)]*\)\s*\{[^}]*REPORT\(pselect6\)[^}]*\}'),
    ('__syscall_pipe2', r'weak int __syscall_pipe2\([^)]*\)\s*\{[^}]*REPORT\(pipe2\)[^}]*\}'),
    ('__syscall_fcntl64', r'weak int __syscall_fcntl64\([^)]*\)\s*\{[^}]*REPORT\(fcntl64\)[^}]*\}'),
    ('__syscall_ioctl', r'weak int __syscall_ioctl\([^)]*\)\s*\{[^}]*REPORT\(ioctl\)[^}]*\}'),
    ('__syscall_socketpair', r'weak int __syscall_socketpair\([^)]*\)\s*\{[^}]*REPORT\(socketpair\)[^}]*\}'),
]

for name, pattern in stubs:
    m = re.search(pattern, content)
    if m:
        content = content.replace(m.group(0),
            '// Removed: ' + name + ' - provided by libdirectsockets.js')
        changed = True

if changed:
    with open(path, 'w') as f:
        f.write(content)
    print('  Patched emscripten_syscall_stubs.c')
else:
    print('  emscripten_syscall_stubs.c: already patched or no stubs found')
"
fi

# 1g. Patch fd_read/fd_write for pipe support
if ! grep -q 'DIRECT_SOCKETS_PIPES.*readPipe' "$EMDIR/src/lib/libwasi.js"; then
python3 -c "
import re
path = '$EMDIR/src/lib/libwasi.js'
with open(path) as f:
    content = f.read()

# Patch fd_read
fd_read_pattern = r'(fd_read\s*:\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{)'
m = re.search(fd_read_pattern, content)
if m:
    inject_after = m.group(0)
    params = [p.strip() for p in m.group(2).split(',')]
    p_fd = params[0] if len(params) > 0 else 'fd'
    p_iov = params[1] if len(params) > 1 else 'iov'
    p_iovcnt = params[2] if len(params) > 2 else 'iovcnt'
    p_pnum = params[3] if len(params) > 3 else 'pnum'

    pipe_read_check = '''
#if DIRECT_SOCKETS
    if (typeof DIRECT_SOCKETS_PIPES !== \"undefined\") {
      var __pipeEntry = DIRECT_SOCKETS_PIPES.getPipe(''' + p_fd + ''');
      if (__pipeEntry) {
        var __totalRead = 0;
        for (var __pi = 0; __pi < ''' + p_iovcnt + '''; __pi++) {
          var __ptr = {{{ makeGetValue(\"''' + p_iov + '''\", '__pi * 8', POINTER_TYPE) }}};
          var __len = {{{ makeGetValue(\"''' + p_iov + '''\", '__pi * 8 + 4', POINTER_TYPE) }}};
          var __chunk = DIRECT_SOCKETS_PIPES.readPipe(''' + p_fd + ''', __len);
          if (__chunk && __chunk.length > 0) {
            HEAPU8.set(__chunk, __ptr);
            __totalRead += __chunk.length;
          }
        }
        {{{ makeSetValue(\"''' + p_pnum + '''\", 0, '__totalRead', POINTER_TYPE) }}};
        return 0;
      }
    }
#endif
'''
    content = content.replace(inject_after, inject_after + pipe_read_check, 1)
    print('  Patched fd_read for pipe support')

# Patch fd_write
fd_write_pattern = r'(fd_write\s*:\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{)'
m = re.search(fd_write_pattern, content)
if m:
    inject_after = m.group(0)
    params = [p.strip() for p in m.group(2).split(',')]
    p_fd = params[0] if len(params) > 0 else 'fd'
    p_iov = params[1] if len(params) > 1 else 'iov'
    p_iovcnt = params[2] if len(params) > 2 else 'iovcnt'
    p_pnum = params[3] if len(params) > 3 else 'pnum'

    pipe_write_check = '''
#if DIRECT_SOCKETS
    if (typeof DIRECT_SOCKETS_PIPES !== \"undefined\") {
      var __pipeEntry = DIRECT_SOCKETS_PIPES.getPipe(''' + p_fd + ''');
      if (__pipeEntry) {
        var __totalWritten = 0;
        for (var __pi = 0; __pi < ''' + p_iovcnt + '''; __pi++) {
          var __ptr = {{{ makeGetValue(\"''' + p_iov + '''\", '__pi * 8', POINTER_TYPE) }}};
          var __len = {{{ makeGetValue(\"''' + p_iov + '''\", '__pi * 8 + 4', POINTER_TYPE) }}};
          var __data = HEAPU8.slice(__ptr, __ptr + __len);
          var __rc = DIRECT_SOCKETS_PIPES.writePipe(''' + p_fd + ''', __data);
          if (__rc < 0) {
            if (__totalWritten > 0) break;
            {{{ makeSetValue(\"''' + p_pnum + '''\", 0, '0', POINTER_TYPE) }}};
            return 29;
          }
          __totalWritten += __rc;
        }
        {{{ makeSetValue(\"''' + p_pnum + '''\", 0, '__totalWritten', POINTER_TYPE) }}};
        return 0;
      }
    }
#endif
'''
    content = content.replace(inject_after, inject_after + pipe_write_check, 1)
    print('  Patched fd_write for pipe support')

with open(path, 'w') as f:
    f.write(content)
"
fi

# 1h. Guard original _emscripten_lookup_name
for LOOKUPFILE in "$EMDIR/src/lib/libsockfs.js" "$EMDIR/src/lib/libsyscall.js" "$EMDIR/src/lib/libnetworking.js"; do
  if [ -f "$LOOKUPFILE" ] && grep -q '_emscripten_lookup_name' "$LOOKUPFILE" 2>/dev/null; then
    if ! grep -q 'DIRECT_SOCKETS.*_emscripten_lookup_name' "$LOOKUPFILE" 2>/dev/null; then
python3 -c "
import re
path = '$LOOKUPFILE'
with open(path) as f:
    content = f.read()

pattern = r'(_emscripten_lookup_name\s*(?::|\s*=))'
m = re.search(pattern, content)
if m:
    pos = m.start()
    lines = content[:pos].split('\n')
    start = pos
    for j in range(len(lines)-1, max(len(lines)-5, -1), -1):
        line = lines[j].strip()
        if '_emscripten_lookup_name__' in line:
            start = len('\n'.join(lines[:j]))
            if start > 0: start += 1
        else:
            break

    guard_start = '\n#if !DIRECT_SOCKETS\n'
    rest = content[m.end():]
    brace_depth = 0
    found_opening = False
    end_offset = 0
    for ci, ch in enumerate(rest):
        if ch == '{':
            brace_depth += 1
            found_opening = True
        elif ch == '}':
            brace_depth -= 1
            if found_opening and brace_depth == 0:
                end_offset = m.end() + ci + 1
                break

    if end_offset > 0:
        tail = content[end_offset:]
        comma_pos = 0
        for ci, ch in enumerate(tail):
            if ch == ',':
                comma_pos = ci + 1
                break
            elif not ch.isspace() and ch != '\n':
                break

        guard_end_pos = end_offset + comma_pos
        guard_end = '\n#endif // !DIRECT_SOCKETS\n'
        content = content[:start] + guard_start + content[start:guard_end_pos] + guard_end + content[guard_end_pos:]

        with open(path, 'w') as f:
            f.write(content)
        print('  Guarded _emscripten_lookup_name in ' + path)
"
    fi
  fi
done

# 1i. Clear emscripten cache
rm -rf "$EMDIR/cache"
echo "  Cleared emscripten cache"

echo ""
echo "=== Phase 1 complete ==="

# ============================================================================
# PHASE 2: Build zlib for WASM
# ============================================================================
echo ""
echo "=== Phase 2: Building zlib ==="
echo ""

DEPSDIR="/deps"

cd "$BUILDDIR"
if [ ! -d zlib-1.3.2 ]; then
  tar xzf "$DEPSDIR/zlib-1.3.2.tar.gz"
fi
cd zlib-1.3.2
if [ ! -f "$PREFIX/lib/libz.a" ]; then
  emconfigure ./configure --prefix="$PREFIX" --static
  emmake make -j"$NPROC"
  emmake make install
  echo "  zlib built and installed"
else
  echo "  zlib already installed"
fi

# ============================================================================
# PHASE 3: Build OpenSSL for WASM
# ============================================================================
echo ""
echo "=== Phase 3: Building OpenSSL ==="
echo ""

cd "$BUILDDIR"
# Always rebuild OpenSSL from clean to avoid stale config
rm -rf openssl-1.1.1w
tar xzf "$DEPSDIR/openssl-1.1.1w.tar.gz"
cd openssl-1.1.1w

if true; then
  # Configure for generic 32-bit build with emscripten
  # threads is required by Tor - emscripten supports pthreads
  ./Configure linux-generic32 \
    --prefix="$PREFIX" \
    --openssldir="$PREFIX/ssl" \
    no-asm \
    no-shared \
    no-engine \
    no-hw \
    no-dso \
    no-afalgeng \
    no-async \
    no-ui-console \
    threads \
    -DOPENSSL_NO_SECURE_MEMORY \
    -DNO_SYSLOG \
    -DOPENSSL_NO_SPEED \
    -pthread \
    CC=emcc \
    CXX=em++ \
    AR=emar \
    RANLIB=emranlib

  # Fix Makefile: remove flags that break emscripten
  sed -i 's/-m32//g' Makefile
  sed -i 's/-ldl//g' Makefile
  sed -i 's/-lpthread//g' Makefile

  emmake make -j"$NPROC" build_libs 2>&1 | tail -5
  emmake make install_dev 2>&1 | tail -3
  echo "  OpenSSL built and installed"
else
  echo "  OpenSSL already installed"
fi

# ============================================================================
# PHASE 4: Build libevent for WASM
# ============================================================================
echo ""
echo "=== Phase 4: Building libevent ==="
echo ""

cd "$BUILDDIR"
rm -rf libevent-2.1.12-stable
tar xzf "$DEPSDIR/libevent-2.1.12-stable.tar.gz"
cd libevent-2.1.12-stable

if true; then
  mkdir -p build-wasm && cd build-wasm

  emcmake cmake .. \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_C_FLAGS="-pthread" \
    -DEVENT__DISABLE_OPENSSL=ON \
    -DEVENT__DISABLE_MBEDTLS=ON \
    -DEVENT__DISABLE_THREAD_SUPPORT=OFF \
    -DEVENT__DISABLE_BENCHMARK=ON \
    -DEVENT__DISABLE_TESTS=ON \
    -DEVENT__DISABLE_SAMPLES=ON \
    -DEVENT__DISABLE_REGRESS=ON \
    -DEVENT__DISABLE_DEBUG_MODE=ON \
    -DEVENT__LIBRARY_TYPE=STATIC \
    2>&1 | tail -10

  emmake make -j"$NPROC" 2>&1 | tail -5
  emmake make install 2>&1 | tail -3
  echo "  libevent built and installed"
else
  echo "  libevent already installed"
fi

# ============================================================================
# PHASE 5: Build Tor for WASM
# ============================================================================
echo ""
echo "=== Phase 5: Building Tor ==="
echo ""

cd "$BUILDDIR"
rm -rf tor-build
cp -r "$TOR_SRC" tor-build
cd tor-build

# Patch config.sub to recognize wasm32-emscripten
# Insert -emscripten) case before the *) catch-all error
sed -i '/^	\*)$/i\\t-emscripten*)\n\t\t;;' config.sub
echo "  Patched config.sub for wasm32-emscripten"

# Tor's configure needs lots of cross-compilation hints since it can't
# run test programs in WASM
export ac_cv_func_fork=no
export ac_cv_func_fork_works=no
export ac_cv_func_vfork=no
export ac_cv_func_vfork_works=no
export ac_cv_func_getifaddrs=no
export ac_cv_func_syslog=no
export ac_cv_func_daemon=no
export ac_cv_func_prctl=no
export ac_cv_func_sysconf=yes
export ac_cv_func_clock_gettime=yes
export ac_cv_func_getentropy=no
export ac_cv_func_getrandom=no
export ac_cv_func_explicit_bzero=yes
export ac_cv_func_timingsafe_memcmp=no
export ac_cv_func_memmem=yes
export ac_cv_func_usleep=yes
export ac_cv_func_pipe2=yes
export ac_cv_func_pipe=yes
export ac_cv_func_socketpair=yes
export ac_cv_func_accept4=yes
export ac_cv_func_strlcpy=no
export ac_cv_func_strlcat=no
export ac_cv_func_mach_approximate_time=no
export ac_cv_func_statvfs=no
export ac_cv_func_getrlimit=no
export ac_cv_func_setrlimit=no
export ac_cv_func_llround=yes
export ac_cv_func_lround=yes
export ac_cv_func_rint=yes
export ac_cv_func_isnan=yes

# Cross-compilation cache variables for struct member checks
export ac_cv_member_struct_timeval_tv_sec=yes
export ac_cv_member_struct_sockaddr_in6_sin6_len=no

# Library search cache — bypass AC_LINK_IFELSE which fails during cross-compile
export tor_cv_library_openssl_dir="$PREFIX"
export tor_cv_library_libevent_dir="$PREFIX"
export tor_cv_library_zlib_dir="$PREFIX"

# OpenSSL version check caches
export tor_cv_openssl_is_nss=no

# Tell configure we're cross-compiling to wasm32
# Use --host to trigger cross-compilation mode
emconfigure ./configure \
  --host=wasm32-unknown-emscripten \
  --build=$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu) \
  --disable-module-relay \
  --disable-module-dirauth \
  --disable-seccomp \
  --disable-libscrypt \
  --disable-systemd \
  --disable-lzma \
  --disable-zstd \
  --disable-tool-name-check \
  --disable-gcc-hardening \
  --disable-linker-hardening \
  --disable-unixdomain-sockets \
  --disable-asciidoc \
  --disable-manpage \
  --disable-html-manual \
  --enable-static-tor \
  --with-openssl-dir="$PREFIX" \
  --with-libevent-dir="$PREFIX" \
  --with-zlib-dir="$PREFIX" \
  --prefix="$PREFIX" \
  CFLAGS="-O2 -pthread -Wno-error" \
  CPPFLAGS="-I$PREFIX/include" \
  LDFLAGS="-L$PREFIX/lib -sDIRECT_SOCKETS -sJSPI -sPROXY_TO_PTHREAD -pthread -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=0 -sUSE_ZLIB=1 -sFORCE_FILESYSTEM=1 -sEXPORTED_RUNTIME_METHODS=FS -sTRUSTED_TYPES" \
  LIBS="-lssl -lcrypto -levent -lz" \
  2>&1

echo ""
echo "  Configure complete, fixing up for static WASM linking..."
echo ""

# Fix Makefile to use static libevent (configure may have found .so)
sed -i 's|/build/install/lib/libevent.so|/build/install/lib/libevent.a|g' Makefile
sed -i 's|/build/install/lib/libevent_core.so|/build/install/lib/libevent_core.a|g' Makefile
sed -i 's|/build/install/lib/libevent_extra.so|/build/install/lib/libevent_extra.a|g' Makefile
# Also remove -ldl and -lrt that don't exist in emscripten
sed -i 's/ -ldl//g' Makefile
sed -i 's/ -lrt//g' Makefile

# Fix autotools timestamps to prevent make from trying to regenerate.
# autoconf/automake are not available in the docker image.
# Order matters: sources first, then generated files (with increasing timestamps).
sleep 1
find . -name '*.am' -exec touch {} +
find . -name 'configure.ac' -exec touch {} +
find . -name 'acinclude.m4' -exec touch {} +
sleep 1
touch aclocal.m4
sleep 1
find . -name Makefile.in -exec touch {} +
touch configure
sleep 1
touch orconfig.h.in config.h.in 2>/dev/null || true
sleep 1
find . -name config.status -exec touch {} +
find . -name Makefile -exec touch {} +
find . -name orconfig.h -exec touch {} +
find . -name config.h -exec touch {} +

# Build Tor - may need patches for things that don't compile
emmake make -j"$NPROC" 2>&1 || {
  echo ""
  echo "  Build failed, attempting to diagnose..."
  emmake make -j1 2>&1 | tail -50
  exit 1
}

echo ""
echo "  Tor built successfully!"

# ============================================================================
# PHASE 6: Link final WASM binary
# ============================================================================
echo ""
echo "=== Phase 6: Linking final WASM ==="
echo ""

# Find the tor binary (it will be a .js file from emscripten)
if [ -f src/app/tor ]; then
  cp src/app/tor "$OUTDIR/tor.js"
  cp src/app/tor.wasm "$OUTDIR/tor.wasm" 2>/dev/null || true
  cp src/app/tor.worker.js "$OUTDIR/tor.worker.js" 2>/dev/null || true
  echo "  Copied tor.js + tor.wasm to output"
elif [ -f src/app/tor.js ]; then
  cp src/app/tor.js "$OUTDIR/tor.js"
  cp src/app/tor.wasm "$OUTDIR/tor.wasm" 2>/dev/null || true
  cp src/app/tor.worker.js "$OUTDIR/tor.worker.js" 2>/dev/null || true
  echo "  Copied tor.js + tor.wasm to output"
else
  echo "  WARNING: Could not find tor binary, looking for it..."
  find src/ -name "tor" -o -name "tor.js" -o -name "*.wasm" 2>/dev/null | head -20
fi

echo ""
echo "=== Build complete ==="
echo ""
ls -la "$OUTDIR/"
