FROM ubuntu:24.04

CMD bash

ARG build_type="RelWithDebInfo"

# Ubuntu 24.04 ships LLVM/Clang 18 in its default repositories.
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-suggests --no-install-recommends \
    autoconf automake autotools-dev libtool \
    clang-18 cmake git libgoogle-perftools-dev libprotobuf-dev llvm-18-dev make pkg-config protobuf-compiler wget libboost-dev libgdbm-dev \
    libz3-dev z3 \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    lldb-18 \
    tmux \
    less emacs-nox htop valgrind psmisc \
    unzip python3-setuptools bsdmainutils

ENV LLVM_DIR="/usr/lib/llvm-18"
ENV CC="/usr/bin/clang-18"
ENV CXX="/usr/bin/clang++-18"
ENV LCM_DIR="$HOME/clou"
ENV LCM_BUILD="$LCM_DIR/build"
ENV LCM_SCRIPTS="$LCM_DIR/scripts"
ENV SRC="$LCM_DIR"
RUN echo "export CMAKE_BUILD_PARALLEL_LEVEL=$(nproc)" >> ~/.bashrc

WORKDIR "$LCM_SCRIPTS"
COPY scripts/cloucc.sh .

# Set up dummy libclou.so
WORKDIR "$LCM_BUILD"
RUN mkdir -p src
RUN echo 'static int i;' > dummy.c
RUN clang-18 -shared -o src/libclou.so dummy.c
RUN rm -f dummy.c

# Loading the Clou pass into clang now uses the new PassManager plugin
# interface (LLVM >= 17 removed the legacy PassManagerBuilder extension points).
ENV CLOU_CFLAGS="-fpass-plugin=${LCM_BUILD}/src/libclou.so"

# Configure libsodium
RUN git clone --depth=1 https://github.com/jedisct1/libsodium.git libsodium
ENV LIBSODIUM_CPPFLAGS="-UHAVE_INLINE_ASM -UHAVE_EMMINTRIN_H -UHAVE_C_VARARRAYS -UHAVE_ALLOCA"
WORKDIR "$LCM_BUILD/libsodium"
RUN autoreconf -i
RUN ./configure --disable-asm CC="$LCM_SCRIPTS/cloucc.sh" CPPFLAGS="$LIBSODIUM_CPPFLAGS -g -Wno-cpp -fpass-plugin=$LCM_BUILD/src/libclou.so" CFLAGS="-O0" || ( cat config.log; exit 1)
RUN mkdir lcm

# Configure openssl
WORKDIR "$LCM_BUILD"
RUN git clone --depth=1 https://github.com/openssl/openssl.git openssl
WORKDIR openssl
RUN ./Configure CC="$LCM_SCRIPTS/cloucc.sh" CFLAGS="-g -fpass-plugin=$LCM_BUILD/src/libclou.so"
RUN mkdir lcm

RUN ulimit -c unlimited
RUN mkdir -p /tmp/cores

# Build lcm tool
WORKDIR "$LCM_BUILD"
COPY CMakeLists.txt $LCM_DIR/

ENV CXXFLAGS -fPIC
# Build with:
#   cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" -DCMAKE_CXX_FLAGS="-fPIC" ..
#   make -j$(nproc)
