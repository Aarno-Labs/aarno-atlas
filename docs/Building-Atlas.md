# Building Atlas
This document describes how to build the Atlas offloading system.

## Infrastructure System

The system is divided into three parts: server, qjs and SEDIMENT (also know as ra).

The first is the Atlas offloading server (written in C++). There are two types offloading servers: an enclave enabled server that runs in a SGX enclave and simple-server that runs outside a enclave (just like any other executable). The SGX server must be built for x86-64 with the special enclave compiler. The simple-server may run on any architecture, but defaults to x86-64. Each offloading server needs to link against the SEDIMENT libraries and qjs libraries. qjs is a Javascript interpreter; the client is a standalone version of qjs (whose binary is called qjs), while the server links the Javascript qjs interpeter as a library. 

Next is the quick javascript interpeter: qjs. qjs is written in C. By default qjs runs on a raspberry pi which is an ARM32 architecture. qjs is built by cross-compiling as building directly on the raspberry pie can take 15-20 minues. It needs to link against the SEDIMENT C++ libraries.

The final infrastructure component is the SEDIMENT remote attestation servers and libraries. The firewall and verifier servers are independent processes. Although they may run on any architecture by default they are built for x86-64. They do not link against any other components.

All executables are linked against two other libraries: MbedTLS and OpenSSL. Each library must be built for the executable's architecture.


## Building x86-64 Components

This command will set up the minimum required develop environment (remove sudo for a docker container)

```
sudo apt update && DEBIAN_FRONTEND=noninteractive TZ=America/New_York sudo apt-get install -y gcc g++ gperf bison flex texinfo help2man make libncurses5-dev python3-dev autoconf automake libtool libtool-bin gawk wget bzip2 xz-utils unzip patch libstdc++6 rsync git meson ninja-build -y
```

Next clone the atlas repo (make sure to give ssh access to github). The remote-attestation repo is a submodule of the main atlas repo.

```
git clone --recurse-submodules git@github.com:Aarno-Labs/atlas.git
```

Set the ATLAS_HOME environment variable to the directory where Atlas will be built.

```
export ATLAS_HOME=/root/atlas
```

In ra repo build the `firewall`, `verifier` executables (x86-64) and the ra libraries.

```
cd $ATLAS_HOME/ra && mkdir build-x86 && cd build-x86 && cmake .. && make -j 8
```

The server binaries will be located at:
```
$ATLAS_HOME/ra/build-x86/firewall
$ATLAS_HOME/ra/build-x86/verifier
```

Two SEDIMENT libraries are built:
```
$ATLAS_HOME/ra/build-x86/libprotocol.a
$ATLAS_HOME/ra/build-x86/ra.a
```

The three mbedtls (x86-64) libraries are built:
```
$ATLAS_HOME/ra/build-x86/build/mbedtls-build/lib/libmbedtls.a
$ATLAS_HOME/ra/build-x86/build/mbedtls-build/lib/libmbedx509.a
$ATLAS_HOME/ra/build-x86/build/mbedtls-build/lib/libmbedcrypto.a
```

Finally two ssl (x86-64) libraries are built:
```
$ATLAS_HOME/ra/build-x86/openssl/lib/libssl.a
$ATLAS_HOME/ra/build-x86/openssl/lib/libcrypto.a
```

Now build the `simple-server` (using the previous x86-64 libraries)

```
cd $ATLAS_HOME/atlas-worker/simple && mkdir simple-x86 && cd simple-x86 && cmake -DRA_BUILD=$ATLAS_HOME/ra/build-x86 .. && make -j 8
```

The simple server is found at:

```
$ATLAS_HOME/atlas-worker/simple/simple-x86/simple-server
```


## Building the qjs for ARM32

Install the [cross compile toolchain](#building-cross-compile-toolchain) for the raspberry pi.

The follow command assume you have installed the toolchain to `$ATLAS_HOME/armv6-rpi-linux-gnueabihf`

Now build qjs (`$ATLAS_HOME/atlas-qjs/src/build-rpi/qjs`):

```
cd $ATLAS_HOME/atlas-qjs/src && mkdir build-rpi && cd build-rpi && PATH=$ATLAS_HOME/armv6-rpi-linux-gnueabihf/bin:$PATH cmake -DCMAKE_TOOLCHAIN_FILE=$ATLAS_HOME/atlas-qjs/x-compile/armv6-rpi-linux-gnueabihf.cmake .. && PATH=$ATLAS_HOME/armv6-rpi-linux-gnueabihf/bin:$PATH make -j 8 qjs
```

The `qjs` executable will be in

```
$ATLAS_HOME/atlas-qjs/src/build-rpi/qjs
```

The various mbedtls, openssl and ra arm32 libraries are in the following locations. They are statically linked in so they are not required to execute qjs.

```
$ATLAS_HOME/atlas-qjs/src/build-rpi/build/mbedtls-build/library/libmbedcrypto.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/build/mbedtls-build/library/libmbedx509.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/build/mbedtls-build/library/libmbedtls.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/ra/librpi.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/ra/libprotocol.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/openssl/lib/libcrypto.a
$ATLAS_HOME/atlas-qjs/src/build-rpi/openssl/lib/libssl.a
```

## Building Cross Compile Toolchain

This section describes how to build the cross compile toolchain arm raspberry pi (armv6)

First clone the cross-tools ng repo
```
git clone https://github.com/crosstool-ng/crosstool-ng
```

This guide is tested on `crosstool-ng-1.25.0`, so checkout it out
```
git checkout crosstool-ng-1.25.0
```

Run boostrap:
```
./bootstrap
```

Configure the build systems makefile
```
./configure --enable-local
```

Make the build system (set your own job number)
```
make -j 12
```

Copy this [config](https://github.com/Aarno-Labs/atlas/blob/master/docs/config) file to `.config` in the crosstool-ng directory (**Note `.` in the name of the local file**)

The cross-ng requires a slight patch to build the old kernel with a newer gcc. Copy this file [glibc.sh](https://github.com/Aarno-Labs/atlas/blob/master/docs/glibc.sh) to `.../crosstool-ng/scripts/build/libc/glibc.sh`.


Now do the build (this will probably take over 10 minutes)
```
ct-ng build
```

Default the toolchain will be written to `~/x-tools/armv6-rpi-linux-gnueabihf`.
