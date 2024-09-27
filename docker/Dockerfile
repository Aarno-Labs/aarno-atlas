FROM ubuntu:20.04

RUN apt update && DEBIAN_FRONTEND=noninteractive TZ=America/New_York apt-get install gcc g++ gperf bison flex texinfo help2man make libncurses5-dev python3-dev autoconf automake libtool libtool-bin gawk wget bzip2 xz-utils unzip patch libstdc++6 rsync git meson ninja-build libsqlite3-dev cmake systemctl -y

WORKDIR /root

RUN git clone https://github.com/crosstool-ng/crosstool-ng

WORKDIR /root/crosstool-ng
RUN git checkout crosstool-ng-1.25.0
COPY atlas/docker/config /root/crosstool-ng/.config
RUN ./bootstrap
RUN ./configure --enable-local
RUN make -j 6
COPY atlas/docker/glibc.sh /root/crosstool-ng/scripts/build/libc/glibc.sh
RUN ./ct-ng build
RUN rm -rf .build

WORKDIR /root/

COPY aarno-atlas/ /root/atlas/
WORKDIR /root/atlas
#RUN git clone https://github.com/sparkly9399/SGX-OpenSSL.git
ADD https://github.com/sparkly9399/SGX-OpenSSL.git /root/atlas/SGX-OpenSSL
# RUN git clone --verbose  --recurse-submodules git@github.com:Aarno-Labs/atlas.git

ENV ATLAS_HOME=/root/atlas

WORKDIR $ATLAS_HOME/ra

WORKDIR $ATLAS_HOME/ra/build-x86

RUN cmake -G Ninja ..
RUN ninja

WORKDIR $ATLAS_HOME/atlas-worker/simple
RUN mkdir simple-x86  

WORKDIR $ATLAS_HOME/atlas-worker/simple/simple-x86
RUN cmake -DRA_BUILD=$ATLAS_HOME/ra/build-x86 -G Ninja ..

RUN ninja

RUN mkdir /root/atlas/atlas-qjs/src/build-rpi
WORKDIR /root/atlas/atlas-qjs/src/build-rpi
ENV PATH=/root/x-tools/armv6-rpi-linux-gnueabihf/bin:$PATH
RUN cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=/root/atlas/atlas-qjs/x-compile/armv6-rpi-linux-gnueabihf.cmake ..
RUN ninja

RUN mkdir -p /root/out/servers
RUN cp /root/atlas/atlas-worker/simple/simple-x86/simple-server /root/out/servers
RUN cp /root/atlas/atlas-worker/evaluator.js /root/out/servers/

RUN mkdir /root/out/client
RUN cp /root/atlas/atlas-qjs/src/build-rpi/qjs /root/out/client/
RUN cp -r /root/atlas/atlas-client /root/out/client/



# # ENV SEDIMENT=/root/atlas/ra

# # COPY sediment.db $SEDIMENT/data
# # COPY qjs /root/atlas/ra/data/testfiles/rpi
# # RUN mkdir /root/logs

# # COPY run-servers.sh /root/run-servers.sh
# # RUN chmod +x /root/run-servers.sh

# # CMD /root/run-servers.sh
