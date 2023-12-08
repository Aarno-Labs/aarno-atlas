# Aarno Labs Atlas Client
This document describes how to install and run the Aarno Labs Atlas client.


## Quick Start

Clone this repository to your Raspberry Pi:

```
git clone ######replaceme########
```

Set the environment `ATLAS_HOME` to the location of the repository:

```
export ATLAS_HOME=/home/pi/aarno-atlas
```

The device needs access to `128.30.84.160` (ports 7000, 8000, and 8100).


The script `atlas.sh` executes the offloading script:


The script runs a JavaScript script, creating a JPEG from raw image data.

Atlas offloads the image creation to the remote server.

Here is a sample output:

```
pi@pi1:~/$ ATLAS_HOME=`pwd` . ./atlas.sh
[2023/10/31-09:21:37.702] Call Encode
[2023/10/31-09:21:39.117] Done Encode
[2023/10/31-09:21:39.121] Call Encode
[2023/10/31-09:21:40.376] Done Encode
[2023/10/31-09:21:40.378] Call Encode
[2023/10/31-09:21:41.707] Done Encode
[2023/10/31-09:21:41.711] Call Encode
[2023/10/31-09:21:42.986] Done Encode
[2023/10/31-09:21:42.989] Call Encode
[2023/10/31-09:21:44.335] Done Encode
...
```

`Call Encode` indicates the image creation has been sent to the server.

`Done Encode` indicates the new image  has been received by the client.

If the connection to the server is lost, qjs run the computation locally.

If connection to the server is established, it will offload computations again.

The following output shows a disconnect, local execution and reconnect:
```
pi@pi1:~/$ ATLAS_HOME=`pwd` . ./atlas.sh
[2023/12/08-10:19:09.563] Call Encode
[2023/12/08-10:19:10.548] Done Encode
[2023/12/08-10:19:10.550] Call Encode
[2023/12/08-10:19:11.541] Done Encode
[2023/12/08-10:19:11.543] Call Encode
[2023/12/8 10:19:12.510] Connect attempt(1) old_fd=7, new_fd=9
r_connect[1] failed sock_fd=9 -1 Connection refused
Failed to connect to server: 192.168.0.22:7000
connection failed
[2023/12/08-10:20:09.195] Done Encode
[2023/12/08-10:20:09.206] Call Encode
[2023/12/8 10:20:09.489] Connect attempt(1) old_fd=7, new_fd=9
r_connect[1] failed sock_fd=9 -1 Connection refused
Failed to connect to server: 192.168.0.22:7000
[2023/12/08-10:21:04.796] Done Encode
[2023/12/08-10:21:04.798] Call Encode
[2023/12/8 10:21:04.978] Connect attempt(1) old_fd=7, new_fd=9
r_connect[1] failed sock_fd=9 -1 Connection refused
Failed to connect to server: 192.168.0.22:7000
[2023/12/08-10:21:59.726] Done Encode
[2023/12/08-10:21:59.729] Call Encode
[2023/12/08-10:22:01.388] Done Encode
...
```

The client attempts to reconnect for approximately 10 minutes.

Passing `-r` to `atlas.sh` enables remote only execution, which will not run computations locally if the connection to the server is lost.

Passing `-v` to `atlas.sh` provides verbose output.

This example sets `ATLAS_HOME` on the command line and uses `--` to pass arguments to `atlas.sh`.
```
ATLAS_HOME=`pwd` . ./atlas.sh -- -v
```

# Further Information
The following provides more information on the Atlas offloading system but it not required to run the system.

## Components

The Atlas client consists of 4 components.

- qjs executable
- Atlas JavaScript
- benchmark javascript files
- Certificate (for ssl)


## qjs
[qjs](https://bellard.org/quickjs/) is a JavaScript interpreter binary that has been modified to support offloading.

It is (statically) compiled for `armv6-rpi-linux-gnueabihf`.

It has been tested on a `Raspberry Pi Zero W Rev 1.1` with the following kernel.

```
pi@pi1:~$ uname -a
Linux pi1 5.10.63+ #1457 Tue Sep 28 11:24:51 BST 2021 armv6l GNU/Linux
```

The script `atlas.sh` is provided to execute the `qjs` as its configuration is complicated.

## JavaScript Files

The directory `atlas-client` contains the Atlas JavaScript files.

They interact with the client JavaScript script to offload its computation.

In addition to the Atlas JavaScript files, benchmark client files are provided.

This demonstration uses the files found in `benchmarks/jimp-npm`.

Other benchmark client require in the installation of npm packages.

## Certificate

The `qjs` uses the self-signed `cert.pem` certificate for SSL communication with the server.

`qjs` directly loads the certificate, it doesn't need to be installed in the system.
