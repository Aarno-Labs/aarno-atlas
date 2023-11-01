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

If the connection to the server is lost, qjs will attempt to reconnect.

The following output shows a disconnect and reconnect:
```
pi@pi1:~/$ ATLAS_HOME=`pwd` . ./atlas.sh
[2023/10/31-09:40:12.664] Call Encode
[2023/10/31-09:40:14.002] Done Encode
[2023/10/31-09:40:14.006] Call Encode
[2023/10/31-09:40:15.236] Done Encode
[2023/10/31-09:40:15.240] Call Encode
[2023/10/31-09:40:16.474] Done Encode
[2023/10/31-09:40:16.477] Call Encode
[2023/10/31 09:40:16.928] Connect attempt(1)
r_connect[1] failed sock_fd=9 -1 Connection refused
3057714240:error:1409E10F:SSL routines:ssl3_write_bytes:bad length:../ssl/record/rec_layer_s3.c:364:
[2023/10/31 09:40:17.936] Connect attempt(2)
r_connect[2] failed sock_fd=7 -1 Connection refused
[2023/10/31 09:40:18.943] Connect attempt(3)
r_connect[3] failed sock_fd=9 -1 Connection refused
[2023/10/31 09:40:19.953] Connect attempt(4)
r_connect[4] failed sock_fd=7 -1 Connection refused
[2023/10/31 09:40:20.960] Connect attempt(5)
r_connect[5] failed sock_fd=9 -1 Connection refused
[2023/10/31 09:40:21.971] Connect success(6)
[2023/10/31-09:40:23.380] Done Encode
[2023/10/31-09:40:23.383] Call Encode
[2023/10/31-09:40:24.621] Done Encode
...
```

The client attempts to reconnect for approximately 10 minutes.

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






