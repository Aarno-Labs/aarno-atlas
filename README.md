This document is an overview on using the Atlas system.

## Docker Build

Assuming repo was cloned into `aarno-atlas` command will build the docker image containing the server and client.

This build may take over ten minutes.

```
docker build -t atlas-servers --progress=plain -f aarno-atlas/docker/Dockerfile .
```

This creates the images `atlas-servers`.

## Simple Server

The simple server is the easiest to run. Use the following command to copy the simple server out of an atlas-server container.
Note docker requires that this files be copied out owned by root. They will run fine.

```
/usr/bin/docker run --rm -v .:/host atlas-servers cp -r /root/out/ /host.
```

The command will run the simple server accepting unecrypted traffic. The server must be run from the `out/servers` directory:

```
cd out/servers && ./simple-server -p 7000
```

## Client
The directory `out/client` hold the client.

The server's address is in this file `.../out/client/atlas-client/address-files/atlas-addresses.unencrypted.txt`.

It needs to be updated with the your server's address.

```
7000 192.168.0.22 unencrypted
```

Copy the entire client directory the target device. Here is an example command:

```
scp -r aarno@192.168.0.23:/home/elahtinen/public-atlas/out/client .
```

This command runs a simple offloading from the `client` directory:

```
../qjs ./atlas.js --file benchmarks/math/run.js --offloads benchmarks/math/aarno-offload-funcs.math.txt --servers 1 --server-file address-files/atlas-addresses.unencrypted.txt
```

Here is a sample output:

```
[2024/09/27-10:17:18.978] REMOTE
[2024/09/27-10:17:19.004] REMOTE
[2024/09/27-10:17:19.017] REMOTE
>> add true 46
>> div true Infinity
>> mul true 5
>> all_passed = 1

```

This command offloads JPEG compression:

```
../qjs --unhandled-rejection ./atlas.js --file benchmarks/jimp-npm/boston_raw.js --offloads benchmarks/jimp-npm/require-boston-offload.json --servers 1 --server-file address-files/atlas-addresses.unencrypted.txt
```

It will write a small jpeg file to `/tmp/j.jpg`. Here is the output from a sample run:

```
[pi@pi2 ~/public/client/atlas-client]$ ../qjs --unhandled-rejection ./atlas.js --file benchmarks/jimp-npm/boston_raw.js --offloads benchmarks/jimp-npm/require-boston-offload.json --servers 1 --server-file address-files/atlas-addresses.unencrypted.txt 
[2024/09/27-13:30:44.429] Call Encode
[2024/09/27-13:30:44.431] REMOTE
[2024/09/27-13:30:44.677] Done Encode
```



