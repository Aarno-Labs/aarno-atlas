#! /bin/sh
# This script runs the atlas offloading system to off load jpeg file creation

# default logging is 4
log_level=4

remote_only=""
reconnect=1
wait_sec=2

usage="$(basename "$0") [-h] [-r] [-t attempts] [-w seconds] [-v]

where:
    -h           show this help text
    -r           enable remote only execution
    -t attempts  number of reconnect attempts (default: 1)
    -w seconds   time to wait between attempts (default: 2 seconds)
    -v           enable verbose logging"


# check for verbose mode
while getopts "t:w::vrh" flag
do
    case "${flag}" in
        v) log_level=7;;
        r) remote_only="--remote-only";;
        t) reconnect="$OPTARG";;
        w) wait_sec="$OPTARG";;
        h) echo "$usage"
           exit
           ;;
    esac
done

# run from the atlas home directory
(cd $ATLAS_HOME; ./qjs -l $log_level -s -c ./RPI-001 ./atlas.js --file benchmarks/jimp-npm/read_raw.js --offloads benchmarks/jimp-npm/require-jimp-offload.txt --servers 1 --server-file address-files/atlas-addresses.ssl-no-verify.txt $remote_only --reconnect $reconnect --recWaitSec $wait_sec)
