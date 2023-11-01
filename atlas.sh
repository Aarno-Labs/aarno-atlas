#! /bin/sh
# This script runs the atlas offloading system to off load jpeg file creation

# default logging is 4
log_level=4


# check for verbose mode
while getopts ":v" flag
do
    case "${flag}" in
        v) log_level=7;;
    esac
done

# run from the atlas home directory
(cd $ATLAS_HOME; ./qjs -l $log_level -s -c ./RPI-001 ./atlas.js --file benchmarks/jimp-npm/read_raw.js --offloads benchmarks/jimp-npm/require-jimp-offload.txt --servers 1 --server-file address-files/atlas-addresses.ssl-no-verify.txt --remote-only --reconnect 300 --recWaitSec 2)
