#!/bin/bash

echo 'Starting firewall'
SEDIMENT=/root/atlas/ra /root/atlas/ra/build-x86/firewall -l -k /root/certs/key.pem -c /root/certs/cert.pem > /root/logs/firewall.log 2>&1 &

echo 'Starting verifier'
SEDIMENT=/root/atlas/ra /root/atlas/ra/build-x86/verifier -l -k /root/certs/key.pem -c /root/certs/cert.pem > /root/logs/verifier.log 2>&1 &

echo 'Starting simple-server'
# cd /root/atlas/atlas-worker && /root/atlas/atlas-worker/simple/simple-x86/simple-server -s 7000 -k /root/certs/key.pem -c /root/certs/cert.pem -f 192.168.0.22:8000 > /root/logs/simple-server.log 2>&1 &
cd /root/atlas/atlas-worker && /root/atlas/atlas-worker/simple/simple-x86/simple-server -s 7000 -k /root/certs/key.pem -c /root/certs/cert.pem -f 192.168.0.22:8000 > /root/logs/simple-server.log 2>&1 &

echo 'All servers starting. Waiting'

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
