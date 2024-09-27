import sys
import argparse
import asyncio
import logging
import socket
from pathlib import Path
from asyncio import CancelledError

logging.basicConfig(
    level  = logging.DEBUG,
    format = '%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s() %(message)s')
logging.info("Starting Test")

parser = argparse.ArgumentParser(description='Test Require Offloading')
parser.add_argument('-a', '--atlas-home',
                    default = '..',
                    dest    = 'atlas_home',
                    help    = 'atlas home directory',
                    type    = str
                    )

parser.add_argument('-p', '--port',
                    default = 7000,
                    dest    = 'atlas_port',
                    help    = 'server port',
                    type    = int
                    )

parser.add_argument('-i', '--ip',
                    default = '192.168.0.22',
                    dest    = 'server_ip',
                    help    = 'server ip address',
                    type    = str
                    )


args = parser.parse_args()
logging.info(f'{args}')

# Use as a call be reference for the proc
class RequireProcess:
    def __init__(self):
        self.proc = None


async def StartServer(
        requireProcess,
        extra_server_args):
    cmd = f'./app'
    cmd_args = ['-p', str(args.atlas_port)] + extra_server_args
    logging.debug(f'[cmd_args={cmd_args}')
    worker_dir = Path(args.atlas_home) / 'atlas-worker'
    requireProcess.proc = await asyncio.create_subprocess_exec(
        cmd, *cmd_args,
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE,
        cwd    = worker_dir
    )
    logging.debug(f'[launched pid={requireProcess.proc.pid} cmd={cmd!r} worker_dir={worker_dir!r}]')

    stdout, stderr = await requireProcess.proc.communicate()
    logging.debug(f'[{cmd!r} exited with {requireProcess.proc.returncode}]')
    if stdout:
        logging.debug(f'[stdout]\n{stdout.decode()}')
    if stderr:
        logging.error(f'[stderr]\n{stderr.decode()}')


async def launch_client(script_offloads,
                        extra_client_args):
    logging.debug(f'[launch client]');
    atlas_qjs_cmd = Path(args.atlas_home) / 'atlas-qjs' / 'src' / 'qjs'
    atlas_client_dir = Path(args.atlas_home) / 'atlas-client'

    javascript_file, offloads_file = script_offloads

    client_cmd = [
        './atlas.js',
        '--file',
        javascript_file,
        '--offloads',
        offloads_file,
        '--servers',
        '1'] + extra_client_args
        # '--server-file',
        # atlas_address_file,
        # '--offloads',
        # offloads_file,

    logging.debug(" ".join([str(c) for c in client_cmd]));
    
    test_proc = await asyncio.create_subprocess_exec(
        atlas_qjs_cmd,
        *client_cmd,
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE,
        cwd    = atlas_client_dir
    )

    logging.debug(f'[launched pid={test_proc.pid}]')

    stdout, stderr = await test_proc.communicate()
    logging.debug(f'[qjs  exited with {test_proc.returncode}]')
    if stdout:
        logging.debug(f'[stdout]\n{stdout.decode()}')
    if stderr:
        logging.error(f'[stderr]\n{stderr.decode()}')

    return test_proc.returncode
    
        
async def test(
        atlas_address_file,
        script_offloads,
        extra_server_args,
        extra_client_args = []
):
    requireProcess = RequireProcess()
    
    task = asyncio.create_task(
        StartServer(
            requireProcess    = requireProcess,
            extra_server_args = extra_server_args
        )
    )

    time_elapsed = 0
    ip_port = (args.server_ip, args.atlas_port)

    connect_timeout_sec_ = 5
    while not task.done():
        time_elapsed += 1
        await asyncio.sleep(1)
        if time_elapsed == connect_timeout_sec_:
            logging.debug(f'Server start failed time_elapsed={time_elapsed} ip_port={ip_port}')
            logging.debug(f'killing {requireProcess.proc.pid}')
            requireProcess.proc.kill()
            logging.debug(f'kill await');
            await task
            logging.debug(f'kill done');
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
            try:
                logging.debug(f'Connecting ip_port={ip_port}')
                s1.connect(ip_port)
                logging.debug(f'Connected ip_port={ip_port}')
                break
            except ConnectionRefusedError:
                logging.debug(f'Connection refused time_elapsed={time_elapsed} ip_port={ip_port}')

    
    logging.debug(f'[launch client]');
    atlas_qjs_cmd = Path(args.atlas_home) / 'atlas-qjs' / 'src' / 'qjs'
    atlas_client_dir = Path(args.atlas_home) / 'atlas-client'
    logging.debug(f'atlas_address_file={atlas_address_file}');

    networked_args = list(extra_client_args)
    networked_args.extend(['--server-file', atlas_address_file])

    client_result = await launch_client(
        script_offloads = script_offloads,
        extra_client_args = networked_args)

    logging.debug(f'killing {requireProcess.proc.pid}')
    requireProcess.proc.terminate()
    logging.debug(f'kill await');
    await requireProcess.proc.wait()
    logging.debug(f'kill done');
    return client_result


PASSED_ = 'PASSED'
FAILED_ = 'FAILED'


def return_code_str(return_code):
    if return_code == 0:
        return PASSED_
    return FAILED_


async def run_tests():

    targets = [
        ('benchmarks/tests/run-global-this-get.js',
         'benchmarks/tests/offloads/require-offloads.global-this-get.txt'),
        ('benchmarks/tests/run-global-this-set.js',
         'benchmarks/tests/offloads/require-offloads.global-this-set.txt'),
        ('benchmarks/exceptions/run-exception.js',
         'benchmarks/exceptions/exception-offloads.txt'),
        ('benchmarks/tests/run-simple-function.js',
         'benchmarks/tests/require-offload.simple.txt'),
        ('benchmarks/math/run.js',
         'benchmarks/math/aarno-offload-funcs.math.txt'),
        ('benchmarks/crypto_benchmark/single-sign-encrypt.js',
         'benchmarks/crypto_benchmark/single-offload-funcs.crypto.txt'),
        ('benchmarks/crypto_benchmark/run.js',
         'benchmarks/crypto_benchmark/aarno-offload-funcs.crypto.txt'),
        ]

    all_passed = 0

    # get on globalThis in remote-only will fail
    global_get_remote_only = await test(
        atlas_address_file = './address-files/atlas-addresses.unencrypted.txt',
        script_offloads    = targets[0],
        extra_server_args  = ["-u"], 
        extra_client_args = ['--remote-only']
    )
    
    logging.info(f'TEST: {targets[0][0]} {return_code_str(not global_get_remote_only)}')

    # Should fail
    all_passed = all_passed | (not global_get_remote_only)

    # set on globalThis in remote-only will fail
    global_set_remote_only = await test(
        atlas_address_file = './address-files/atlas-addresses.unencrypted.txt',
        script_offloads    = targets[1],
        extra_server_args  = ["-u"], 
        extra_client_args = ['--remote-only']
    )

    # Should fail
    all_passed = all_passed | (not global_set_remote_only)
    logging.info(f'TEST: {targets[0][0]} {return_code_str(not global_set_remote_only)}')

    for target in targets:
        logging.info(f'TEST:local {target[0]}')
        local_result = await launch_client(
            script_offloads   = target,
            extra_client_args = ['--local']
        )
        logging.info(f'TEST:local {return_code_str(local_result)}')
        all_passed = all_passed | local_result

        unencypted_result = await test(
            atlas_address_file = './address-files/atlas-addresses.unencrypted.txt',
            script_offloads    = target,
            extra_server_args  = ["-u"]
        )

        logging.info(f'TEST:unencrypted {return_code_str(unencypted_result)}')
        all_passed = all_passed | unencypted_result

        ssl_verify = await test(
            atlas_address_file = './address-files/atlas-addresses.ssl-verify.txt',
            script_offloads    = target,
            extra_server_args  = "-s -k /home/elahtinen/certificates/self-sign.key -c /home/elahtinen/certificates/self-sign.crt".split()
        )
        logging.info(f'TEST:ssl-verify {return_code_str(ssl_verify)}')
        all_passed = all_passed | ssl_verify
    
        ssl_no_verify = await test(
            atlas_address_file = './address-files/atlas-addresses.ssl-no-verify.txt',
            script_offloads    = target,
            extra_server_args  = "-s -k /home/elahtinen/certificates/self-sign.key -c /home/elahtinen/certificates/self-sign.crt".split()
        )
        logging.info(f'TEST:ssl-no-verify {return_code_str(ssl_no_verify)}')

    logging.info(f'TEST:all_passed {all_passed} {return_code_str(all_passed)}')
    return all_passed


    
all_passed = asyncio.run(run_tests())
logging.info(f'ALL: {return_code_str(all_passed)}')
sys.exit(all_passed)
    
