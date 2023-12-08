import atlas_tools from './atlas-tools.js';
import * as std from 'std';
import * as os from 'os';

// let Nodes = new Map();
var id = 0
var current_node = 0

/*
 * 1. Parse the atlas configuration file and read all the pairs of servers with their ports
 * 2. Connect to each of the available servers and establish secure e2e communication
 * using public/private key.
 * 3. Exchange encryption keys
 * 4. Encrypt data using the encryption keys
 */ 
function setup_servers(server_file) {
    id = 0
    var nodes = [];
    /* parse the server file */
    const addresses = std.loadFile(server_file);
    if(addresses.length) { 
        let s = addresses.split('\n').
            forEach((s) => {
                // FIXME: add a flag to check if we surpass the number of workers
                if (id == get_server_count()) {
                    return ;
                } else if (s === '') {
                    print("Add more servers to atlas-addresses.txt")
                    std.exit(1)
                }
              //  const socket = atlas.socket();  
                const ID = id;
                const info = s.split(' ');
                const port = info[0];
                const ip = info[1];
                const ssl = info[2];
                const verify = info[3];
                const cert = info[4];
                var node = {
                    port      : port,
                    ip        : ip,
                    c_idx     : -1,
                    id        : ID,
                    nonce     : 0,
                    port      : port,
                    ssl       : ssl,
                    verify    : verify,
                    cert      : cert,
                    connected : false
                };
                id++;
                nodes.push(node);
                // atlas.send_pubkey(socket)
                // atlas.recv_pubkey(socket);
                // atlas.recv_encryption_key(socket)
            });
    }
    return nodes;
}

/*
 * Get a server node to schedule
 */
const getNode = () => {
    const currNode = Nodes[current_node%id]
    const info = Nodes[currNode.id]; 
    current_node++;
    return currNode;
}

/*
 * Close all pending server connections
 */
function close_sockets() {
    for (let i in Nodes)  {
        atlas.close(Nodes[i].socket)
    }
}

/*
 * This function will be called when create_traffic or traffic_int end their execution
 */
function atlas_finalize() {
    atlas_print("#Time: " +  atlas_tools.get_time_diff(atlas_tools.get_time(), globalThis.gstart_time))
    let bat_diff = globalThis.atlas_battery.get_battery_diff(globalThis.bat_start)
    if (bat_diff !== -1) {
        atlas_print("#Battery Diff:", bat_diff)
    }
    std.exit(0)
}

/*
 * Functionality for scheduling packets on different intervals
 */
let found = 0
export function create_traffic(func, ...args) {
    os.setTimeout(function() {
        func(...args);
        create_traffic(func, ...args);
    }, interval);

    //n = atlas_tools.get_time_diff(atlas_tools.get_time(), t)
    if (globalThis.atlas_wrapper.pkt_received >= 120) {
        atlas_finalize()
    }
    if (globalThis.atlas_wrapper.pkt_sent < 10 && found == 0) {
        found = 1
        interval = 800;
    } else if (globalThis.atlas_wrapper.pkt_sent > 10 && pkt_sent < 25 && found == 1) {
        interval = 700;
        found = 2
    } else if (globalThis.atlas_wrapper.pkt_sent > 25 && pkt_sent < 55 && found == 2) {
        interval = 400;
        found = 3;
    } else if (globalThis.atlas_wrapper.pkt_sent > 55 && pkt_sent < 80 && found == 3) {
        interval = 200;
        found = 4
    } else if (globalThis.atlas_wrapper.pkt_sent > 80 && pkt_sent < 100 && found == 4) {
        interval = 500;
        found = 5
    } else if (globalThis.atlas_wrapper.pkt_sent > 100 && pkt_sent < 120 && found == 5) {
        interval = 900;
        found = 6
    }
}

/*
 * Generate Burst traffic
 */
export function scaleout_traffic(func, args) {
    traffic_int()
    for (let j = 0; j < 50; j++) {
        func(args)
    }
}

function traffic_int() {
    if (received >= 50) {
        atlas_finalize()
    }
    os.setTimeout(function() {
        traffic_int()
    }, 100);
}

function demo_setup() {
    globalThis.t = atlas_tools.get_time()
    globalThis.n = 0
    globalThis.stop = 0
    globalThis.interval = 800
    globalThis.exec_time = 500
}

globalThis.create_traffic = create_traffic
globalThis.scaleout_traffic = scaleout_traffic
globalThis.atlas_finalize = atlas_finalize
let atlas_scheduler = {};
atlas_scheduler.getNode = getNode;
atlas_scheduler.close_sockets = close_sockets
atlas_scheduler.setup_servers = setup_servers;
export default atlas_scheduler;
