import * as std from "std";
import * as os from "os";
import atlas_scheduler from './atlas-scheduler.js';
import * as atlas_wrapper from './atlas-wrapper.js';
import {WorkersManager} from './workers-manager.js';
import atlas_tools from './atlas-tools.js';
import {stringify, parse} from './atlas-srl.js';
// import {atlas_battery, BatteryWorkers}  from './atlas-battery.js';
globalThis.os = os;
globalThis.std = std;
globalThis.atlas_tools = atlas_tools;
globalThis.stringify = stringify;
globalThis.parse = parse;
globalThis.file_to_exec = undefined;
globalThis.scaling = false;
globalThis.local_execution = false;
globalThis.interval = -1;
globalThis.wrapping_libs = false;
globalThis.log_name = undefined;
let number_of_servers = 0;
let number_of_workers = 0;

/*
 * the actual workers that currently can be used for scheduling
 */
globalThis.actual_workers = 1
/******************************/
/*     Setters and Getters    */
/******************************/
function get_server_count() {
    return number_of_servers;
}
function get_worker_count() {
    return number_of_workers;
}
function set_server_count(n) {
    number_of_servers = n
}
function set_worker_count(n) {
    number_of_workers = n
}

globalThis.get_server_count = get_server_count
globalThis.get_worker_count = get_worker_count
globalThis.set_server_count = set_server_count

function atlas_print(...str) {
    if (globalThis.log_name !== undefined) {
        var args = Array.prototype.slice.call(arguments);
        args.forEach(function(element) {
            log_file.printf("%s", element);
        }, this);
        log_file.printf("\n");
        log_file.flush();
    }
}

globalThis.atlas_print = atlas_print;


function print_usage_and_exit() {
    print("Usage: quickjs daemon.js --log --servers x --file input.js --offload offloads.txt\n" +
        "flags:\n" +
        "servers     \t Number of atlas node to use\n" + 
        "file        \t The source code to execute\n" +
        "server-file \t The file that contains the atlas nodes with ips\n" + 
        "offloads    \t File containing list of offloaded functions\n" + 
        "log         \t Write atlas execution logs to file\n" + 
        "remoteOnly  \t No local execution if remote fails\n" + 
        "reconnect   \t Number of reconnect attempts\n" + 
        "help        \t Show this usage message");
    std.exit(1)
}

function evaluate_args(opts) {
    if (opts["file"] !== undefined) {
        globalThis.file_to_exec = opts["file"]
    } else {
        print("Failed to provide the executable file, exiting")
        print_usage_and_exit();
    }

    // Map from file name to Set of offloaded functions
    globalThis.offload_funcs = new Map();
    if (opts.hasOwnProperty("local")) {
        globalThis.local_execution = true
    }
    if (opts["servers"] === undefined) {
        print("Set number of servers")
        print_usage_and_exit()
    }
    set_worker_count(parseInt(opts["servers"]))
    set_server_count(parseInt(opts["servers"]))
    if (opts.hasOwnProperty("scaling")) {
        globalThis.scaling = true
    } else {
        // since we are not using scaling, use all the workers without the local
        actual_workers = get_worker_count()
    }
    if (opts["server-file"] !== undefined)
        globalThis.server_file = opts["server-file"]
    else
        globalThis.server_file = "./atlas-addresses.txt"

    if(opts["offloads"] == undefined) {
        print("Error: Missing required argument 'offloads'.");
        print_usage_and_exit();
    }
    var func_file_stat = os.stat(opts["offloads"]);
    if(func_file_stat[1] != 0) {
        print(`[Error: (${func_file_stat[1]}) reading offloading file "${opts["funcs_file"]}"]`);
        std.exit(1);
    }
    
    // Create offload map [offload file]->[func name]->[func name, timeout]
    let offloads = JSON.parse(std.loadFile(opts["offloads"]));
    if (offloads === undefined || offloads === null) {
        print (`Error: failed to read offloads file "${opts['offloads']}."`);
        std.exit(1);
    }
    
    offloads.offloads.forEach((offload) => {
        let imports = globalThis.offload_funcs.get(offload.file);
        if (imports !== undefined) {
            print(`[WARNING: duplicate offload file ${offload.file}`);
        } else {
            imports = new Map();
            globalThis.offload_funcs.set(offload.file, imports);
        }
            
        offload.funcs.forEach((func) => {
            if (imports.has(func.name)) {
                print (`[WARNING duplicate entry ${func}]`);
            } else {
                imports.set(func.name, func);
            }
        });
    });

    if (opts["log"] !== undefined) {
        globalThis.log_name = opts["log"];
        globalThis.log_file = std.open(globalThis.log_name, 'w');
    }

    if (opts["battery"] !== undefined) {
        globalThis.battery = true;
    } else {
        globalThis.battery = false;
    }

    if (opts["remote-only"] != undefined) {
        globalThis.remoteOnly = true;
    } else {
        globalThis.remoteOnly = false;
    }

    if (opts["reconnect"] !== undefined) {
        globalThis.reconnect_attempts = parseInt(opts["reconnect"])
    } else {
        globalThis.reconnect_attempts = 5;
    }        

    if (opts["recWaitSec"] !== undefined) {
        globalThis.wait_sec = parseInt(opts["recWaitSec"])
    } else {
        globalThis.wait_sec = 1;
    }        

    //if (get_worker_count() != get_server_count() && local_execution == false) {
    //    print("Error, set more servers");
    //    print_usage_and_exit();
    //}
}

// parse the user arguments
const opts = atlas_tools.parse_args(scriptArgs)
globalThis.opts = opts
// evaluate the arguments
evaluate_args(opts)
// start the ticking clock
globalThis.gstart_time = atlas_tools.get_time();
/***********************************************/
/*      Initialize the atlas scheduler         */
/***********************************************/
globalThis.atlas_scheduler = atlas_scheduler
/***********************************************/
/*        Initialize atlas workers         */
/***********************************************/
let nodes = null;
if (local_execution == false) {
    nodes = atlas_scheduler.setup_servers(server_file)
}

/***********************************************/
/*        Initialize the atlas wrapper         */
/***********************************************/
globalThis.atlas_wrapper = atlas_wrapper

const servers_per_node =
      Math.floor(get_server_count() / get_worker_count());
const servers_remaining = get_server_count();

if(!globalThis.battery) {
    var workersManager = new WorkersManager(
        get_server_count(),
        get_worker_count(),
        servers_per_node,
        servers_remaining,
        nodes,
        globalThis.remoteOnly,
        globalThis.reconnect_attempts,
        globalThis.wait_sec
    );
} else {
    var workersManager = new BatteryWorkers(
        get_server_count(),
        get_worker_count(),
        servers_per_node,
        servers_remaining,
        nodes,
        globalThis.remoteOnly,
        globalThis.reconnect_attempts
    );
}
var aWrapper = new atlas_wrapper.AtlasWrapper(workersManager);
globalThis.aWrapper = aWrapper;

globalThis.wrapper = aWrapper.wrapObject.bind(aWrapper);

if (local_execution == false) {
    workersManager.spawn_workers();
} else {
    WorkersManager.execute_script()
    //atlas_tools.tidy_file();
}
