import * as std from 'std';
import * as os from "os";

import {WorkersManager} from './workers-manager.js';

/*
 * Return battery statistics for laptops and android aarch64 devices (using dumpsys)
 * If not available return -1;
 */
function get_battery() {
    let arch = std.popen("uname -m", "r");
    let arch_var = arch.getline()
    /* x86 handling */
    if (arch_var == "x86_64") {
        // laptops
        let power_sup = std.loadFile("/sys/class/power_supply/BAT0/capacity")
        if (power_sup === null)
            return -1;
        power_val = power_sup.getline();
        return parseFloat(power_val.getline())
    } else if (arch_var == "aarch64") {
        /* maybe something different for android ? like /sys/class/power_supply/capacity? */
        let cmd = "/system/bin/dumpsys battery"
        var prog = std.popen(cmd, "r");
        let data = []
        let r ;
        while (( r = prog.getline()) != null) {
            data.push(r.trim(" "))
        }
        prog.close(prog)
        // the hashmap that will store all the information with battery stas
        const battery_stats = new Map();
        // extract battery statistics from the android devices
        for (let i = 1; i < data.length; i++) {
            let item = data[i]
            let kv = item.split(": ")
            battery_stats[kv[0]] = kv[1]
        }
        r = parseFloat(battery_stats["level"])
        if (r > 100)
            r = 100
        return r
    } else {
        let cmd = "python3 battery_waveshare.py"
        var prog = std.popen(cmd, "r");
        let result = prog.getline().split();
        if (isNaN(result)) {
            // try the sugarpi server
            let cmd = "bash get_battery.sh"
            var prog = std.popen(cmd, "r");
            result = prog.getline().split(' ')[1]
        }
        // convert the string to float
        var r = parseFloat(result)
        // overcharge ? set to 100
        if (r > 100) 
            r = 100
        return r
    }
}

function get_battery_diff(start) {
    let end = get_battery();
    if (start == -1)
        return -1
    else
        return (start + '->' + end + ':' +Math.abs(end - start))
}

export var atlas_battery = {}
atlas_battery.battery = get_battery;
atlas_battery.get_battery_diff = get_battery_diff
export default atlas_battery;

// globalThis.bat_start = get_battery()

export class BatteryWorkers extends WorkersManager {
    constructor(server_count,
                worker_count,
                servers_per_node,
                servers_remaining,
                remoteOnly,
                reconnect_attempts) {
        super(server_count,
              worker_count,
              servers_per_node,
              servers_remaining,
              remoteOnly,
              reconnect_attempts);
        if (bat_start !== -1) {
            atlas_print("#Start Battery:", bat_start)
        }

    }

    write_worker_results(e) {
        // count how many entries of each function we have received
        this.atlas_increase_function_count(e.func);
        let b = -1;
        if (globalThis.bat_start !== -1)
            b = get_battery()
        atlas_print(e.started + '\t' + e.duration + '\t' + e.latency + '\t' + e.buffer_size + '\t' + e.interval+  '\t' + e.return  + '\t' + e.mode + '\t' + e.tid + '\t' + e.type + '\t' + e.func + '\t' + e.req_id + '\t' + b)
        /* 
         * if the type is not distibuted, don't count it as received, since its used
         * as initialization of the enclave nodes
         */
        this.pkt_received++
    }

    update_onmessage_resolvers(worker) {
        worker.onmessage = (e) => {
            this.write_worker_results(e.data.values);
            // resolve the value
            this.resolvers[e.data.values.req_id](e.data.values.data);
        }
    }
}
