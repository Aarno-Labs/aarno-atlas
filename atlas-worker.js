import * as std from "std";
import * as os from "os";
import atlas_tools from './atlas-tools.js';
import {stringify, parse} from './atlas-srl.js'
// the current server id we are using
let current_server = 0
// the number of servers the thread may control
let server_count = 0
// thread id
let tid = -1
// nonce for avoiding replay attacks
let nonce = 0
// the results from the async execs
let promise_results = []
// the tasks that need to be executed on this thread
let worker_tasks = []

let server = null;
let server_info = null;

/*
 * Craft the atlas response packet for local/remote
 */
function craft_response(send_start, fulfill, worker_res, msg, mode) {
    let result = {}
    // console.log(`altas-worker.js:25`);
    let duration = atlas_tools.get_time_diff(atlas_tools.get_time(), send_start);
    // console.log(`altas-worker.js:27`);
    let latency = atlas_tools.get_time_diff(atlas_tools.get_time(), msg.issued_time);
    // console.log(`altas-worker.js:27a`);
    result.data = worker_res
    result.duration = duration
    result.latency = latency
    // console.log(`altas-worker.js:31`);
    result.started = atlas_tools.get_time_diff(msg.issued_time, globalThis.gstart_time)
    result.interval = msg.inter
    result.return = atlas_tools.get_time_diff(atlas_tools.get_time(), globalThis.gstart_time)
    // console.log(`altas-worker.js:35`);
    result.mode = mode
    result.type = "exec"
    result.tid = tid
    // console.log(`altas-worker.js:39`);
    result.func = msg.func
    // console.log(`altas-worker.js:41`);
    result.req_id = msg.req_id
    result.fulfill = fulfill;
    return result
}

var reconnect_attempts = 5;
var wait_sec = 1;

function connect_to_server(server, node) {
    // var attempts = reconnect_attempts;
    // console.log(`connect_to_server.js:53 node['nonce']=${node['nonce']}`);
    node['nonce'] = 0

    // console.log(`connect_t_server.js:57 reconnect_attempts=${reconnect_attempts} wait_sec=${wait_sec}`);
    var connect_result = atlas.connect(
        server,
        node.ip,
        node.port,
        node.ssl,
        node.verify,
        node.cert,
        reconnect_attempts,
        wait_sec
    );
    if (connect_result == -1) {
        print(`Failed to connect to server: ${node.ip}:${node.port}`);
        return connect_result;
    }
    
    return connect_result;
}

const func_depends = new Map();

/*
 * offload the request to the remote worker
 */
function send(server, msg, arguments_list) {
    // calculate the send time
    //    var attempts = reconnect_attempts;
    const send_start = atlas_tools.get_time();
    if (!func_depends.has(msg.func)) {
        func_depends.set(msg.func, msg.deps);
    }
    
    while (true) {
        try {
            const str_msg = stringify(msg);             
           // console.log(`atlas-worker.js:110 send write`);
            const write_res = atlas.write(server, str_msg, arguments_list);
            // console.log(`atlas-worker.js:115 send write write_res=${write_res}`);
            if(write_res == undefined) {
                // Need to reset the nonce and resend the depends
                // TODO(epl): main thread only sends depends once
                // console.log(`atlas-worker.js:115 write failed`);
                const connect_result = connect_to_server(server, server_info);
                if (connect_result == -1) {
                    console.log(`atlas-worker.js:122 connection failed server=${server}`);
                    break;
                }
                msg.nonce = server_info.nonce;
                msg.deps = func_depends.get(msg.func);
                // console.log(`atlas-worker.js:124 write reconnect server=${server}`);
                continue;
            }
            
            // console.log(`atlas-worker.js:128 recv server=${server}`);
            const data_both = receive(server);
            // console.log(`atlas-worker.js:132 receive done ${data_both}`);

            try {
            // undefined mean communication failure, so reconnect
            if(data_both === undefined) {
                // console.log(`atlas-worker.js:121 receive failed`);
                const recv_reconnect = connect_to_server(server, server_info);
                // console.log(`atlas-worker.js:123 recv reconnect failed server=${server}`);
                if (recv_reconnect == -1) {
                    console.log(`atlas-worker.js:123 recv reconnect failed server=${server}`);
                    break;
                }
                console.log(`atlas-worker.js:126 receive reconnect succeeded`);
                msg.deps = func_depends.get(msg.func);
                msg.nonce = server_info.nonce;
                // console.log(`server.nonce={}`, server.nonce);
                // console.log(msg.deps);
                continue;
            }
            // console.log('atlas-worker.js:133');
            const recv_res = data_both.serialized;
            // console.log(`atlas-worker.js:157 ${recv_res}`);
                
            // increase the nonce
            msg.nonce = msg.nonce + 1
            if (msg.nonce != recv_res.nonce) {
                console.log("Error, invalid nonce. Expected:", msg.nonce, "Received:", recv_res.nonce)
                std.exit(1)
            }
            // console.log(`atlas-worker.js:178 send recv`);
            let res = craft_response(send_start, recv_res.fulfill, recv_res.data, msg, "remote");
            // console.log(`atlas-worker.js:115 send recv`);
            res.buffer_size = write_res
            // console.log(`atlas-worker.js:182 send`);
            return res;
        } catch (err) {
            console.log(`atlas-worker.js:186 err=${err}`);
            break;
        }
        } catch(ee) { console.log(ee);}
    }
    // console.log(`atlas-worker.js:178 failed`);
    var fail_response =  craft_response(send_start, 'LOCAL', undefined, msg, "remote");
    return fail_response;
}

/*
 * Receive the response from the atlas worker
 */
function receive(sock) {
    // Receive data
    let data_both = atlas.read(sock);
    return data_both;
    // console.log(`altas_worker:153 data_both=${data_both}`);
    // for(const k in data_both) {
    //     console.log(`data_both[${k}]=${data_both[k]}`);
    // }
    // // parse the results
    // // const parse_res = parse(data);
    // const parse_res = eval('(' + data_both.json + ')');
    // return [data_both.serialized, parse_res];
}

async function do_task(server, msg, arguments_list) {
    var send_result = send(server, msg, arguments_list)
    return send_result;
}

var parent = os.Worker.parent;


let node = null;
/*
 * Worker request handler. Communicatbes with the parent thread and 
 * sends/receives offloading messages from/to the parent thread and the workers
 */
function handle_msg(e) {
    var ev = e.data;
    switch(ev.type) {
    case "tid" :
        tid = ev.tid;
        globalThis.gstart_time = ev.gstart_time
        break;
    case "intialize":
        reconnect_attempts = ev.reconnect_attempts;
        wait_sec = ev.wait_sec;
        break;
    case "servers" :
        server = atlas.create_server();
        server_info = ev.msg[0];
        connect_to_server(server, server_info);
        break;
    case "task" :
        worker_tasks.push(ev.msg)
        break;
    case "task_streaming":
        // get a server
        let msg = ev.msg
        msg.nonce = server_info['nonce']
        msg['nodeIp'] = server_info['ip']
        // push the task and store xin the promises array
        let val = do_task(server, msg, ev.args)
        val.then(function(result) {
            server_info['nonce'] = msg.nonce
            parent.postMessage({type: "streaming_done", "values" : result})
        });
        break;
    case "ready":
        parent.postMessage({type : "start_reading"})
        break;
    }
}
parent.onmessage = handle_msg;
