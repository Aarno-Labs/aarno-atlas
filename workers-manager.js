'use strict';

export class WorkersManager {
    constructor(server_count,
                worker_count,
                servers_per_node,
                servers_remaining,
                server_nodes,
                remoteOnly,
                reconnect_attempts,
                wait_sec
               ) {
        this.worker_ready = 0;
        this.server_count = server_count;
        this.worker_count = worker_count;
        this.servers_per_node = servers_per_node;
        this.servers_remaining = servers_remaining;
        this.server_nodes = server_nodes;
        this.remoteOnly = remoteOnly;
        this.resolvers  = new Map();
        this.rejectors  = new Map();
        this.local_exec = new Map();
        this.worker_array = [];
        this.total_workers = [];
        this.received_functions = new Map();
        this.reconnect_attempts = reconnect_attempts;
        this.wait_sec = wait_sec;
        
        globalThis.atlas_get_received_function_count = (func) =>  {
            // on local execution, we have to resolve the real function name
            // i.e, when running benchmarks.encrypt_sign, only encrypt_sign will be parsed
            // whereas in remote, benchmarks.encrypt_sign will be parsed as function name
            // as a whole (which is what we want)
            let v = get_real_target_name(func);
            // if the entry is undefined, return 0;
            return this.received_functions.get(v) || 0;
        }
    }

    atlas_increase_function_count(func) {
        let entry = this.received_functions.get(func);
        if (entry === undefined)
            this.received_functions.set(func, 1);
        else
            // increase the existing counter (even if it doesn't exist, entry will be 0)
            this.received_functions.set(func, entry + 1);
    }

    update_onmessage_resolvers(worker) {
        worker.onmessage = (e) =>  {
            this.atlas_increase_function_count(e.data.values.func);
            // console.log(`workers-manager.js:52 e.data.values.data=${e.data.values.data}`);
            
            // resolve the value
//             const worker_result = eval('(' + e.data.values.data + ')');
            const worker_result = e.data.values.data;

            if(e.data.values.fulfill === 'SUCCESS') {
                this.resolvers.get(e.data.values.req_id)(worker_result);
            }
            else if(e.data.values.fulfill === 'REJECT') {
                this.rejectors.get(e.data.values.req_id)(worker_result);
            }
            else if(e.data.values.fulfill === 'LOCAL'
                   || e.data.values.fulfill === 'GlobalAccessError') {
                // console.log(`workers-manager.js:56 this.remoteOnly=${this.remoteOnly}`);
                if (this.remoteOnly === true) {
                    console.log(`ERROR: remote execution failed fulfill=${e.data.values.fulfill} remoteOnly=${this.remoteOnly}`);
                    std.exit(1);
                }
                // console.log(`workers-manager.js:61 remoteOnly=${remoteOnly}`);
                try {
                    var local_exec = this.local_exec.get(e.data.values.req_id);
                    // console.log(`workers-manager.js:57`);
                    // for(const k in aWrapper) {
                    //     console.log(`aWrapper[${k}]=${aWrapper[k]}`);
                    // }
                    var local_promise = aWrapper.exec_local(
                        local_exec.target,
                        local_exec.target_name,
                        local_exec.arguments_list);
                    // console.log(`workers-manager.js:62`);
                    local_promise.then(this.resolvers.get(e.data.values.req_id),
                                        this.rejectors.get(e.data.values.req_id));
                    // console.log(`workers-manager.js:65`);
                } catch (err) {
                    // console.log(`workers-manager.js:63`);
                    console.log(err);
                }
            }
            this.resolvers.delete(e.data.values.req_id);
            this.rejectors.delete(e.data.values.req_id);
        }
    }

    
    change_msg_handler() {
        var worker_count = get_worker_count()
        for (let i = 0; i < worker_count; i++) {
            this.update_onmessage_resolvers(this.worker_array[i]);
        }
    }

    static execute_script() {
        atlas_print("#Start Duration Latency Bytes Interval End Mode Thread_ID Type Function Request_ID Battery_Status");
        // detect the modules we need to import
        atlas.import_modules();
        // trigger flag to detect imported local names to offload to the client
        atlas.start_wrapping(globalThis.offload_funcs);
        // start executing the client's code
        atlas.execute_script(file_to_exec);
    }

    // qjs won't shutdown if a worker is running or outstanding Promises
    // Check if only one worker (should be our worker)
    // setting onmessage to null terminates worker thread and allow shutdown
    checkEndWorker () {
        if(atlas.NoJobsSingleWorker()
          && this.resolvers.size === 0) {
            for(var w = 0;
                w < this.total_workers.length;
                w++) {
                var worker = this.total_workers[w];
                worker.onmessage = null;
                
            }
        } else {
            os.setTimeout(() => {this.checkEndWorker()}, 2000);
        }
    };
    
    /*
     * Spawn the qjs workers for handling pending requests. Assign the atlas servers
     * to each one of the workers
     */
    spawn_workers() {
        globalThis.module_sent_to_all_workers = []
        // assign the servers
        for (let i = 0; i < this.worker_count; i++) {
            var worker = new os.Worker("./atlas-worker.js");

            // use => to bind this to the current this
            worker.onmessage = (e) => {
                // initiate reading from the input after all the workers are ready
                this.worker_ready++
                
                /* wait until all workers are started */
                if (this.worker_ready == this.total_workers.length) {
                    /*********************************************/
                    // start running the script
                    WorkersManager.execute_script()
                    /*********************************************/
                    /* 
                     * after we have and injected tasks in our work queues
                     * trigger the workers to start offloading 
                     */
                    this.worker_ready = 0
                    this.change_msg_handler();

                    // cancel our worker so qjs can shutdown
                    os.setTimeout(() => {this.checkEndWorker()}, 2000);
                }
            }
            module_sent_to_all_workers[i] = 0;
            // send tid to each worker
            worker.postMessage({type : "intialize",
                                reconnect_attempts : this.reconnect_attempts,
                                wait_sec : this.wait_sec
                               });

            worker.postMessage({type : "tid", tid:i, "gstart_time": globalThis.gstart_time})
            // server assignment
            if (i === get_worker_count() - 1) {
                globalThis.servers_per_node = this.servers_remaining
            }
            // for (let j = 0; j < servers_per_node; j++) {
            //     const node = atlas_scheduler.getNode();
            //     worker.postMessage({type : "server", msg : node})
            // }
            worker.postMessage(
                {type : "servers",
                 msg  : this.server_nodes.slice(i, i + this.servers_per_node)
                });
            
            globalThis.servers_remaining = this.servers_remaining - servers_per_node
            this.worker_array[i] = worker
            worker.postMessage({type : "ready"})
            this.total_workers.push(worker)
        }
    }
}
