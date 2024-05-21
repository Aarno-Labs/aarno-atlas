import * as os from "os";
/*
 * Variables used for scheduling 
 */
globalThis.last_latency = 0;
globalThis.remote_avg = 0;
globalThis.local_sd = 0;
globalThis.local_avg = 0;
globalThis.final_results = [];
globalThis.time = [];


export class AtlasWrapper {
    constructor(workerManager) {
        this.wrappedObjects = new Map();
        // holds the required libs for each function call
        this.function_call_deps = new Map();

        this.pkt_received = 0;
        this.pkt_sent = 0;
        this.current_worker = 0;
        // total exec time
        this.atlas_time = 0;
        this.workerManager = workerManager;
        this.module_sent_to_all_workers = [];
        this.ignored_libs = [
            "atlas-battery",
            "atlas-scheduler",
            "atlas-wrapper",
            "atlas-worker",
            "atlas-srl",
            "atlas-tools",
            "workers-manager",
            "atlas-battery"];

        globalThis.atlas_wrapper = this;
        /*
         * In contrast with remote calls where we just offload the call name
         * i.e benchmarks.encrypt_sign (all this line will be transmitted to the other party
         * and the function will be executed remotely.
         * However, in local execution, all the code is executed command by command
         * Thus, by running encrypt_sign ---> AES.encrypt(...); HMAC(...); both of them
         * are ALREADY wrapped since they are a part of the original library, thus they 
         * return a promise object back to the client (a series of promises .....).
         * to solve this, we create a counter that shows if function A has not been called
         * by another wrapped function. If A is indeed the first, we increase the counter.
         * In our case, A = benchmarks.encrypt_sign, so the following calls AES.encrypt and
         * HMAC will enter the exec_local function and atlas_nested_fcalls will NOT be 0
         * thus, they will NOT have to return a PROMISE, but the actual value back to A
         */
        this.atlas_nested_fcalls = 0;

        this.handler =  {
            apply: (target, p1, ...arguments_list) => {
                // console.log(`atlas-wrapper.js:54`);
                // iterate all wrapped objects
                var target_name = get_real_target_name(target);
                if (local_execution == false) {
                    try {
                        var scaler =  this.atlas_scale(target, target_name, ...arguments_list);
                    } catch(e) {
                        console.log(e);
                    }
                    return scaler;
                } else {
                    this.atlas_nested_fcalls++;
                    var e = exec_local(target, target_name, ...arguments_list, "exec")
                    this.atlas_nested_fcalls--;
                    return e
                }
            }
        }


        globalThis.get_real_target_name = (target) => {
            // the offloaded function name
            var found = false;
            // get the current target_name
            var target_name = target.name;
            for (let [i,v] of this.wrappedObjects) {
                var name = v.rname;
                var p = v.father;
                //atlas_print(i, target.name, target.father)
                //atlas_print('------------------------------------')
                //atlas_print('Checking:', i, i.name)
                //atlas_print('Value   :', stringify(v))
                //atlas_print('Args    :', stringify(...arguments_list))
                //atlas_print('Realname:', name)
                //atlas_print('Father  :', p)
                //atlas_print('Target  :', target)
                //atlas_print('TName   :', target.name)
                //atlas_print('TFather :', target.father)
                if (i.name === target.name && (target.father === name || (target.father !== name && p === false))) {
                    switch(p) {
                    case false:
                        //atlas_print('Offloading function, sending name only');
                        if (v.real_path !== target.name)
                            target_name = name
                        else
                            target_name = target_name;
                        found = true;
                        break;
                    case true:
                        //atlas_print('Offloading object function call');
                        target_name = v.rname + '.' + target.name;
                        found = true;
                        break;
                    }
                    if (found === true)
                        break;
                }
            }
            return target_name;
        }
        
    }

    handler_func(offload) {
        return {
            apply: (target, p1, ...arguments_list) => {
                // iterate all wrapped objects
                var target_name = get_real_target_name(target);
                if (local_execution == false) {
                    var scaler =  this.atlas_scale(target, target_name, offload, ...arguments_list);
                    return scaler;
                } else {
                    this.atlas_nested_fcalls++;
                    var e = exec_local(target, target_name, ...arguments_list, "exec")
                    this.atlas_nested_fcalls--;
                    return e
                }
            }
        }
    }
    
    /*
     * Fetch a worker for a task
     */
    pick_worker(n) {
        let wk = this.next_worker(n)
        this.current_worker++
        return wk
    }
    
    /*
     * Function to get the id of the next available worker for offloading
     */
    next_worker(n) {
        return this.current_worker % n
    }

    /*
     * Given a parsed object, craft an offload request package
     */
    craft_request(function_name, arguments_list)
    {
        let deps = ''
        // send the modules only once
        deps = this.parse_request_modules(function_name)
        // Change the package name
        if (function_name.indexOf('/') != -1) {
            function_name = function_name.split('/');
            function_name = function_name[function_name.length - 1].split('.')[0]; 
        }
        // craft the atlas object to offload
        let request = {
            req_id : this.pkt_sent,
            func: function_name,
//            args: arguments_list,
            issued_time : atlas_tools.get_time(),
            inter: globalThis.interval,
            deps: deps,
            imports: this.find_imports(),
        }
        return request
    }

    promise_reference(wrk, request, target, function_name, offload_info, arguments_list) {
        return new Promise((resolve, reject) => {
            this.workerManager.total_workers[wrk].postMessage(
                {type : "task_streaming",
                 msg  : request,
                 args : arguments_list});
            this.workerManager.resolvers.set(request.req_id, resolve);
            this.workerManager.rejectors.set(request.req_id, reject);
            this.workerManager.local_exec.set(request.req_id,
                                              { target : target,
                                                function_name: function_name, arguments_list});
            if (offload_info.hasOwnProperty('timeout')) {
                // console.log('[atlas-wrapper.js:167 set timeout]');
                os.setTimeout( () => {
                    // console.log(`[atlas-wrapper.js:191 local ${offload_info.timeout} timeout]`);
                    const task_not_completed = this.workerManager.resolvers.has(request.req_id);
                    // console.log(`[atlas-wrapper.js:175 task_not_completed=${task_not_completed}]`);
                    if (task_not_completed) {
                        // console.log(`[atlas-wrapper.js:177 launch local]`);
                        var local_exec = this.workerManager.local_exec.get(request.req_id);
                        
                        var local_promise = aWrapper.exec_local(
                            local_exec.target,
                            local_exec.target_name,
                            local_exec.arguments_list);
                        // console.log(`workers-manager.js:62`);
                        local_promise.then(this.workerManager.resolvers.get(request.req_id),
                                           this.workerManager.rejectors.get(request.req_id));
                        this.workerManager.completed_locally.set(request.req_id);
                    }
                }, offload_info.timeout);
            }
        });
    }

    /*
     * We are in streaming mode, offload task remotely on workers
     */
    stream_packet(request, target, function_name, offload_info, arguments_list) {
        // can we scale dynamically by allocating more workers
        if (globalThis.scaling == true) {
            change_worker_count()
        }
        // pick a worker
        let wrk = this.pick_worker(actual_workers);
        // if we have already forwarded all the modules to the target, skip re-sending them
        if (this.module_sent_to_all_workers[wrk] === 1) {
            request.deps = '';
        } else
            this.module_sent_to_all_workers[wrk] = 1;
        // offload the request to a worker
        return this.promise_reference(wrk, request, target, function_name, offload_info, arguments_list)
    }

    /*
     * Offload to atlas nodes or local node
     */
    atlas_scale(target, function_name, offload_config, arguments_list) {
        // generate an offloading request
        let request = this.craft_request(function_name, arguments_list)
        //increase the number of packets sent
        this.pkt_sent++;
        // offload the result
        return this.stream_packet(request, target, function_name, offload_config, arguments_list);
    }

    basename(s) {
        return s.split('\\').pop().split('/').pop().split(".js")[0];
    }

    find_imports() {
        let result = std.loadFile(file_to_exec).replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, '')
        const patternImport = new RegExp(/import(?:["'\s]*([\w*${}\n\r\t, ]+)from\s*)?["'\s]["'\s](.*[@\w_-]+)["'\s].*$/, 'mg')
        let p_match = result.match(patternImport)
        let s =''
        for (let i in p_match) {
            // convert " to ' in the imports                                     
            let tes = p_match[i].replaceAll('"', "'")                            
            // split ' to tokens                                                 
            let tok = tes.split("'")                                             
            // replace fullpath to basename                                      
            p_match[i] = p_match[i].replace(tok[1], this.basename(tok[1]))
            s = s + p_match[i] + '\n'
        }
        return s
    }   

    strip_import_path(f) {
        let result = std.loadFile(f) ;//.replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, '')
        const patternImport = new RegExp(/import(?:["'\s]*([\w*${}\n\r\t, ]+)from\s*)?["'\s]["'\s](.*[@\w_-]+)["'\s].*$/, 'mg')
        let p_match_imports = result.match(patternImport)
        for (let i in p_match_imports) {
            // convert " to ' in the improts                                     
            let tes = p_match_imports[i].replaceAll('"', "'");
            // split ' to tokens                                                 
            let tok = tes.split("'")                                             
            // replace fullpath to basename                                      
            result = result.replace(tok[1], this.basename(tok[1]))
        }

        const patternExport = new RegExp(/export(?:["'\s]*([\w*${}\n\r\t, ]+)from\s*)?["'\s]["'\s](.*[@\w_-]+)["'\s].*$/, 'mg')
        let p_match_exports = result.match(patternExport)
        for (let i in p_match_exports) {
            // convert " to ' in the improts                                     
            let tes = p_match_exports[i].replaceAll('"', "'");
            // split ' to tokens                                                 
            let tok = tes.split("'")                                             
            // replace fullpath to basename                                      
            result = result.replace(tok[1], this.basename(tok[1]))
        }
        
        return result
    }  

    /*
     * we parse the request modules with their local variable names and exported name
     * we will send both the source code + import the modules using the local/exported name
     */
    parse_request_modules(fname) {
        let pair = this.function_call_deps.get(fname)

        // we found the entry, return it
        if (pair !== undefined) {
            return pair
        }
        let bench_ref = {}
        let mdata = atlas.read_modules()
        let s = mdata.split('\n').
            forEach((s) => {
                s = s.split(',')
                // so we have no more entries, exit loop
                if (s[0] == "")
                    return 
                let atlas_lib = () => {
                    for (let i in this.ignored_libs) {
                        if (s[0].includes(this.ignored_libs[i])) {
                            return true
                        }
                    }
                    return false
                }
                // we don't want atlas libs
                if (atlas_lib())
                    return 
                else {
                    if (bench_ref[this.basename(s[0])] === undefined) 
                        bench_ref[this.basename(s[0])] = {"source": this.strip_import_path(s[0]), "path":this.basename(s[0])};
                }
            });
        this.function_call_deps.set(fname, bench_ref)
        return bench_ref
    }


    /**
     * Return true is the object is to be offloaded
     *
     * @param {string} real_name The name being imported
     * @param {string} filename The file name doing the importing
     * @return {bool} true if the object should be offloaded
     */
    /**
     * Return true is the object is to be offloaded
     *
     * @param {string} real_name The name being imported
     * @param {string} filename The file name doing the importing
     * @return {bool} true if the object should be offloaded
     */
    IsOffloaded(real_name, filename) {
        const imports = globalThis.offload_funcs.get(filename);
        if(imports === undefined) {
            return undefined;
        }
        return imports.get(real_name);
    }

    /*
     * Wrapper function that identifies the bottlenecked functions
     * real_name: the defined variable that we may use // import {math} from './math.js' -> math is the real_name
     * import_name: the imported variable name (we don't use) // import {math as m} from './math.js' -> math -> imported, m: real_name
     * filename: the file doing the importing
     */
    wrapObject(nobj, real_name, import_name, filename) {
        // Get the type of the object 
        const type = typeof(nobj);
        
        // If it is an function 
        if (type === 'function') {
            let offload = this.IsOffloaded(real_name, filename);
            if(offload === undefined) {
                return nobj;
            }

            let obj = nobj
            if (import_name === '*')
                // we deep copy in case the obj is const
                obj = Object.assign(() => {}, nobj);
            // Wrap the function in a proxy 
            // const wrappedObj = new Proxy(obj, this.handler);
            const wrappedObj = new Proxy(obj, this.handler_func(offload));
            Object.defineProperty(obj, "father", { value: obj.name });
            if (obj.name === '') {
                Object.defineProperty(obj, 'name', { value: real_name });
            }
            // Store the wrapped obj 
            this.wrappedObjects.set(obj, {'rname' :real_name, 'father' : false});
            // and return it
            return wrappedObj;
            // If it is a object 
        } else if (type === 'object') {
            let obj = nobj;
            if (import_name === '*')
                // deep copy in case obj is const
                obj = Object.assign({}, nobj)
            // get the keys of the object
            const objKeys = Object.keys(obj);
            for (let key of objKeys) { 
                //if its an anonymous function
                if (typeof(obj[key]) === 'function') { // && obj[key].name === undefined) {
                    const import_attribute = `${real_name}.${key}`;
                    let offload = this.IsOffloaded(import_attribute, filename);
                    if (offload === undefined) {
                        continue;
                    }

                    //rewrite the name property
                    Object.defineProperty(obj[key], "name", { value: key });
                    Object.defineProperty(obj[key], "father", { value: real_name });
                    // wrap the function call with a proxy
                    let p = new Proxy(obj[key], this.handler_func(offload));
                    // Store the wrapped obj
                    this.wrappedObjects.set(p, {'rname' :real_name, 'father': true});
                    obj[key] = p
                }
            }
            return obj
        }
        return nobj;
    }

    /*
     * Wrap the local call to async to prevent blocking
     */
    exec_local(target, target_name, argumentsList, type) {
        let result = {};
        let issue_time = atlas_tools.get_time();
        result.started = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);

        return new Promise(async (resolve, reject) => {
            try {
                // console.log(`atlas-wrapper.js:375 about to await target`);
                let res = await target.call(this, ...argumentsList);
                // console.log(`atlas-wrapper.js:377 awaited target`);
                result.started;
                result.data = res;
                result.duration = atlas_tools.get_time_diff(atlas_tools.get_time(), issue_time);
                result.latency = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);
                result.interval = interval;
                result.return = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);
                result.mode = 'local';
                result.type = type;
                result.tid = -1;
                result.func = target_name;
                result.buffer_size = JSON.stringify(argumentsList).length;
                // console.log(`atlas-wrapper.js:389 ${res}`);
                globalThis.aWrapper.workerManager.atlas_increase_function_count(target_name);
                // console.log(`atlas-wrapper.js:389 ${resolve}`);
                resolve(res);
            } catch(e) {
                reject(e);
            }
        });
    }
}




/*
 * Condition that decides if we should scale up to more nodes
 */
function scale_up_condition() {
    if (local_avg === 0) {
        return (last_latency  > remote_avg * 1.1)
    } else
        return (last_latency  > remote_avg * 1.1) && (last_latency / local_avg) > remote_avg
}

/*
 * Condition that decides if we should scale down to less nodes
 */
function scale_down_condition() {
    return last_latency / remote_avg < remote_avg
}

/*
 * The actual scheduling policy that chooses whether we should use more or less
 * workers, using the atlas cloud
 */
function change_worker_count() {
    // we should scale here
    if (scale_up_condition() == true && actual_workers != workerManager.total_workers.length) {
        actual_workers++
    } else if (scale_down_condition() == true && actual_workers != 1) {
        //actual_workers--
        //TODO
    }
    return 
}

/*
 * Wrap the local call to async to prevent blocking
 */
function exec_local(target, target_name, argumentsList, type) {
    let result = {};
    let issue_time = atlas_tools.get_time();
    result.started = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);

    return new Promise(async (resolve, reject) => {
        try {
            let res = await target.call(this, ...argumentsList);
            result.started;
            result.data = res;
            result.duration = atlas_tools.get_time_diff(atlas_tools.get_time(), issue_time);
            result.latency = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);
            result.interval = interval;
            result.return = atlas_tools.get_time_diff(atlas_tools.get_time(), gstart_time);
            result.mode = 'local';
            result.type = type;
            result.tid = -1;
            result.func = target_name;
            result.buffer_size = JSON.stringify(argumentsList).length;
            globalThis.aWrapper.workerManager.atlas_increase_function_count(target_name);
            resolve(res);
        } catch(e) {
            reject(e);
        }
    });
}

