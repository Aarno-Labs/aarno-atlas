import {benchmarks} from 'benchmarks/crypto_benchmark/crypto-wrapper.js';
/*
 * Functionality for generating and scheduling packets on different intervals
 */
let promise_results = []
let step = 0
let last_step = 0;
let interval = 1;
function generate_traffic(func, ...args) {
    // calculate how many function we have received
    var received_func_count = atlas_get_received_function_count(func);
    os.setTimeout(function() {
        // print only when the interval switches, no reason to spam the stdio
        if (last_step !== step) {
//            print("Pkt Received:", received_func_count);
            last_step = step;
        }
        if (local_execution === true)
            globalThis.atlas_wrapper.pkt_sent++;
        // resolve the promise
        promise_results.push(func(...args))
        generate_traffic(func, ...args);
    }, interval);

    // have we received 120 packets?
    if (received_func_count >= 10) {
        // gather all the results and print them
        Promise.allSettled(promise_results)
            .then(function(results) {
                // you might want to print this, but the output IS HUGE
                // var i = 0;
                // print the results for each request
                // results.forEach((result) => print('Pkt ID:', i++, "Result:", result.value));
                // complete execution and exit the program
                print("Execution completed, exiting...");
                std.exit(0);
            });
    }
}

let key = 'secret key 123'
// generate input
let input = ''
for (let i = 0; i < globalThis.opts.input; i++)
    input = input + 'a';
// start generating traffic
generate_traffic(benchmarks.encrypt_sign, input, key, key);
