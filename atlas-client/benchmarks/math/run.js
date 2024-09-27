import {math} from 'benchmarks/math/math.js';


let a = math.add(12,34).then((v) => { return { test : "add", pass : (v === 46), v : v}});
let d = math.div(1,0).then((v)   => { return { test : "div", pass : (v === Infinity), v : v}});
let m = math.mult(1,5).then((v)  => { return { test : "mul", pass : (v === 5), v : v}});
let s = math.sub(1,5);


// gather all the promises and resolve the results
// Promise.allSettled([a, s, d, m])

Promise.allSettled([a, d, m])
    .then(function(results) {
        // print the results for each request
//        results.forEach((result) => console.log(`${result.value} ${typeof result.value}`));
        var all_passed = true;
        results.forEach((result) => {
            console.log(`>> ${result.value.test} ${result.value.pass} ${result.value.v}`);
            all_passed &= result.value.pass;
        });
        console.log(`>> all_passed = ${all_passed}`);
        if (all_passed) {
            std.exit(0);
        }
        std.exit(1);
    });
