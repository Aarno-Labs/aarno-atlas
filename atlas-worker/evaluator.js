import * as std from 'std';

if (msg.nonce != current_nonce) {
    print("Expected:", current_nonce, "received:", msg.nonce)
    std.exit(1)
}


var t=msg.deps;

//print("System Imports:", msg.imports)
for (let i in t) {
    // get the key --- libname
    let o = t[i]
    // we have already pushed to global state
    if (o.source === "" || o.source === undefined)  
        break;
    atlas.execute_script(o.source, o.path)
}

function import_globals(a) {
    let str = a + "\n;do_rest(" + JSON.stringify(msg) + ',' + msg.func + ');'
    atlas.execute_script(str, "<script>");
    return 
}

globalThis.do_rest = async function(msg, func) {
    class GlobalAccessError {
        constructor(access_type, property) {
            this.access_type = access_type;
            this.accessed_property = property;
        }
    };
    // console.log(`msg.args`);
    // console.log(msg.args);

    try {

        let aarno_args = globalThis.aarno_args;
        let globalThisOld = globalThis;
        globalThis = new Proxy(globalThis, {
            get(target, property) {
                throw new GlobalAccessError('get', property);
            },
            set(target, property, value) {
                // our use of globalThis is legal
                if(property !== 'msg' && property !== 'do_rest') {
                    throw new GlobalAccessError('set', property);
                }
                Reflect.set(...arguments);
            },
            apply(target, thisArg, args) {
                throw new GlobalAccessError('apply', target);
            }
        });

        let result_obj = null;
        
        try {
            var result_data = await func.apply(this, aarno_args)
            if (result_data === undefined)
                result_data = "done"
            // increase the nonce
            current_nonce++
            var results = JSON.stringify(
                {fulfill : 'SUCCESS',
                 data    : JSON.stringify(result_data),
                 nonce   : current_nonce});

            result_obj = {
                fulfill : 'SUCCESS',
                data    : result_data,
                nonce   : current_nonce};

        } catch (err) {
            current_nonce++
            var strf_err = JSON.stringify(err);
            const error_type = (err instanceof GlobalAccessError) ? 'GlobalAccessError' : 'REJECT';
            results = JSON.stringify(
                {fulfill : error_type,
                 data    : strf_err,
                 nonce   : current_nonce});
            result_obj =
                {fulfill : error_type,
                 data    : err,
                 nonce   : current_nonce};
        }

        console.write_to_client(results, result_obj);
        //    print(results)
        // gc every 10 pkts
        if (current_nonce % 10)
            std.gc()
        globalThis = globalThisOld;
        globalThisOld = null;
    } catch(all_err) {
        console.log(all_err);
    }
}
import_globals(msg.imports)

