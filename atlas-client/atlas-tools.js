/*
 * Get current timestamp
 */ 
function get_time() {
    var date = new Date()
    return date.getTime();
}

/*
 * get time diff in seconds
 */
function get_time_diff(end, start) {
    return ((end - start)/1000);
}

/*
 * get random integer
 */
function get_random_int(min, max) {
        min = Math.ceil(min);
        max = Math.floor(max);
        return Math.floor(Math.random() * (max - min) + min);
}

/*
 * generate a buffer of count size bytes given an input
 */
function repeat(pattern, count) {
    if (count < 1) return '';
    var result = '';
    while (count > 1) {
        if (count & 1) result += pattern;
        count >>= 1, pattern += pattern;
    }
    return result + pattern;
}

/*
 * Parse the command line arguments
 */
function parse_args(cmd) {
    // ignore the binary name
    let args = cmd.slice(1)
    let res = {}
    try {
        for (let i = 0; i < args.length; i++) {
            if(args[i].startsWith('--')) {
                if (parseInt(i) + 1 < args.length && !args[i+1].startsWith('--')) {
                    // strip the -- from the argument
                    args[i] = args[i].substring(2)
                    // parse the value
                    res[args[i]] = args[i+1]
                    i++
                } else {
                    // assign arg name as value
                    args[i] = args[i].substring(2)
                    res[args[i]] = true
                }
            }
        }
    } catch (e) {
        atlas_print("Error", e)
        usage();
    }
    return res
}

function tidy_file() {
    atlas_print("Execution done");
    if (globalThis.log_name !== undefined) {
        globalThis.log_file.close();
        std.popen('column -t ' + globalThis.log_name + ' > .sorted_atlas; mv .sorted_atlas ' + globalThis.log_name, "w");
    }
}

let atlas_tools = {};
atlas_tools.get_time = get_time;
atlas_tools.get_time_diff = get_time_diff;
atlas_tools.get_random_int = get_random_int;
atlas_tools.repeat = repeat;
atlas_tools.parse_args = parse_args;
atlas_tools.tidy_file = tidy_file;
export default atlas_tools;
