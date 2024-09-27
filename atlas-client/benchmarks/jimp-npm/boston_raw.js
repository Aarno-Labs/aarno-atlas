
import {encode} from 'benchmarks/jimp-npm/node_modules/jpeg-js/lib/encoder.js';
import * as os from "os";


function getDateTime() {
    let currentdate = new Date();
    let test = "" + currentdate.getMinutes();

    var datetime =
        + `${currentdate.getFullYear()}`.padStart(4, "0")  
        + "/" + `${currentdate.getMonth()+1}`.padStart(2, "0")
        + "/" + `${currentdate.getDate()}`.padStart(2, "0")
        + "-" + `${currentdate.getHours()}`.padStart(2, "0")
        + ":" + `${currentdate.getMinutes()}`.padStart(2, "0")
        + ":" + `${currentdate.getSeconds()}`.padStart(2, "0")
        + "." + `${currentdate.getMilliseconds()}`.padStart(3, "0")
    ;

    return datetime;
}

async function main() {
    try {
	const raw_file = 'benchmarks/jimp-npm/boston.110x73.bin';
        let width = 110;
        let height = 73;

        let raw_stat = os.stat(raw_file);
        let raw_data = os.open(raw_file, os.O_RDONLY);
        let abuf = new ArrayBuffer(raw_stat[0].size);
        let image_data = os.read(raw_data, abuf, 0, raw_stat[0].size);
        let buf = new Uint8Array(abuf);

        

//	const raw_file = 'benchmarks/jimp-npm/boston.small.rgba';
        // let width = 439;
        // let height = 293;
        var rawImageData = {
            data: buf,
            width: width,
            height: height,
        };

//         while (true) {
            console.log("[" + getDateTime() + "] Call Encode");
            var jpegImageData = await encode(rawImageData, 50);
            console.log("[" + getDateTime() + "] Done Encode");
            let f = os.open('/tmp/j.jpg', os.O_CREAT | os.O_RDWR);
            const r = os.write(f, jpegImageData.data.buffer, 0, jpegImageData.data.length);
        os.close(f);
//        os.setTimeout(main, 0);
//        os.setTimeout(main, 2000);
//        }
    } catch(err) {
        console.log(err);
    }
};

try {
    main();
} catch(error) {
    console.log(error);
}
