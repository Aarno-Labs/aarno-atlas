import {wrapObject as wrapper} from './atlas-wrapper.js'
import {FRead_bench as Fread_asd} from './benchmarks/micro/Special/FRead.js'
let FRead_bench = wrapper(Fread_asd)

let read_size;
let total_size = 1024 * 1024 * 4;
for(read_size = 64; read_size<total_size; read_size*=2){
	
	for(let i = 0;i<10; i++){
		FRead_bench(read_size);
	}
	print(read_size," done")
}

print('*FRead done*')
