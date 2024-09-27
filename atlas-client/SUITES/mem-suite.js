import {wrapObject as wrapper} from './atlas-wrapper.js'
import {MemRead_bench as MemRead_asd} from './benchmarks/micro/Special/MemRead.js'
import {MemWrite_bench as MemWrite_asd} from './benchmarks/micro/Special/MemWrite.js'

let MemRead_bench = wrapper(MemRead_asd)
let MemWrite_bench = wrapper(MemWrite_asd)

let read_size;
let total_size = 1024 * 1024 * 4;
for(read_size = 64; read_size<total_size; read_size*=2){
	
	for(let i = 0;i<10; i++){
		MemRead_bench(read_size);
	}
	
	print(read_size," done")
}

for(read_size = 64; read_size<total_size; read_size*=2){
	
	for(let i = 0;i<10; i++){
		MemWrite_bench(read_size);
	}
	
	print(read_size," done")
}


print('*MemWrite done*')
