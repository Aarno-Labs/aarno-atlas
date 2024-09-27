import {wrapObject as wrapper} from './atlas-wrapper.js'

let db_size = 20000;
let operations = 200000;
let batch = 10000;

if(scriptArgs){

	if(scriptArgs[1] && scriptArgs[2] && scriptArgs[3]){
		db_size = Number(scriptArgs[1]);
		operations = Number(scriptArgs[2]);
		batch = Number(scriptArgs[3]);

	}

}

print(`DBsize: ${db_size}, Operations: ${operations}, batch: ${batch}`);

import {CreateDB_bench as CreateDB_asd} from './macro/simple-pw/CreateDB.js'
let CreateDB_bench = wrapper(CreateDB_asd)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
CreateDB_bench(db_size,operations,batch)
print('*CreateDB done*')
import {UpdateN_bench as UpdateN_asd} from './macro/simple-pw/UpdateN.js'
let UpdateN_bench = wrapper(UpdateN_asd)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
UpdateN_bench(db_size,operations,batch)
print('*UpdateN done*')
import {ReadN_bench as ReadN_asd} from './macro/simple-pw/ReadN.js'
let ReadN_bench = wrapper(ReadN_asd)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
ReadN_bench(db_size,operations,batch)
print('*ReadN done*')
import {DeleteN_bench as DeleteN_asd} from './macro/simple-pw/DeleteN.js'
let DeleteN_bench = wrapper(DeleteN_asd)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
DeleteN_bench(db_size,operations,batch)
print('*DeleteN done*')
