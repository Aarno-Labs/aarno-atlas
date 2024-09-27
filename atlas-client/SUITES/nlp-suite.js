import {wrapObject as wrapper} from './atlas-wrapper.js'
import * as std from 'std'

let input;
let sentence = 'Eithetairus, an Athenian citizen, but disgusted with his own country starts on his travels proposing to seek his fortune in the kingdom of the Birds.';
let paragraph = 'Eithetairus, an Athenian citizen, but disgusted with his own country starts on his travels proposing to seek his fortune in the kingdom of the Birds. He is represented as the essential man of business and ability, the true political adventurer the man who directs every thing and every body who is never in the wrong, never at a loss, never satisfied with what has been done by others, uni formly successful in his operations. He maintains a constant ascendency, or if he loses it for a moment, recovers it immediately. Ejielpides^ a simple easy-minded droll companion, his natural follower and adherent, as the Merry Andrew is of the Mountebank. It will be seen that, like the Merry Andrew, he interposes his buffoonish comments on the grand oration delivered by his master.';
let book = std.loadFile('./macro/nlp/birds.txt');

if(scriptArgs){
	if(scriptArgs[1]){
		print("Input: ",scriptArgs[1]);
		switch(scriptArgs[1]){

			case 'sentence': { input = sentence; break; }
			case 'paragraph': { input = paragraph; break; }
			case 'book': { input = book; break; }
			default: { print("Wrong input; Must be [sentence|paragraph|book]"); std.exit(1);}
		}
	}
}

import {Nouns_bench as Nouns_asd} from './macro/nlp/Nouns.js'
let Nouns_bench = wrapper(Nouns_asd)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
Nouns_bench(input)
print('*Nouns done*')
import {Verbs_bench as Verbs_asd} from './macro/nlp/Verbs.js'
let Verbs_bench = wrapper(Verbs_asd)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
Verbs_bench(input)
print('*Verbs done*')
import {Adjectives_bench as Adjectives_asd} from './macro/nlp/Adjectives.js'
let Adjectives_bench = wrapper(Adjectives_asd)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
Adjectives_bench(input)
print('*Adjectives done*')
import {Adverbs_bench as Adverbs_asd} from './macro/nlp/Adverbs.js'
let Adverbs_bench = wrapper(Adverbs_asd)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
Adverbs_bench(input)
print('*Adverbs done*')
