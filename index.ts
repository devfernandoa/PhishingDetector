console.log('Parsed URL:');

import { analyzeURL } from './src/phishingDetector';

const result = analyzeURL('0000000000c0.x9xcax2a.workers.dev');
console.log(JSON.stringify(result, null, 2));