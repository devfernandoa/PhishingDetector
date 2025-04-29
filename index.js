"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
console.log('Parsed URL:');
var phishingDetector_1 = require("./src/phishingDetector");
var result = (0, phishingDetector_1.analyzeURL)('0000000000c0.x9xcax2a.workers.dev');
console.log(JSON.stringify(result, null, 2));
// teste
var test = (0, phishingDetector_1.teste)();
console.log(test);
