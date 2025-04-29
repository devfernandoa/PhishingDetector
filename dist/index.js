"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
console.log('Parsed URL:');
const phishingDetector_1 = require("./src/phishingDetector");
const result = (0, phishingDetector_1.analyzeURL)('0000000000c0.x9xcax2a.workers.dev');
console.log(JSON.stringify(result, null, 2));
