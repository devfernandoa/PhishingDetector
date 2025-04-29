import { analyzeURL } from './src/phishingDetector';

(async () => {
    const result = await analyzeURL('faceb0ook.com');
    console.log(JSON.stringify(result, null, 2));
})();