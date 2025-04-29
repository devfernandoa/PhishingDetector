"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeURL = analyzeURL;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
// Load phishing domain list
const phishingDomains = new Set();
const listPath = path_1.default.resolve(__dirname, '../data/phishing-domains.txt');
try {
    const content = fs_1.default.readFileSync(listPath, 'utf-8');
    content.split('\n').forEach(line => {
        const domain = line.trim().toLowerCase();
        if (domain)
            phishingDomains.add(domain);
    });
}
catch (err) {
    console.error('Error reading phishing domain list:', err);
}
function analyzeURL(input) {
    const domain = extractDomain(input);
    const issues = [];
    if (domain === '') {
        return {
            url: input,
            domain: '',
            issues: [{
                    type: 'InvalidDomain',
                    message: `Could not parse domain from input: "${input}"`,
                }],
        };
    }
    if (isKnownPhishingDomain(domain)) {
        issues.push({
            type: 'KnownPhishingDomain',
            message: `Domain '${domain}' is listed as a phishing site.`,
        });
    }
    if (containsNumberInsteadOfLetters(domain)) {
        issues.push({
            type: 'NumbersInDomain',
            message: `Domain '${domain}' contains numbers, which can be suspicious.`,
        });
    }
    if (hasExcessiveSubdomains(domain)) {
        issues.push({
            type: 'ExcessiveSubdomains',
            message: `Domain '${domain}' has too many subdomains.`,
        });
    }
    if (containsSpecialCharacters(input)) {
        issues.push({
            type: 'SpecialCharacters',
            message: `Input contains unusual special characters.`,
        });
    }
    return {
        url: input,
        domain,
        issues,
    };
}
function extractDomain(input) {
    try {
        const withProtocol = input.includes('://') ? input : `http://${input}`;
        const parsed = new URL(withProtocol);
        return parsed.hostname.toLowerCase();
    }
    catch (_a) {
        return '';
    }
}
function isKnownPhishingDomain(domain) {
    for (const bad of phishingDomains) {
        if (domain === bad || domain.endsWith(`.${bad}`)) {
            return true;
        }
    }
    return false;
}
function containsNumberInsteadOfLetters(domain) {
    return /[0-9]/.test(domain);
}
function hasExcessiveSubdomains(domain) {
    return domain.split('.').length > 4;
}
function containsSpecialCharacters(input) {
    return /[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]/.test(input);
}
