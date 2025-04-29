import fs from 'fs';
import path from 'path';

type Issue = {
  type: string;
  message: string;
};

type URLCheckResult = {
  url: string;
  domain: string;
  issues: Issue[];
};

// Load phishing domain list
const phishingDomains: Set<string> = new Set();
const listPath = path.resolve(__dirname, '../data/phishing-domains.txt');

try {
  const content = fs.readFileSync(listPath, 'utf-8');
  content.split('\n').forEach(line => {
    const domain = line.trim().toLowerCase();
    if (domain) phishingDomains.add(domain);
  });
} catch (err) {
  console.error('Error reading phishing domain list:', err);
}

export function analyzeURL(input: string): URLCheckResult {
  const domain = extractDomain(input);
  const issues: Issue[] = [];

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

function extractDomain(input: string): string {
  try {
    const withProtocol = input.includes('://') ? input : `http://${input}`;
    const parsed = new URL(withProtocol);
    return parsed.hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isKnownPhishingDomain(domain: string): boolean {
  for (const bad of phishingDomains) {
    if (domain === bad || domain.endsWith(`.${bad}`)) {
      return true;
    }
  }
  return false;
}

function containsNumberInsteadOfLetters(domain: string): boolean {
  return /[0-9]/.test(domain);
}

function hasExcessiveSubdomains(domain: string): boolean {
  return domain.split('.').length > 4;
}

function containsSpecialCharacters(input: string): boolean {
  return /[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]/.test(input);
}
