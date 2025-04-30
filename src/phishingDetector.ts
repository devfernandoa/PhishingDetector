import fs from 'fs';
import path from 'path';
import tls from 'tls';
import { distance } from 'fastest-levenshtein';
import dns from 'dns/promises';

const got = require('got').default;
const whois = require('whois-json');
const cheerio = require('cheerio');

type Issue = {
  type: string;
  message: string;
};

type URLCheckResult = {
  url: string;
  domain: string;
  issues: Issue[];
  riskScore: number;
};

// Load phishing domain list
const phishingDomains: Set<string> = new Set();
const listPath = path.resolve(__dirname, '../data/phishing-domains.txt');

const knownDomains: string[] = [];
const knownDomainsPath = path.resolve(__dirname, '../data/known-domains.txt');

const ddnsProviders = [
  'duckdns.org',
  'no-ip.org',
  'no-ip.biz',
  'no-ip.com',
  'dyndns.org',
  'dynu.com',
  'dnsdynamic.org',
  'freedns.afraid.org',
  'changeip.com',
  'homelinux.com',
  'myvnc.com',
];


try {
  const content = fs.readFileSync(listPath, 'utf-8');
  content.split('\n').forEach(line => {
    const domain = line.trim().toLowerCase();
    if (domain) phishingDomains.add(domain);
  });
} catch (err) {
  console.error('Error reading phishing domain list:', err);
}

try {
  const content = fs.readFileSync(knownDomainsPath, 'utf-8');
  content.split('\n').forEach(line => {
    const domain = line.trim().toLowerCase();
    if (domain) knownDomains.push(domain);
  });
} catch (err) {
  console.error('Error reading known domains list:', err);
}

async function checkDomainExists(domain: string): Promise<boolean> {
  try {
    await dns.lookup(domain);
    return true;
  } catch {
    return false;
  }
}

const issueWeights: Record<string, number> = {
  KnownPhishingDomain: 40,
  NumbersInDomain: 10,
  ExcessiveSubdomains: 10,
  SpecialCharacters: 10,
  DomainTooNew: 30,
  DomainAgeUnknown: 10,
  DomainAgeCheckFailed: 5,
  DDNSDetected: 30,
  NoSSLCertificate: 20,
  ExpiredSSLCertificate: 20,
  WeakSSLIssuer: 10,
  SSLConnectionError: 10,
  SSLTimeout: 10,
  TooManyRedirects: 15,
  InsecureRedirect: 15,
  CrossDomainRedirect: 15,
  RedirectCheckFailed: 5,
  SimilarToKnownDomain: 20,
  FormDetected: 5,
  LoginFormDetected: 10,
  SensitiveFieldDetected: 10,
  FormAnalysisFailed: 5,
};

export async function analyzeURL(input: string): Promise<URLCheckResult> {
  const normalizedURL = input.startsWith('http://') || input.startsWith('https://')
    ? input
    : `http://${input}`;
  const domain = extractDomain(normalizedURL);
  console.log(`Extracted domain: ${domain}`);
  const issues: Issue[] = [];

  if (domain === '') {
    return {
      url: input,
      domain: '',
      issues: [{
        type: 'InvalidDomain',
        message: `Could not parse domain from input: "${normalizedURL}"`,
      }],
      riskScore: 0,
    };
  }

  const domainExists = await checkDomainExists(domain);
  if (!domainExists) {
    return {
      url: input,
      domain,
      issues: [{ type: 'NonExistentDomain', message: `The domain '${domain}' does not exist.` }],
      riskScore: 0,
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

  if (containsSpecialCharacters(normalizedURL)) {
    issues.push({
      type: 'SpecialCharacters',
      message: `Input contains unusual special characters.`,
    });
  }

  const domainAgeIssue = await checkDomainAge(domain);
  if (domainAgeIssue) {
    issues.push(domainAgeIssue);
  }

  const ddnsIssue = checkDDNSUsage(domain);
  if (ddnsIssue) issues.push(ddnsIssue);

  const sslIssues = await checkSSL(normalizedURL);
  issues.push(...sslIssues);

  const redirectIssues = await checkRedirects(normalizedURL);
  issues.push(...redirectIssues);

  const similarityIssue = checkDomainSimilarity(domain);
  if (similarityIssue) issues.push(similarityIssue);

  const formIssues = await checkForSensitiveForms(normalizedURL);
  issues.push(...formIssues);

  let score = 0;
  for (const issue of issues) {
    score += issueWeights[issue.type] || 0;
  }

  // Normalize to a maximum of 100
  if (score > 100) score = 100;

  return {
    url: input,
    domain,
    issues,
    riskScore: score,
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

async function checkDomainAge(domain: string): Promise<Issue | null> {
  try {
    const data = await whois(domain);

    if (!data || !data.creationDate) {
      return {
        type: 'DomainAgeUnknown',
        message: `Could not determine creation date for domain '${data.creationDate}'.`,
      };
    }

    const creation = new Date(data.creationDate);
    const now = new Date();
    const ageInDays = (now.getTime() - creation.getTime()) / (1000 * 60 * 60 * 24);

    if (ageInDays < 30) {
      return {
        type: 'DomainTooNew',
        message: `Domain '${domain}' is very recent (created ${Math.round(ageInDays)} days ago).`,
      };
    }

    return null;
  } catch (error) {
    return {
      type: 'DomainAgeCheckFailed',
      message: `Failed to check WHOIS data for domain '${error}'.`,
    };
  }
}

function checkDDNSUsage(domain: string): Issue | null {
  for (const ddns of ddnsProviders) {
    if (domain === ddns || domain.endsWith(`.${ddns}`)) {
      return {
        type: 'DDNSDetected',
        message: `Domain '${domain}' uses Dynamic DNS provider '${ddns}', which is often used in malicious campaigns.`,
      };
    }
  }
  return null;
}

function checkSSL(url: string): Promise<Issue[]> {
  return new Promise((resolve) => {
    const issues: Issue[] = [];
    const domain = extractDomain(url);

    const socket = tls.connect(443, domain, {
      servername: domain,
      rejectUnauthorized: false,
    });

    const timeout = setTimeout(() => {
      socket.destroy();
      issues.push({
        type: 'SSLTimeout',
        message: `SSL connection to '${domain}' timed out.`,
      });
      resolve(issues);
    }, 5000); // 5-second timeout

    socket.on('secureConnect', () => {
      clearTimeout(timeout);
      const cert = socket.getPeerCertificate();

      if (!cert || Object.keys(cert).length === 0) {
        issues.push({
          type: 'NoSSLCertificate',
          message: `The domain '${domain}' does not provide an SSL certificate.`,
        });
      } else {
        const now = new Date();
        const validTo = new Date(cert.valid_to);

        if (validTo < now) {
          issues.push({
            type: 'ExpiredSSLCertificate',
            message: `The SSL certificate for '${domain}' expired on ${cert.valid_to}.`,
          });
        }

        if (cert.issuer && cert.issuer.O) {
          const issuer = cert.issuer.O.toLowerCase();
          if (issuer.includes('self-signed') || issuer.includes("let's encrypt")) {
            issues.push({
              type: 'WeakSSLIssuer',
              message: `The SSL certificate for '${domain}' is issued by '${cert.issuer.O}', which may be considered less trustworthy.`,
            });
          }
        }
      }

      socket.end();
      resolve(issues);
    });

    socket.on('error', (err) => {
      clearTimeout(timeout);
      issues.push({
        type: 'SSLConnectionError',
        message: `Failed to connect via SSL to '${domain}': ${err.message}`,
      });
      resolve(issues);
    });
  });
}

async function checkRedirects(url: string): Promise<Issue[]> {
  const issues: Issue[] = [];

  try {
    const response = await got(url, {
      followRedirect: true,
      throwHttpErrors: false,
      maxRedirects: 10,
      timeout: {
        request: 5000 // 5 seconds
      }
    });

    const hops: string[] = response.redirectUrls || [];

    if (hops.length > 3) {
      issues.push({
        type: 'TooManyRedirects',
        message: `The URL redirected ${hops.length} times, which is suspicious.`,
      });
    }

    for (let i = 0; i < hops.length - 1; i++) {
      const from = new URL(hops[i]);
      const to = new URL(hops[i + 1]);

      if (from.protocol === 'https:' && to.protocol === 'http:') {
        issues.push({
          type: 'InsecureRedirect',
          message: `Redirected from secure (HTTPS) to insecure (HTTP): ${from.href} → ${to.href}`,
        });
      }

      if (!to.hostname.endsWith(from.hostname) && from.hostname !== to.hostname) {
        issues.push({
          type: 'CrossDomainRedirect',
          message: `Redirected between unrelated domains: ${from.hostname} → ${to.hostname}`,
        });
      }
    }

  } catch (err: any) {
    issues.push({
      type: 'RedirectCheckFailed',
      message: `Failed to analyze redirects for '${url}': ${err.message}`,
    });
  }

  return issues;
}

function checkDomainSimilarity(domain: string): Issue | null {
  let closestMatch = '';
  let minDistance = Infinity;

  for (const known of knownDomains) {
    const d = distance(domain, known);
    if (d < minDistance) {
      minDistance = d;
      closestMatch = known;
    }
  }

  if (minDistance > 0 && minDistance <= 2) {
    return {
      type: 'SimilarToKnownDomain',
      message: `Domain '${domain}' is very similar to '${closestMatch}' (distance ${minDistance}). Could be typosquatting.`,
    };
  }

  return null;
}

async function checkForSensitiveForms(url: string): Promise<Issue[]> {
  const issues: Issue[] = [];

  try {
    const response = await got(url, {
      timeout: {
        request: 5000,
      },
      throwHttpErrors: false,
    });

    const html = response.body;
    const $ = cheerio.load(html);

    const forms = $('form');
    const hasLogin = forms.find('input[type="password"], input[name*="user"], input[name*="email"], input[name*="login"]').length > 0;
    const hasSensitiveFields = forms.find('input[name*="ssn"], input[name*="credit"], input[name*="card"]').length > 0;

    if (forms.length > 0) {
      issues.push({
        type: 'FormDetected',
        message: `The page contains ${forms.length} form(s).`,
      });
    }

    if (hasLogin) {
      issues.push({
        type: 'LoginFormDetected',
        message: `The page contains a login form or password field.`,
      });
    }

    if (hasSensitiveFields) {
      issues.push({
        type: 'SensitiveFieldDetected',
        message: `The form requests sensitive personal information like SSN or credit card.`,
      });
    }

  } catch (err: any) {
    issues.push({
      type: 'FormAnalysisFailed',
      message: `Failed to analyze HTML content from '${url}': ${err.message}`,
    });
  }

  return issues;
} 2