# PhishingDetector

A TypeScript-based tool for detecting potentially malicious or phishing URLs using heuristics and a domain blacklist.

## Features

- Detects known phishing domains from a local list (`phishing-domains.txt`)
- Analyzes suspicious patterns:
  - Numbers replacing letters in domain names
  - Excessive use of subdomains
  - Presence of unusual special characters
- Returns a JSON object with all flagged issues
- Built entirely in TypeScript with CommonJS compatibility

## Project Structure

```
PhishingDetector/
├── data/
│   └── phishing-domains.txt         # List of known phishing domains
├── src/
│   └── phishingDetector.ts          # Main detection logic
├── index.ts                         # Entry point for testing
├── tsconfig.json                    # TypeScript config
```

## Usage

### Run using `ts-node` (development)

```bash
npx ts-node index.ts
```

### Compile and run (production)

```bash
npx tsc
node dist/index.js
```

### Sample output

```json
{
  "url": "0000000000c0.x9xcax2a.workers.dev",
  "domain": "0000000000c0.x9xcax2a.workers.dev",
  "issues": [
    {
      "type": "KnownPhishingDomain",
      "message": "Domain '0000000000c0.x9xcax2a.workers.dev' is listed as a phishing site."
    },
    {
      "type": "NumbersInDomain",
      "message": "Domain '0000000000c0.x9xcax2a.workers.dev' contains numbers, which can be suspicious."
    },
    {
      "type": "ExcessiveSubdomains",
      "message": "Domain '0000000000c0.x9xcax2a.workers.dev' has too many subdomains."
    }
  ]
}
```

## Configuration

To ensure compatibility:

- `phishing-domains.txt` should list one domain per line, no protocols (`http://` or `https://`)
- The tool supports both full URLs and bare domain strings

## License

MIT
