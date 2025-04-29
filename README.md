# Phishing Detection Backend

This is the backend API for analyzing URLs and detecting phishing indicators. It is written in TypeScript using Express and exposes a single HTTP endpoint.

## 🚀 Features

- WHOIS-based domain age verification
- Known phishing domain list check
- Dynamic DNS (DDNS) detection
- SSL certificate validation and inspection
- Redirect chain analysis
- Domain similarity check using Levenshtein distance
- HTML form inspection for login fields or sensitive data
- Risk score calculation with detailed issue list

## 📦 Project Structure

```
PhishingBackend/
├── data/
│   ├── phishing-domains.txt        # List of known phishing domains
│   └── known-domains.txt           # Top 1000 most popular domains
├── src/
│   ├── server.ts                   # Express API server
│   └── phishingDetector.ts         # Core phishing detection logic
├── tsconfig.json
├── package.json
```

## 📡 API

### `GET /analyze?url=example.com`

Analyze a given URL and return structured phishing detection results.

#### Response

```json
{
  "url": "example.com",
  "domain": "example.com",
  "issues": [
    {
      "type": "SimilarToKnownDomain",
      "message": "Domain is similar to google.com"
    }
  ],
  "riskScore": 45
}
```

## 🛠 Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Start the server:

   ```bash
   npx ts-node src/server.ts
   ```

3. Visit:

   ```
   http://localhost:3000/analyze?url=example.com
   ```

> Make sure your `data/` folder is in the root and includes `phishing-domains.txt` and `known-domains.txt`.

## 📄 License

MIT
