[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/Chmod351/radar?color=green&label=version&sort=semver)](https://github.com/Chmod351/radar-service/releases)
![GitHub closed pull requests](https://img.shields.io/github/issues-pr-closed/Chmod351/radar-service?color=green) ![GitHub issues](https://img.shields.io/github/issues/Chmod351/radar-service?color=red) ![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/Chmod351/radar-service) ![GitHub top language](https://img.shields.io/github/languages/top/Chmod351/radar-service?color=blue) ![](https://img.shields.io/github/license/Chmod351/radar-service.svg)

 
#   RADAR: Reconnaissance & Advanced Data Analysis Runtime

  Radar is a high-efficiency command-line interface (CLI) tool developed in TypeScript using the Bun runtime, designed for automating reconnaissance (Recon) and assessing an organization's external attack surface. Unlike traditional sequential scripts, Radar implements an event-driven architecture based on asynchronous data streaming and processing queues with constant-time O(1) deduplication. This enables it to discover, map, and assess digital assets on a massive scale without being blocked by network latency.

 * Asset Discovery and Enclave: Executes a passive and active enumeration phase combining subfinder and assetfinder to map all subdomains associated with the target.

 * Infrastructure Mapping and Routing: Extracts DNS records via dnsx and intercepts the ASN (Autonomous System Number). ASN analysis allows for precisely identifying physical network ownership to classify the infrastructure into Cloud, Self-Hosted, or Reseller environments, detecting the presence or absence of CDNs (mitigation filters).

 * Web Telemetry and Attribution: Uses httpx and whois queries to determine the asset's legitimacy, domain registration data, HTTP status codes, and security header availability.

 * Cross-Fingerprinting and Port Scanning: Performs a port inspection on the 100 most common vectors using nmap, correlating results with technology and web version identification provided by whatweb. The core of the system applies cross-validation between network telemetry (DNS phase) and the application layer (web phase) to eliminate false positives.

 * Dynamic Risk Weighting (Scoring): All findings are processed by a scoring engine that classifies assets into Criticality Tiers (High, Medium, and Low Impact) based on data exposure and technology stack obsolescence, centralizing historical deltas in a local database for subsequent visualization.


## Option 1: Clone the Repository

`git clone https://github.com/Chmod351/radar`

### Build the Image

From the project root, run:

`docker build -t radar .`

## Option 2: Download the Image (Recommended)

`docker pull chmod351/radar:latest`

# Docker Deployment

The project is packaged and available on Docker Hub based on a Kali Linux image, with all reconnaissance tools (`subfinder`, `nmap`, `httpx`, etc.) and the `Bun` runtime pre-installed.

### Download Available Images

* `chmod351/radar:latest` - Latest stable version from the master branch

## Usage:

In the root folder: `bun run radar -S target.com`

## Read the Manual

`bun run radar man`

## Variables

* `NODE_ENV`=test or dev: Determines local information storage and console output definitions.
* `IS_DOCKER`: Identifies the environment to determine database storage locations. Without this, the database persists using the execution directory as the path.
* `WEBHOOK_URL`: API webhook to receive real-time scanning events.

It receives two types of events:

### Phase 1 or 3 Completed:

```json
{
  "scanId": 104,
  "status": "completed",
  "total_stages_executed": 3,
  "total_subdomains_found": 42
}

```

### Data Streaming:

```json
{
  "scanId": 104,
  "status": "process",
  "target": "target.com",
  "ip": "1.1.1.1",
  "open_ports": [
    {
      "port": 443,
      "service": "https",
      "protocol": 6,
      "version": "nginx",
      "transport": 6
    }
  ],
  "http_intel": [
    {
      "protocol": 1,
      "status": 200,
      "security": { "strict-transport-security": true },
      "server": "nginx",
      "poweredBy": null,
      "cookies": true,
      "attempts": [
        {
          "method": "GET",
          "header": null,
          "status": 200,
          "size": 1024,
          "timestamp": "2026-05-28T11:47:00Z"
        }
      ],
      "error": null
    }
  ],
  "webserver": "nginx",
  "total_stages_executed": 3
}

```

## Lint:

To run the linter across the entire project: `bun run lint:fix`

## Radar uses SQLite to store information

Check the manual to read the available queries.

## Disclaimer

This tool was created for asset management and authorized security auditing. Any use on systems without consent is the sole responsibility of the user.


