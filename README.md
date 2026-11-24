
  
![Docker Pulls](https://img.shields.io/docker/pulls/chmod351/radar)
![Docker Image Version](https://img.shields.io/docker/v/chmod351/radar?sort=semver)
<img src="https://img.shields.io/github/license/Chmod351/radar-service" alt="License">


# RADAR




**Reconnaissance & Advanced Data Analysis Runtime** is a TypeScript/Bun command-line tool for discovering and profiling an organization's internet-facing domain assets. It streams discovered subdomains through DNS, network-ownership, web-server, and (unless OSINT-only mode is enabled) service-fingerprinting checks, then sends structured results to a webhook.

RADAR is intended for asset inventory and authorized external attack-surface reviews. It is not a vulnerability scanner, exploitation framework, or guarantee that every asset will be discovered.

## What It Does

RADAR processes a root domain in three stages:

1. **Subdomain discovery:** runs Subfinder and Assetfinder and deduplicates their output.
2. **DNS and basic enrichment:** resolves discovered names with dnsx; obtains IP ownership/ASN information through Team Cymru DNS; probes HTTP metadata; classifies CDN indicators; and queries WHOIS for eligible domains.
3. **Service fingerprinting:** for resolved IPs, checks the 100 most common ports using Nmap (`-F`, open ports only, service/version detection at minimum intensity, and banner script), fingerprints web technologies with WhatWeb, and gathers HTTP headers and status. Nmap work is limited to one scan at a time and repeated IPs reuse the same fingerprint result.

The default run performs all three stages. OSINT-only mode skips Stage 3. Despite some internal data structures and installed packages, the current workflow does not perform vulnerability matching or risk scoring.

## Requirements

### Recommended: Docker

- Docker Engine or Docker Desktop, with permission to run containers.
- Network access from the container to the target and to the external services/tools used during reconnaissance.
- A webhook receiver if you want to retain or consume scan results. RADAR does not provide a results UI.

The image includes Bun and the reconnaissance utilities used by the scan: Subfinder, Assetfinder, dnsx, httpx-toolkit, Nmap, WhatWeb, whois, curl, and supporting system packages.

### Run Directly on Linux

- Bun (the project uses Bun APIs, including `bun:sqlite`).
- The same external command-line tools listed above, installed and available on `PATH`.
- Network/DNS access required for the selected probes.

Direct local execution is useful for development. The Docker image is the simpler way to get a consistent toolchain.

## Quick Start

### Use the Published Image Through the CLI

Clone the repository to use its CLI wrapper, then run:

```sh
git clone https://github.com/Chmod351/radar.git
cd radar
docker pull chmod351/radar:latest
WEBHOOK_URL=https://your.example/api/radar-events bun run radar.ts -S example.com
```

The `-S` wrapper starts a disposable container and invokes the scan entry point. Set `WEBHOOK_URL` to an endpoint you control; otherwise RADAR uses the built-in default URL (see [Configuration](#configuration)). Only scan domains and systems you are authorized to assess.

### Build and Run Locally with Docker

```sh
git clone https://github.com/Chmod351/radar.git
cd radar
docker build -t radar .
NODE_ENV=dev WEBHOOK_URL=https://your.example/api/radar-events bun run radar.ts -S example.com
```

`NODE_ENV=dev` tells the wrapper to use the locally built `radar` image and mount the working tree in the container. The runtime dependencies are installed in the image.

### Run the Image Directly

The image runs a one-off scan and exits when it completes. The image entrypoint is `bun`; pass the scan script and target as the command:

```sh
docker run --rm \
  -e WEBHOOK_URL=https://your.example/api/radar-events \
  -e SCAN_ID=123 \
  -e IS_OSINT=false \
  chmod351/radar:latest \
  run src/app/use-cases/index.ts example.com
```

ECS/Fargate uses the same image. Configure the task definition with `ENTRYPOINT` inherited from the image and override the container command with `run`, `src/app/use-cases/index.ts`, and the target. Set `WEBHOOK_URL`, `SCAN_ID`, and `IS_OSINT` as container environment overrides. The task needs outbound network access to scan targets and reach the webhook receiver; it does not need an inbound port, Docker CLI, or Docker socket.

### Run from Bun Without Docker

After installing Bun and all required external tools:

```sh
bun install
WEBHOOK_URL=https://your.example/api/radar-events bun run src/app/use-cases/index.ts example.com
```

The script uses the target argument as the root domain. The built-in help is available with `bun run radar.ts man`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBHOOK_URL` | `http://192.168.100.135:8080/api/webhook` | Destination for scan event POSTs. Set this to your receiver. |
| `IS_OSINT` | `false` | Set to `true` to skip Stage 3 service and web fingerprinting. |
| `SCAN_ID` | Unset | Numeric scan identifier attached to emitted results. Used by integrations; not generated by the CLI. |
| `RADAR_DB_PATH` | `:memory:` | SQLite path. The database is ephemeral by default. |
| `NODE_ENV` | Unset | The CLI wrapper selects its local `radar` image and mounts the project only when set to `dev` or `test`. |

`IS_DOCKER` is not read by the current application. ECS tasks use the default in-memory database, so scan data is ephemeral in the task; webhook delivery is the supported way to consume results.

## Webhook Events and Data

Every webhook request is an HTTP `POST` with `Content-Type: application/json` and this envelope:

```json
{
  "timestamp": "2026-10-06T12:00:00.000Z",
  "event": "host:updated",
  "status": "success",
  "payload": {}
}
```

Host events use `host:discovered` with `processing`, followed by `host:updated` with `success` or a partial result status. A final `phase-1` and `scan:finished` event report the `scanId`, number of discovered subdomains, and stages executed. Host payloads may include hostnames, IP addresses, URLs, HTTP status/title/server and response headers, security-header indicators, observed cookies, request attempt metadata, ASN/owner/country, CDN indicator, WHOIS fields, detected technologies, open ports, and service/version/banner data. Values depend on what each probe can observe.

RADAR sends scan results only to the configured webhook. The probes also make outbound requests or queries to the target infrastructure and public resolution/registration services as part of scanning. Specifically, discovery uses Subfinder and Assetfinder; DNS and ASN data use DNS queries (including Team Cymru's `origin.asn.cymru.com`); HTTP probes contact discovered hosts; WHOIS queries the relevant root domain; Nmap sends service-detection probes to the target IP; and WhatWeb requests the target URL. When an HTTP response is `403`, RADAR makes additional GET attempts with alternate headers. Do not use an untrusted webhook: the event payload can contain infrastructure details and raw response/WHOIS data.

Webhook failures are logged. Delivery is attempted during the scan, but a failed receiver can mean results are not delivered; use an available, reachable endpoint and monitor its responses.

## ECS/Fargate Tasks

The backend starts one Fargate task per scan with the AWS ECS SDK. ECS launches the scan container directly; the worker does not run an HTTP command server or start nested Docker containers. The backend passes the target as a command argument and supplies `WEBHOOK_URL`, `SCAN_ID`, and `IS_OSINT` as environment overrides. Scan events continue to be delivered to the backend through the configured HTTP webhook.

## Data Storage

RADAR contains a SQLite schema for scans, targets, infrastructure, ports, and technology stack data. The default database path is in-memory, and worker-launched scans explicitly use an in-memory database, so data is discarded when the process/container exits. Current use cases primarily publish results to the webhook; there is no documented user-facing query command or local report export.

## Development and Checks

```sh
bun install
bun run check       # ESLint and TypeScript type check
bun test            # Tests
```

For local Docker development, build the image first with `docker build -t radar .`, then invoke the wrapper with `NODE_ENV=dev` as shown above. The wrapper's `test` environment follows the same Docker path.

https://radar-dashboard-plum.vercel.app  

<img width="1378" height="835" alt="2026-10-14_18-40-17" src="https://github.com/user-attachments/assets/b0791450-7e53-4169-867e-696e355083b3" />

## Responsible Use

Only scan assets that you own or are explicitly authorized to assess. RADAR performs active HTTP and Nmap probes, including service/version detection and additional header variations after HTTP 403 responses. Confirm the target scope and obtain approval before running it; operators are responsible for complying with applicable laws, contracts, and provider policies.


