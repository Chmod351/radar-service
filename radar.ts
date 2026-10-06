#!/usr/bin/env bun
import { createHmac, timingSafeEqual } from "node:crypto";
import { execSync, spawn } from "child_process";
import { showManual } from "./src/core/presentation/manual";
import { logger } from "./src/shared/systemLogger";
import { getErrorMessage } from "./src/shared/utils/utils";
import { isDev, isTest, WEBHOOK_API } from "./src/infra/enviromentVariables";

const args = process.argv.slice(2);
const flag = args[0];
const param = args[1];


async function main() {
  if (process.env.RADAR_WORKER_SERVER === "true") {
    startWorkerServer();
    return;
  }

  if (!flag || flag === "-h" || flag === "--help" || flag === "man") {
    showManual();
    process.exit(0);
  }

  switch (flag) {
  case "-S": // El flag de Escaneo que abstrae Docker
    if (!param) {
      console.error("❌ Error: Se requiere un dominio raíz. Ejemplo: radar -S nmap.org");
      process.exit(1);
    }

    runScanInDocker(param);
    break;

  default:
    console.log("❌ Flag desconocido. Escribí \"radar man\".");
    process.exit(1);
  }
}

type ScanCommand = {
  target?: unknown;
  tenantId?: unknown;
  organizationId?: unknown;
  scanId?: unknown;
  isOsintMode?: unknown;
  webhookUrl?: unknown;
};

function startWorkerServer() {
  const port = Number(process.env.PORT || process.env.RADAR_WORKER_PORT || 8090);
  const secret = process.env.RADAR_WORKER_SECRET;

  if (!secret) {
    throw new Error("RADAR_WORKER_SECRET is required in worker server mode");
  }

  Bun.serve({
    hostname: "0.0.0.0",
    port,
    async fetch(request) {
      const url = new URL(request.url);

      if (request.method !== "POST" || url.pathname !== "/api/scan") {
        return Response.json({ error: "Not Found" }, { status: 404 });
      }

      const timestamp = request.headers.get("X-Radar-Timestamp");
      const signature = request.headers.get("X-Radar-Signature");
      if (!timestamp || !signature) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }

      const bodyText = await request.text();
      if (!isValidSignature(timestamp, signature, secret, bodyText)) {
        return Response.json({ error: "Invalid signature" }, { status: 401 });
      }

      let command: ScanCommand;
      try {
        command = JSON.parse(bodyText) as ScanCommand;
      } catch {
        return Response.json({ error: "Invalid JSON" }, { status: 400 });
      }

      const target = typeof command.target === "string" ? command.target.trim() : "";
      const webhookUrl = typeof command.webhookUrl === "string" ? command.webhookUrl : "";
      const scanId = Number(command.scanId);
      const tenantId = Number(command.tenantId);
      const organizationId = Number(command.organizationId);

      if (
        !target ||
        !webhookUrl ||
        !Number.isInteger(scanId) ||
        !Number.isInteger(tenantId) ||
        !Number.isInteger(organizationId)
      ) {
        return Response.json({ error: "Invalid scan command" }, { status: 400 });
      }

      try {
        new URL(webhookUrl);
      } catch {
        return Response.json({ error: "Invalid webhook URL" }, { status: 400 });
      }

      launchDockerScan({
        target,
        webhookUrl,
        scanId,
        isOsintMode: command.isOsintMode === true,
      });

      return Response.json({ status: "started", scanId }, { status: 202 });
    },
  });

  logger.info("WORKER", `Listening for scan commands on http://0.0.0.0:${port}`);
}

function isValidSignature(
  timestamp: string,
  signature: string,
  secret: string,
  body = "",
): boolean {
  const timestampValue = Number(timestamp);
  if (!Number.isInteger(timestampValue) || Math.abs(Date.now() / 1000 - timestampValue) > 300) {
    return false;
  }

  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
  const receivedBuffer = Buffer.from(signature, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");

  return (
    receivedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(receivedBuffer, expectedBuffer)
  );
}

function launchDockerScan({
  target,
  webhookUrl,
  scanId,
  isOsintMode,
}: {
  target: string;
  webhookUrl: string;
  scanId: number;
  isOsintMode: boolean;
}): void {
  const imageName = process.env.RADAR_DOCKER_IMAGE || "chmod351/radar:latest";
  const network = process.env.RADAR_DOCKER_NETWORK || "bridge";
  const dockerArgs = [
    "run",
    "--rm",
    "--network",
    network,
    "-e",
    `WEBHOOK_URL=${webhookUrl}`,
    "-e",
    "NODE_ENV=production",
    "-e",
    `SCAN_ID=${scanId}`,
    "-e",
    "IS_DOCKER=true",
    "-e",
    "RADAR_DB_PATH=:memory:",
    "-e",
    `IS_OSINT=${isOsintMode}`,
    "--entrypoint",
    "bun",
    imageName,
    "run",
    "src/app/use-cases/index.ts",
    target.toLowerCase(),
  ];

  const child = spawn("docker", dockerArgs, { stdio: "inherit" });
  child.on("error", (error) => {
    logger.error("DOCKER_WORKER", error.message);
  });
  child.on("exit", (code) => {
    if (code !== 0) logger.error("DOCKER_WORKER", `Scan exited with code ${code}`);
  });
}

function runScanInDocker(targetDomain: string) {
  const currentDir = process.cwd();
  const webhookUrl = process.env.WEBHOOK_URL || WEBHOOK_API;

  const args = ["run", "--rm"];

  if (isDev || isTest) {
    args.push("-it");
    args.push("-v", `${currentDir}:/app`);
    args.push("--entrypoint", "bun");
  }

  args.push("-e", `WEBHOOK_URL=${webhookUrl}`);

  const imageName = isDev || isTest ? "radar" : "Chmod351/radar:latest";
  args.push(imageName);

  // 3. Argumentos de ejecución del contenedor
  if (isDev || isTest) {
    args.push("run", "src/app/use-cases/index.ts", targetDomain);
  } else {
    args.push(targetDomain);
  }

  try {
    logger.info("DOCKER:", `Ejecutando escaneo para ${targetDomain}...`);

    execSync(`docker ${args.join(" ")}`, { stdio: "inherit" });

  } catch (error) {
    if (isDev || isTest) {
      logger.error("DOCKER_CRASH:", getErrorMessage(error));
    }
    console.error("\n❌ Error crítico en la ejecución del contenedor de Docker.");
    process.exit(1);
  }
}


main();
