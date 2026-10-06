import { execa } from "execa";
import { getRandomAgent } from "../../../../shared/utils/utils";
const MAX_RESPONSE_SIZE_BYTES = 5 * 1024 * 1024;
const CURL_METADATA_MARKER = "\n__RADAR_META__";

interface MeasuredResponse {
  response: Response;
  size: number;
  sizeComplete: boolean;
}

interface CurlResponse {
  headers: string;
  status: number;
  size: number;
  sizeComplete: boolean;
  error?: string;
}

async function measureBody(response: Response): Promise<{ size: number; sizeComplete: boolean }> {
  if (!response.body) return { size: 0, sizeComplete: true };

  const reader = response.body.getReader();
  let size = 0;
  let sizeComplete = true;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > MAX_RESPONSE_SIZE_BYTES) {
        size = MAX_RESPONSE_SIZE_BYTES;
        sizeComplete = false;
        await reader.cancel().catch(() => undefined);
        break;
      }
      size += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  return { size, sizeComplete };
}

export async function fetchTargetWithTimeout(
  url: string,
  requestHeader: string | null = null,
  agent: string = getRandomAgent() ?? "Radar/1.0",
): Promise<MeasuredResponse> {
  const headers: Record<string, string> = {
    "User-Agent": agent,
    "Accept-Encoding": "identity",
  };

  if (requestHeader) {
    const separator = requestHeader.indexOf(":");
    if (separator <= 0) throw new Error(`Header de prueba inválido: ${requestHeader}`);
    headers[requestHeader.slice(0, separator).trim()] = requestHeader.slice(separator + 1).trim();
  }

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers,
      redirect: "follow",
      signal: controller.signal,
    });
    const { size, sizeComplete } = await measureBody(response);
    return { response, size, sizeComplete };
  } finally {
    clearTimeout(id);
  }
}


async function curlResponse(url: string, agent: string, requestHeader: string | null = null): Promise<CurlResponse> {
  const args = [
    "-sS", "-L", "-k",
    "--max-time", "10",
    "--max-filesize", String(MAX_RESPONSE_SIZE_BYTES),
    "-H", "Accept-Encoding: identity",
    "-A", agent,
    "-D", "-",
    "-o", "/dev/null",
    "-w", `${CURL_METADATA_MARKER}%{http_code},%{size_download}`,
    url,
  ];

  if (requestHeader) args.splice(args.length - 1, 0, "-H", requestHeader);

  const { stdout, stderr, exitCode } = await execa("curl", args, { reject: false });
  const markerIndex = stdout.lastIndexOf(CURL_METADATA_MARKER);
  if (markerIndex < 0) {
    throw new Error(stderr || `Curl no devolvió metadatos (exit ${exitCode ?? "desconocido"})`);
  }

  const [rawStatus, rawSize] = stdout.slice(markerIndex + CURL_METADATA_MARKER.length).trim().split(",");
  const status = Number.parseInt(rawStatus || "0", 10) || 0;
  const size = Number.parseInt(rawSize || "0", 10) || 0;

  return {
    headers: stdout.slice(0, markerIndex),
    status,
    size,
    sizeComplete: exitCode === 0,
    ...(exitCode === 0 ? {} : { error: stderr || `Curl terminó con exit ${exitCode}` }),
  };
}

export async function fetchFallback(url: string, agent: string): Promise<CurlResponse> {
  return curlResponse(url, agent);
}

export async function tryFuff(
  url: string,
  requestHeader: string | null,
  agent: string,
): Promise<{ status: number; size: number; sizeComplete: boolean }> {
  const { response, size, sizeComplete } = await fetchTargetWithTimeout(url, requestHeader, agent);
  return { status: response.status, size, sizeComplete };
}

export async function tryFuffFallback(url: string, requestHeader: string | null, agent: string): Promise<CurlResponse> {
  return curlResponse(url, agent, requestHeader);
}
