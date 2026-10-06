import { logger } from "../../shared/systemLogger.ts";
import { generateBypassPayloads, getErrorMessage, getRandomAgent } from "../../shared/utils/utils.ts";
import { normalizedIntel } from "../../shared/utils/const.ts";
import type { BypassAttempt, HttpIntel, OpenPort, WhatWebPluginDetails } from "../../core/entities/types.ts";
import { compareSize } from "../../app/phase3Surface/utils.ts";
import { getWebPageFingerprinting } from "./infra/adapters/fingerprinting.adapter.ts";
import { whatwebParser } from "./infra/mappers/whatweb.mapper.ts";
import { fetchFallback, fetchTargetWithTimeout, tryFuff, tryFuffFallback } from "./infra/adapters/headers.adapter.ts";
import { headersFormatter } from "../phase2Dns/infra/mappers/http.mapper.ts";
import { getPortsAvailable } from "./infra/adapters/nmap.adapter.ts";
import { parseNmapOutput } from "./infra/mappers/nmap.mapper.ts";
import { httpIntelBuilder } from "./infra/mappers/headers.mapper.ts";



export type WhatWebRawResponse = Record<string, WhatWebPluginDetails>;
const MAX_NMAP_CONCURRENCY = 1;
const active: Promise<unknown>[] = []; 




async function webTechFingerprintingService(target:string) {
  try {
    const rawContent = await getWebPageFingerprinting(target);
 
    const parsedTech= whatwebParser(rawContent);
  
    return parsedTech;
  
  } catch (e) {
    /* handle error */
    logger.error("WEBTECH:", getErrorMessage(e));
  }
}


async function analyzeHeaders(url: string):Promise<HttpIntel> {
  const userAgent = getRandomAgent() ?? "Radar/1.0";
  try {
    const { response, size, sizeComplete } = await fetchTargetWithTimeout(url, null, userAgent);
    const headers = Object.fromEntries(response.headers.entries());
    const baseline: BypassAttempt = {
      method: "GET",
      header: null,
      status: response.status,
      size,
      size_complete: sizeComplete,
      timestamp: new Date().toISOString(),
    };
    const attempts = [baseline];

    if (response.status === 403) {
      attempts.push(...await performBypassAttempt(url, userAgent, baseline));
    }

    return httpIntelBuilder(headers, url, response.status, attempts, !!response.headers.get("set-cookie"));
  } catch (error: unknown) {
    logger.error("HEADERS", getErrorMessage(error));
    return headersFallback(url, userAgent);
  }
}

async function headersFallback(url: string, userAgent: string): Promise<HttpIntel> {
  try {
    const fallback = await fetchFallback(url, userAgent);
    const { headers } = headersFormatter(fallback.headers);
    const baseline: BypassAttempt = {
      method: "GET",
      header: null,
      status: fallback.status,
      size: fallback.size,
      size_complete: fallback.sizeComplete,
      ...(fallback.error ? { error: fallback.error } : {}),
      timestamp: new Date().toISOString(),
    };
    const attempts = [baseline];

    if (fallback.status === 403) {
      attempts.push(...await performBypassAttempt(url, userAgent, baseline, true));
    }

    return httpIntelBuilder(headers, url, fallback.status, attempts, !!headers["set-cookie"]);

  } catch (error:unknown) {
    logger.error("HEADERS-CURL", getErrorMessage(error));
    return { 
      ...normalizedIntel,
      error: getErrorMessage(error), 
      status: 0, 
    };
  } 
}


async function performBypassAttempt(
  url: string,
  userAgent: string,
  baseline: BypassAttempt,
  useCurlFallback = false,
): Promise<BypassAttempt[]> {
  const attempts: BypassAttempt[] = [];
  const bypassPayloads = generateBypassPayloads(url).filter((payload) => payload.header !== null);

  for (const payload of bypassPayloads) {
    const jitter = Math.floor(Math.random() * 500);
    await Bun.sleep(jitter); 
    try {
      const result = useCurlFallback
        ? await tryFuffFallback(url, payload.header, userAgent)
        : await tryFuff(url, payload.header, userAgent);
      const resultError = "error" in result && typeof result.error === "string" ? result.error : undefined;
      const attempt: BypassAttempt = {
        method: "GET",
        header: payload.header,
        status: result.status,
        size: result.size,
        size_complete: result.sizeComplete,
        ...(resultError ? { error: resultError } : {}),
        timestamp: new Date().toISOString(),
      };
      attempts.push(attempt);
      compareSize(baseline, attempt, url);
    } catch (error) {
      logger.error("BYPASS-ATTEMPT", `Error probando ${payload.name}: ${getErrorMessage(error)}`);
      attempts.push({
        method: "GET",
        header: payload.header,
        status: 0,
        size: 0,
        size_complete: false,
        error: getErrorMessage(error),
        timestamp: new Date().toISOString(),
      });
    }
  }
  return attempts;
}

export async function getWebIntel(url: string) {
  const [intel, stack] = await Promise.all([
    analyzeHeaders(url),
    webTechFingerprintingService(url),
  ]);

  return {
    http_intel: intel ||{ error:"Unreachable" },
    http_stack: stack || [],
  };
} 




// EVITA QUE SE QUEME EL PC
async function runWithNmapLimit<T>(fn: () => Promise<T>): Promise<T> {
  while (active.length >= MAX_NMAP_CONCURRENCY) {
    await Promise.race(active);
  }

  const job = fn();
  active.push(job);

  try {
    return await job;
  } finally {
    const i = active.indexOf(job);
    if (i > -1) active.splice(i, 1);
  }
}


async function scanPorts(target: string): Promise<OpenPort[]> {
  try {
    const stdout = await getPortsAvailable(target);

    if (!stdout) return [];

    const discoveredPorts = parseNmapOutput(stdout);
    if (discoveredPorts.length > 0) {
      logger.info("NMAP", `Detectados ${discoveredPorts.length} puertos en ${target}`);
    }
    return discoveredPorts;
  } catch (e: unknown) {

    logger.error("NMAP", getErrorMessage(e));

    return [];
  }
}

export const scanPortsSafe = (target: string) =>
  runWithNmapLimit(() => scanPorts(target));
