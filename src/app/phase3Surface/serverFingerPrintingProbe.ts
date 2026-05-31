import { logger } from "../../shared/systemLogger.ts";
import { generateBypassPayloads, getErrorMessage } from "../../shared/utils/utils.ts";
import { normalizedIntel,PROTOCOLS } from "../../shared/utils/const.ts";
import type { BypassAttempt, HttpIntel, OpenPort, WhatWebPluginDetails } from "../../core/entities/types.ts";
import { compareSize } from "../../app/phase3Surface/utils.ts";
import { getWebPageFingerprinting } from "./infra/adapters/fingerprinting.adapter.ts";
import { whatwebParser } from "./infra/mappers/whatweb.mapper.ts";
import { fetchFallback, fetchTargetWithTimeout, tryFuff } from "./infra/adapters/headers.adapter.ts";
import { bypassAttemptParser, headersFormatter } from "../phase2Dns/infra/mappers/http.mapper.ts";
import { getPortsAvailable } from "./infra/adapters/nmap.adapter.ts";
import { parseNmapOutput } from "./infra/mappers/nmap.mapper.ts";
import { httpIntelBuilder } from "./infra/mappers/headers.mapper.ts";
import { withRetry } from "../../shared/retry.ts";



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
  try {

    const response = await fetchTargetWithTimeout(url);
    
    const headers = Object.fromEntries(response.headers.entries());
    const contentLength = parseInt(response.headers.get("content-length") || "0");

    const statusCode=response.status;
    const attemps= [{ method:"GET",header:null,status:response.status,size:contentLength,timestamp:new Date().toISOString() }];

    const cookies =!!response.headers.get("set-cookie");
    const parsedResponse= httpIntelBuilder(headers, url,statusCode,attemps,cookies);

    return parsedResponse;
  } catch (error: unknown) {
    
    logger.error("HEADERS", getErrorMessage(error));

    return   await headersFallback(url);
      
  }
}

async function bypassController (baseResults:{protocol:number,status:number},url:string) {
  if (baseResults.status===403) {
    logger.warn("HEADERS CURL:",`403 Detectado para ${url}, Iniciando fase de Sniffing`);
    const  performedAttempts = await withRetry("BYPASS-ATTEMPT:", ()=>  performBypassAttempt(url),{ retries:2,delay:3000 });
    return performedAttempts;
  } else {
    const   performedAttempts=[{ method:"HEAD",header:null,status:baseResults.status,size:0,timestamp:new Date().toISOString() }];
    return performedAttempts;
  }
}

async function headersFallback(url:string) :Promise<HttpIntel>{
  try {
    const stdout = await fetchFallback(url);

    const { headers,statusCode }= headersFormatter(stdout); 

    const baseResults={
      protocol:url.startsWith("https")? PROTOCOLS.APP.HTTPS:PROTOCOLS.APP.HTTP,
      status:isNaN(statusCode)?0:statusCode,
    };

    let performedAttempts;
  
    performedAttempts = await bypassController(baseResults, url);
       
    const successfulAttempt = performedAttempts.find(a => a.status === 200); 
    const finalStatus = successfulAttempt ? successfulAttempt.status : baseResults.status;

    return httpIntelBuilder(headers,url,finalStatus,performedAttempts,!!headers["set-cookie"]);

  } catch (error:unknown) {
    logger.error("HEADERS-CURL", getErrorMessage(error));
    return { 
      ...normalizedIntel,
      error: getErrorMessage(error), 
      status: 0, 
    };
  } 
}


async function performBypassAttempt(url: string): Promise<BypassAttempt[]> {
  const attempts: BypassAttempt[] = [];
  const bypassPayloads=generateBypassPayloads(url);

  for (const payload of bypassPayloads) {
    const jitter = Math.floor(Math.random() * 500);
    await Bun.sleep(jitter); 
    try {
      // Usamos -w para obtener el HTTP CODE y el SIZE_DOWNLOAD al final del output
      const stdout = await tryFuff(url, payload.header);

      if (stdout) {

        const { status,s,size }= bypassAttemptParser(stdout);
        
        attempts.push({
          method: "GET",
          header: payload.header,
          status,
          size:s,
          timestamp: new Date().toISOString(),
        });
        compareSize(attempts, status, url, size, payload.header, s);
      }
    } catch (error) {
      logger.error("BYPASS-ATTEMPT", `Error probando ${payload.name}: ${getErrorMessage(error)}`);
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
