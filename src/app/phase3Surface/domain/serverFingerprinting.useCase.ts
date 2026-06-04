import type { AnalyzedTarget, HttpIntel } from "../../../core/entities/types";
import { withRetry } from "../../../shared/retry";
import { logger } from "../../../shared/systemLogger";
import { normalizedIntel } from "../../../shared/utils/const";
import { getErrorMessage } from "../../../shared/utils/utils";
import { normalizeHttpIntel, normalizeTarget } from "../../phase2Dns/infra/mappers/normalizeJson";
import { identifyCDN } from "../../phase2Dns/utils/cdnDetector";
import { getWebIntel, scanPortsSafe } from "../serverFingerPrintingProbe";
import fingerprintingPhaseService from "./phase3.repository";


export async function fingerprintingPhase(target: AnalyzedTarget,scanId:number|bigint): Promise<AnalyzedTarget> {
  const host = target.host;

  try {
    logger.info("FINGERPRINTING:",`target: ${target.host}`);

    const [httpData, openPorts] = await Promise.all([
      withRetry("http-intel", ()=>  getWebIntel(target.url),{ retries:2 }),
      withRetry("nmap-scan", ()=>  scanPortsSafe(host),{ retries:2,delay:2000 }),
    ]);
    
    const httpIntelNormalized=normalizeHttpIntel(httpData.http_intel as HttpIntel);
    
    const   webserver= httpIntelNormalized.server || httpData.http_stack?.[0]?.name;
    const   headersRaw= JSON.stringify(httpData.http_stack || {});

    const { cdn } = identifyCDN(target,webserver,headersRaw); 

    const result={ 
      ...target,
      http_intel: httpIntelNormalized || normalizedIntel,
      http_stack: httpData.http_stack,
      open_ports: openPorts || [],
      cdn,
    };
    const normalized = normalizeTarget(result,scanId);
    const data= await fingerprintingPhaseService.saveFingerprintingInfo(host, normalized,scanId);
    console.debug("PHASE 3 DB SAVING:",data);
    return normalized;
  } catch (error: unknown) {
    logger.error("PHASE-03", getErrorMessage(error));

    return { 
      ...target,
      http_intel:{ 
        ...normalizedIntel,
        error:getErrorMessage(error)?? "Fallo el fingerprinting", 
      },
      http_stack:target.http_stack,
      open_ports:target.open_ports, 
    };
  } finally {
    logger.info("PHASE 3:", `[#] Fingerprinting Finalizado ${target.host}`);
  }
}
