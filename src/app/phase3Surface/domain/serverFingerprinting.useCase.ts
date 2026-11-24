import type { AnalyzedTarget, HttpIntel } from "../../../core/entities/types";
import { isOsintMode } from '../../../infra/enviromentVariables';
import { withRetry } from "../../../shared/retry";
import { logger } from "../../../shared/systemLogger";
import { normalizedIntel } from "../../../shared/utils/const";
import { getErrorMessage } from "../../../shared/utils/utils";
import { normalizeHttpIntel, normalizeTarget } from "../../phase2Dns/infra/mappers/normalizeJson";
import { identifyCDN } from "../../phase2Dns/utils/cdnDetector";
import { getWebIntel } from "../serverFingerPrintingProbe";


export async function fingerprintingPhase(target: AnalyzedTarget, scanId: number | bigint): Promise<AnalyzedTarget> {

  try {
    logger.info("FINGERPRINTING:", `target: ${target.host}`);

    const httpData = await withRetry("http-intel", () => getWebIntel(target.url), { retries: 2 })

    const httpIntelNormalized = normalizeHttpIntel(httpData.http_intel as HttpIntel);

    const webserver = httpIntelNormalized.server || httpData.http_stack?.[0]?.name;
    const headersRaw = JSON.stringify(httpIntelNormalized.headers || {});

    const { cdn } = identifyCDN(target, webserver, headersRaw);

    const result = {
      ...target,
      http_intel: httpIntelNormalized || normalizedIntel,
      http_stack: httpData.http_stack,
      open_ports:[],
      cdn,
      analysis_phase: 2 as const,
      analysis_state: isOsintMode? "complete" as const : "partial" as const,
      analysis_confidence: "medium" as const,
      evidence: {
        dns: true,
        asn: Boolean(target.asn || target.asn_owner),
        http: Boolean(httpIntelNormalized.status || httpIntelNormalized.server),
        whois: Boolean(target.whois),
        nmap: false,
        whatweb: true,
      },
    };
    const normalized = normalizeTarget(result, scanId);
    // const data= await fingerprintingPhaseService.saveFingerprintingInfo(host, normalized,scanId);
    return normalized;
  } catch (error: unknown) {
    logger.error("PHASE 2", getErrorMessage(error));

    return {
      ...target,
      analysis_phase: 2,
      analysis_state: "failed",
      analysis_confidence: "low",
      evidence: {
        ...(target.evidence || { dns: true, asn: false, http: false, whois: false, nmap: false, whatweb: false }),
        nmap: false,
        whatweb: false,
      },
      http_intel: {
        ...normalizedIntel,
        error: getErrorMessage(error) ?? "Fallo el fingerprinting",
      },
      http_stack: target.http_stack,
      open_ports: target.open_ports,
    };
  } finally {
    logger.info("PHASE 2:", `[#] Fingerprinting Finalizado ${target.host}`);
  }
}
