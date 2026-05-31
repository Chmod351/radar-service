import type { AnalyzedTarget } from "../../../core/entities/types";
import { withRetry } from "../../../shared/retry";
import { logger } from "../../../shared/systemLogger";
import { emptyWhois, SENSORS } from "../../../shared/utils/const";
import { getErrorMessage } from "../../../shared/utils/utils";
import { normalizeTarget } from "../infra/mappers/normalizeJson";
import { enrichWebData, getASNInfo, getWhoisIntel, resolveSingleDomain } from "../infraProbes";
import { identifyCDN } from "../utils/cdnDetector";
import { classifyTarget } from "../utils/classifyTarget";
import infraService from "./phase2.repository";

export async function dnsPhaseStream(subdomain: string,scanId:number|bigint): Promise<Partial<AnalyzedTarget> | null> {
  try {
    logger.info("DNS PHASE:",`${subdomain}`);
    const resolved = await resolveSingleDomain(subdomain);
    if (!resolved || resolved.ip === "0.0.0.0") return null; 

    const [asnInfo, webInfo] = await Promise.all([
      withRetry("ASN-INFO", ()=>    getASNInfo(resolved.ip),{ retries:2 }),
      withRetry("WHATWEB", ()=>   enrichWebData(subdomain),{ retries:2 }),
    ]);

    const baseData= {
      ...resolved,
      ...webInfo,
      ...asnInfo,
    };

    const { cdn }= identifyCDN(baseData);

    baseData.cdn=cdn;

    const analyzed = classifyTarget(baseData);
    if (analyzed.action === SENSORS.ACTION.READY) {
      analyzed.whois = await withRetry("whois",()=> getWhoisIntel(subdomain),{ retries:1,delay:2000 })
        .catch(() => emptyWhois);
    }

    infraService.saveDNSphaseInfo(analyzed as AnalyzedTarget,scanId);
    const normalized: AnalyzedTarget=normalizeTarget(analyzed as AnalyzedTarget);
    return normalized;
    
  } catch (error: unknown) {
    logger.error("DNS-PHASE", getErrorMessage(error));
    return null;
  }
}

