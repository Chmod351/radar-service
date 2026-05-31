import { emptyWhois } from "../../shared/utils/const.ts";
import { logger } from "../../shared/systemLogger.ts";
import { getErrorMessage } from "../../shared/utils/utils.ts";
import type { ASNIntel, ResolvedDomain, WebMetadata, WhoisIntel } from "../../core/entities/types.ts";
import { isValididIp } from "./utils/isValidIp.ts";
import { cymruService } from "./infra/adapters/asnInfo.adapter.ts";
import { asnMapper } from "./infra/mappers/asn.mapper.ts";
import { dnsResolver } from "./infra/adapters/dns.adapter.ts";
import { dnsMapper } from "./infra/mappers/dnsx.mapper.ts";
import { getHttpHeaders } from "./infra/adapters/http.adapter.ts";
import { httpParser } from "./infra/mappers/http.mapper.ts";
import { getRootDomain, normalizeWhois } from "./infra/mappers/whois.mapper.ts";
import { getWhois } from "./infra/adapters/whois.adapter.ts";

const whoisCache = new Map<string, WhoisIntel>();
const netCache= new Map<string, ASNIntel>();
const providerCache = new Map<string,ASNIntel>();

const emptyResults:ASNIntel={ 
  asn_owner:null,
  asn:null,
  country:null,
};

export async function getASNInfo(ip: string): Promise<ASNIntel> {
  try {
    if (!isValididIp(ip)) return emptyResults;

    if (netCache.has(ip)) return netCache.get(ip)!;

    const firstEntry= await cymruService(ip);
  
    if (!firstEntry) {
      const internalResult = { ...emptyResults, asn: "INTERNAL", asn_owner: "RFC1918/BOGON" };
      netCache.set(ip, internalResult);
      return internalResult;
    }
    const basicAsn =  asnMapper(firstEntry);
   
    if (!basicAsn.asn) {
      const unknownResult = basicAsn;
      
      netCache.set(ip, unknownResult);
      return unknownResult;
    }

    const enriched= providerCache.get(basicAsn.asn); 
    if (enriched) {
      const finalResult={ ...emptyResults, ...basicAsn,...enriched,query:ip };
      netCache.set(ip, finalResult);
      return finalResult;  
    }
    

    const combined: ASNIntel = {
      ...emptyResults,
      ...basicAsn,
      asn_owner: basicAsn.asn_owner  || "Unknown",
    };
    netCache.set(ip,combined);
   
    return combined;
    
  } catch (e) {
    logger.error("ASN-INFO:", getErrorMessage(e));
    return emptyResults;
  }
}



export async function resolveSingleDomain(domain: string): Promise<ResolvedDomain | null> {
  try {
    const stdout = await dnsResolver(domain);
    return dnsMapper(stdout);
    
  } catch (e:unknown) {
    logger.error("RESOLVER-SINGLE-DOMAIN", getErrorMessage(e));
    return null;
  }
}

export async function enrichWebData(host: string): Promise<WebMetadata> {
  const emptyRes= {
    url: `http://${host}`,
    status_code: 0,
    title: null,
    webserver: null,
    cdn: null,
  };
  try {
 
    const headers= await getHttpHeaders(host);
    const pardedHeaders= httpParser(headers, host);

    return pardedHeaders;
       
  } catch (e) {
    // Fallback: Si falla el escaneo profundo, devolvemos lo básico
    logger.error("ENRICH", `${host} fallo con error: ${e}, mandando fallback`);
    return emptyRes;
  }
}



export async function getWhoisIntel(host: string): Promise<WhoisIntel> {
  const root = getRootDomain(host); 

  if (whoisCache.has(root)) {
    return whoisCache.get(root)!;
  }
  try {
  
    const stdout = await getWhois(root);

    if (!stdout || stdout.includes("No match for")) return emptyWhois;
    const parsed = normalizeWhois(stdout);
    whoisCache.set(root, parsed);
    return parsed;

  } catch (error: unknown) {
    whoisCache.set(root, emptyWhois);
    logger.error("WHO-IS", getErrorMessage(error));
    return emptyWhois;
  }
}
