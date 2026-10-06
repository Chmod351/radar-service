import type { AnalyzedTarget, HttpIntel, OpenPort, Technology, WhoisIntel } from "../../core/entities/types";


/**
 * Normaliza los payloads parciales o completos enviados por el Docker (Radar)
 * asegurando un fallback seguro de datos y el cumplimiento estricto del tipo AnalyzedTarget.
 */
export function normalizeRadarTarget(payload: any,scanId:number): AnalyzedTarget {
  if (!payload) {
    throw new Error("[MAPPER ERROR] No se puede normalizar un payload inexistente.");
  }

  const host = payload.target || payload.host || "";
  
  const protocol = payload.http_intel?.protocol;
  const isSsl = protocol !== null && protocol !== undefined && protocol !== 0;
  const url = payload.url || (host ? `${isSsl ? "https" : "http"}://${host}` : "");

  const httpIntelNormalized: HttpIntel = {
    protocol: payload.http_intel?.protocol ?? null,
    status: payload.http_intel?.status ?? payload.status_code ?? 0,
    security: {
      hsts: !!payload.http_intel?.security?.hsts,
      csp: !!payload.http_intel?.security?.csp,
      xfo: !!payload.http_intel?.security?.xfo,
      nosniff: !!payload.http_intel?.security?.nosniff,
    },
    server: payload.http_intel?.server || payload.webserver || null,
    poweredBy: payload.http_intel?.poweredBy || null,
    cookies: !!payload.http_intel?.cookies,
    attempts: Array.isArray(payload.http_intel?.attempts) ? payload.http_intel.attempts : [],
    headers: payload.http_intel?.headers,
    error: payload.http_intel?.error || null,
  };

  const whoisNormalized: WhoisIntel = {
    registrar: payload.whois?.registrar || null,
    creationDate: payload.whois?.creationDate || null,
    expirationDate: payload.whois?.expirationDate || null,
    nameServers: Array.isArray(payload.whois?.nameServers) ? payload.whois.nameServers : [],
    status: Array.isArray(payload.whois?.status) ? payload.whois.status : [],
    emails: payload.whois?.emails || null,
    raw: payload.whois?.raw || "",
  };

  return {
    scanId: scanId !== undefined ? Number(scanId) : 0,
    id: payload.id !== undefined ? Number(payload.id) : 0,
    
    host,
    ip: payload.ip || "0.0.0.0",
    url,
    status_code: payload.status_code ?? payload.http_intel?.status ?? 0,
    title: payload.title || null,
    webserver: payload.webserver || payload.http_intel?.server || "Desconocido",
    cdn: payload.cdn ?? null,
    analysis_phase: payload.analysis_phase ?? 2,
    analysis_state: payload.analysis_state ?? "partial",
    analysis_confidence: payload.analysis_confidence ?? "low",
    evidence: payload.evidence,

    // ASNIntel (Datos provistos por Docker en Fase 2, se arrastran o inicializan en null)
    asn: payload.asn || null,
    asn_owner: payload.asn_owner || null,
    country: payload.country || null,

    // Classifiers / Métricas de control interno
    action: payload.total_stages_executed ?? payload.action ?? 2,
    // priority: payload.priority ?? 0,
    app_status: payload.app_status ?? 0,

    // Datos relacionales de Fase 3 y 4
    http_intel: httpIntelNormalized,
    http_stack: Array.isArray(payload.http_stack) ? (payload.http_stack as Technology[]) : [],
    open_ports: Array.isArray(payload.open_ports) ? (payload.open_ports as OpenPort[]) : [],
    vulnerabilities: Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [],

    // Metadata avanzada de Whois
    whois: whoisNormalized,
    whois_raw: payload.whois_raw || payload.whois?.raw || null,
  };
}
