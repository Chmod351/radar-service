import { CDN_PROVIDERS, PROTOCOLS } from "../../shared/utils/const";
const getConstantKey = (dictionary: Record<string, any>, value: number): string => {
  return Object.keys(dictionary).find(key => dictionary[key] === value) || "UNKNOWN";
};

export function formatSecurityRow(row: any) {

  // 2. Mapear Puertos con Protocolos de Aplicación y Transporte
  const formattedPorts = row.open_ports_raw 
    ? row.open_ports_raw.split(",").map((pStr: string) => {
      const [portStr, appProtoIdStr, transProtoIdStr, service] = pStr.split(":");
      const portNum = portStr ? parseInt(portStr, 10) : null;
      const appProtoId = appProtoIdStr ? parseInt(appProtoIdStr, 10) : null;
      const transProtoId = transProtoIdStr ? parseInt(transProtoIdStr, 10) : null;

      return {
        port: portNum,
        service: service || "unknown",
        transport: transProtoId !== null ? getConstantKey(PROTOCOLS.TRANSPORT, transProtoId) : "UNKNOWN",
        app_protocol: appProtoId !== null ? getConstantKey(PROTOCOLS.APP, appProtoId) : "UNKNOWN",
      };
    })
    : [];

  // 3. Evaluar vector de riesgo web (Falta de cabeceras de seguridad básicas)
  const securityMissingHeaders: string[] = [];
  if (!row.hsts) securityMissingHeaders.push("HSTS");
  if (!row.csp) securityMissingHeaders.push("CSP");
  if (!row.xfo) securityMissingHeaders.push("X-Frame-Options");
  if (!row.nosniff) securityMissingHeaders.push("X-Content-Type-Options");

  return {
    host: row.host,
    ip: row.ip,
    status_code: row.status,
    webserver: row.webserver || "Desconocido",
    cdn: getConstantKey(CDN_PROVIDERS, row.cdn),
    
    
    
    // Superficie de Ataque Abierta
    attack_surface: {
      http_stack: row.stack ? row.stack.split(",") : [],
      open_ports: formattedPorts,
    },
    
    // Datos OSINT / Reconocimiento Pasivo
    passive_intel: {
      whois_emails: row.whois_emails ? row.whois_emails : "Ninguno detectado",
      whois_registrar: row.whois_registrar || "Desconocido",
    },
    
    // Postura de Seguridad Web
    security_posture: {
      missing_headers: securityMissingHeaders,
      is_vulnerable: securityMissingHeaders.length > 0,
      // infra_type_eval: getConstantKey(SENSORS.INFRA_TYPE, row.infra_type),
    },
  };  
}
