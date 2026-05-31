import type { WhoisIntel } from "../../../../core/entities/types";

type WhoisRawData = Record<string, string | string[]>;

export function parseWhoisAgnostic(rawText: string): WhoisRawData {
  const lines = rawText.split("\n");
  const json: WhoisRawData = {};

  for (const line of lines) {
    // Limpieza de comentarios y líneas sin ":"
    if (line.startsWith("%") || line.startsWith("#") || !line.includes(":")) continue;

    const [rawKey, ...valueParts] = line.split(":");
    if (!rawKey) continue;

    const key = rawKey.trim().toLowerCase().replace(/\s+/g, "_");
    const value = valueParts.join(":").trim();
    if (!value) continue;

    const existing = json[key];
    if (existing) {
      // Si ya existe, convertimos a array o agregamos al existente
      json[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
    } else {
      json[key] = value;
    }
  }
  return json;
}


export function getRootDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;

  const last = parts[parts.length - 1];
  const prev = parts[parts.length - 2];
  if (last && prev) {
    if (last.length <= 2 && prev.length <= 3) {
      return parts.slice(-3).join(".");
    }
  
    return parts.slice(-2).join(".");
  }
  return parts.slice(-2).join(".");
}


export function normalizeWhois(rawText: string): WhoisIntel {
  const data = parseWhoisAgnostic(rawText);

  const get = (k: string): string | undefined => {
    const val = data[k];
    return Array.isArray(val) ? val[0] : val;
  };

  const getAll = (k: string): string[] => {
    const val = data[k];
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
  };

  return {
    registrar: get("registrar") || get("sponsoring_registrar") || null,
    creationDate: get("creation_date") || get("registered_on") || null,
    expirationDate: get("registry_expiry_date") || get("expires_on") || null,
    nameServers: [...new Set([...getAll("nserver"), ...getAll("name_server")])],
    status: [...new Set([...getAll("domain_status"), ...getAll("status")])],
    emails: get("registrant_email") || get("abuse_contact_email") || null,
    raw: rawText.slice(0, 500),
  };
}

