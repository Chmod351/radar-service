import type { ResolvedDomain } from "../../../../core/entities/types";

export function dnsMapper(stdout:string):null|ResolvedDomain {

  if (!stdout.trim()) return null;
 
  const data = JSON.parse(stdout);
  return {
    host: data.host,
    ip: data.a?.[0] || "0.0.0.0",
  };

}
